// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A nested TLS connection.
//!
//! The Siguldry server is designed to accept no incoming network connections. Instead, it
//! communicates with Siguldry clients via a bridge, which proxies the communication back and forth
//! between the client and the server.
//!
//! In order to ensure the bridge has no visibility into the secrets being shared from the client,
//! such as passphrases to access signing keys, the client and server use TLS within the TLS
//! connection to the bridge.
//!
//! A [`Nestls`] connection is capable of behaving as a client or a server. It does not
//! implement the Siguldry protocol, and merely provides a socket over which the protocol can be
//! implemented.

//! Connect to a Sigul bridge and server.
//!
//! [`Connection`] is capable of connecting to a Sigul bridge and the Sigul server
//! behind that bridge.
//!
//! The high-level client connection flow is as follows:
//!
//! 1. A TLS connection to the Sigul bridge is made. The client authenticates via
//!    an x509 certificate.
//!
//! 2. A protocol header is sent which is a magic number, a protocol version, and
//!    the role of this connection (server or client). This protocol version dictates
//!    what the wire format is for framing and commands.
//!
//! 3. The client starts a nested TLS session within the TLS connection to the Sigul bridge,
//!    targeting the Sigul server, and transmits a set of secrets to the server. All commands must
//!    include the SHA512 digest of the command sent to the bridge, and each side must generate a
//!    set of HMAC keys to validate any further requests and responses through the bridge. Additional
//!    command-specific secrets must also be shared at this point, like key passphrases.
//!
//! 4. The inner TLS session is closed and communication resumes with the bridge as a proxy.
//!
//! 5. The client sends a command to the bridge. The bridge validates it and forwards
//!    it to the server connection.
//!
//! 6. Depending on the command sent, the client may send multiple requests and receive multiple
//!    responses. Each request and response is validated using secrets exchanged in step 4.
//!
//! 7. Once the client is done, it sends a completion message to the bridge, which informs the
//!    server and both connections are closed.
//!
//! ## Protocol Details
//!
//! ### Protocol Header
//!
//! Every connection must begin with the protocol header, which announces the protocol version to
//! follow. The server may reject the request if the version is unknown or unsupported. A server may
//! support multiple versions, but must always use the version requested by the client if it is
//! supported.
//!
//! |--------------------------|
//! |      Protocol Header     |
//! |--------------------------|
//! | u64 | Magic number       |
//! | u32 | Protocol version   |
//! | u8  | Role               |
//! |--------------------------|
//!
//! If the server does not support the requested protocol, the connection is closed.
//!
//! ### Secret exchange
//!
//! After the protocol header, the client starts a second TLS session within the first one. In
//! this session, the client must configure the TLS session to accept the Sigul server's hostname
//! and must present its client TLS certificate.
//!
//! ### Frames
//!
//! Each message following the protocol header must be encapsulated in a frame, which includes
//! a header and a footer.
//!
//! #### Header
//!
//! A frame header consists of a recipient, followed by a content type, followed by the frame
//! size in bytes.
//!
//! |--------------------------|
//! |      Frame Header        |
//! |--------------------------|
//! | u32 | Content-Type       |
//! | u64 | Frame size (bytes) |
//! |--------------------------|
//!
//! The [`Recipient`] is represented as a u8 and uses the values `0` for client, `1` for server, and
//! `2` for the bridge.  The content type is represented as a u32, refer to [`ContentType`] for
//! examples.  The frame size is an unsigned 64 bit integer and does *NOT* include the frame footer.
//! This should be sent in network byte order.
//!
//! #### Footer
//!
//! A frame footer is made up of the the frame's HMAC-SHA512 signature. The frame header and body are
//! both included in the signature. The key used for signing is exchanged with the server in the
//! nested TLS session during the connection handshake.
//!
//! |---------------------------|
//! |       Frame Footer        |
//! |---------------------------|
//! | [u8; 64] | HMAC Signature |
//! |---------------------------|

use std::pin::Pin;

use bytes::BytesMut;
use openssl::ssl::Ssl;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpStream, ToSocketAddrs},
    task::JoinHandle,
};
use tokio_openssl::SslStream;
use tracing::{instrument, Instrument};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::{error::ConnectionError as Error, v2::tls::ServerConfig};

/// Magic number used in the protocol header.
pub const MAGIC: u64 = u64::from_le_bytes([83, 73, 71, 85, 76, 68, 82, 89]);
/// The Sigul wire protocol version this implementation supports
pub const PROTOCOL_VERSION: u32 = 2;

enum ContentType {
    InnerSsl,
    Json,
    Binary,
}

enum Recipient {
    Client,
    Server,
    Bridge,
}

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Client,
    Server,
}

#[derive(IntoBytes, Immutable, KnownLayout, Debug, Clone)]
pub struct ProtocolHeader {
    /// Each connection starts with a [`MAGIC`] number. While the version and role
    /// also have a fairly restricted set of valid values, this makes it even more likely a random
    /// incoming connection doesn't send a valid header so the bridge can hang up sooner. This isn't
    /// a security thing, just a "make it very likely you can log the right error" thing.
    magic: [u8; 8],
    /// The protocol version being requested by the connection; the current version is
    /// [`PROTOCOL_VERSION`].
    version: [u8; 4],
    /// The [`Role`] of this connection; the bridge should listen on entirely different ports and so
    /// it should know whether each connection is a client or a server. This exists primarily to
    /// help catch mis-configurations where the client or server connects to the other's port on the
    /// bridge.
    role: u8,
}

impl From<Role> for ProtocolHeader {
    fn from(value: Role) -> Self {
        Self {
            magic: MAGIC.to_be_bytes(),
            version: PROTOCOL_VERSION.to_be_bytes(),
            role: match value {
                Role::Client => 0_u8,
                Role::Server => 1_u8,
            },
        }
    }
}

/// Each client request or server response starts with a frame that declares the payload's content
/// type and size (in bytes).
///
/// TODO: if something like JSON doesn't work for all commands, we could do something where a
/// request/response is a list of frames so they can have mixed content types. But I think JSON will
/// be fine for everything, so let's keep it simple for now.
struct Frame {
    content_type: ContentType,
    size: u64,
}

// TODO Things the connection should have config for:
//
// Optional timeout for connection to bridge
// Optional timeout for connection to server
// Optional read/write timeout to server?
// Optional buffer size for the ferry pipe? Probably not
// The bridge address
// The bridge SSL config (not optional)
// The server SSL config (differs client vs server, but does this layer handle that?)
//
// Offer hook to send Stream to outer connection before proceeding with the inner connection (use for sending magic protocol header)
// Everything else should be nothing to do with the Sigul protocol.
//
// After you build it, you should get yourself a normal thing that implements AsyncRead/AsyncWrite by using the inner impl, right?

/// Build the configuration for a nested TLS session.
pub struct NestlsBuilder {
    bridge_ssl: Ssl,
    bridge_payload: Option<bytes::Bytes>,
}

pub struct Nestls {
    /// The TLS connection to the Sigul server.
    inner_stream: SslStream<DuplexStream>,
    /// The task holding the TLS connection to the bridge.
    ferry_task: JoinHandle<Result<SslStream<TcpStream>, Error>>,
}

impl Nestls {
    pub fn builder(bridge_ssl: Ssl) -> NestlsBuilder {
        NestlsBuilder::new(bridge_ssl)
    }

    #[instrument(err, skip_all)]
    async fn into_outer(self) -> Result<SslStream<TcpStream>, Error> {
        // It's important to drop the inner stream before attempting to join with the framing task,
        // as this closes DuplexStream. Failing to do so causes the task to hang indefinitely.
        drop(self.inner_stream);
        self.ferry_task.await.expect("The ferry task panicked")
    }
}

impl AsyncRead for Nestls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.as_mut().inner_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Nestls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.as_mut().inner_stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().inner_stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().inner_stream).poll_shutdown(cx)
    }
}

impl NestlsBuilder {
    /// Build a configuration for a [`Nestls`] connection.
    pub fn new(bridge_ssl: Ssl) -> Self {
        Self {
            bridge_ssl,
            bridge_payload: None,
        }
    }

    /// Send these bytes to the bridge after establishing the TLS connection with it.
    pub fn with_bridge_payload(mut self, payload: bytes::Bytes) -> Self {
        self.bridge_payload = Some(payload);
        self
    }

    #[instrument(err, skip_all)]
    async fn connect_to_bridge<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        payload: Option<bytes::Bytes>,
    ) -> Result<SslStream<TcpStream>, Error> {
        let outer_stream = TcpStream::connect(&bridge_addr).await?;
        tracing::debug!(?bridge_addr, "TCP connection to the bridge established");
        let mut outer_stream = tokio_openssl::SslStream::new(bridge_ssl, outer_stream)?;
        Pin::new(&mut outer_stream).connect().await?;
        tracing::debug!("TLS session with the bridge established");

        if let Some(payload) = payload {
            outer_stream.write_all(&payload).await?;
            tracing::debug!(bytes_sent = payload.len(), "Payload sent to the bridge")
        }

        tracing::info!(?bridge_addr, "Connection to the bridge established.");
        Ok(outer_stream)
    }

    async fn ferry(
        mut outer_stream: SslStream<TcpStream>,
        mut inner_stream: DuplexStream,
    ) -> Result<SslStream<TcpStream>, Error> {
        let size = 1024 * 64;
        let (client_sent_bytes, server_sent_bytes) = tokio::io::copy_bidirectional_with_sizes(
            &mut outer_stream,
            &mut inner_stream,
            size,
            size,
        )
        .await?;
        tracing::info!(
            client_sent_bytes,
            server_sent_bytes,
            "inner TLS session completed"
        );
        Ok(outer_stream)
    }

    /// Connect to a nested TLS server.
    #[instrument(err, skip(self, server_ssl))]
    pub async fn connect<S: ToSocketAddrs + std::fmt::Debug>(
        self,
        bridge_addr: S,
        server_ssl: Ssl,
    ) -> Result<Nestls, Error> {
        let outer_stream =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.bridge_payload).await?;

        let (inner_stream, inner_stream_ferry) = tokio::io::duplex(1024 * 64);
        let ferry_task =
            tokio::spawn(Self::ferry(outer_stream, inner_stream_ferry).in_current_span());

        let mut inner_stream = tokio_openssl::SslStream::new(server_ssl, inner_stream)?;
        Pin::new(&mut inner_stream).connect().await?;
        tracing::debug!("Inner TLS session with the server established");

        Ok(Nestls {
            inner_stream,
            ferry_task,
        })
    }

    /// Accept a new incoming nested TLS connection.
    #[instrument(err, skip(self, server_tls_config))]
    pub async fn accept<S: ToSocketAddrs + std::fmt::Debug>(
        self,
        bridge_addr: S,
        server_tls_config: ServerConfig,
    ) -> Result<Nestls, Error> {
        let outer_stream =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.bridge_payload).await?;

        let (inner_stream, inner_stream_ferry) = tokio::io::duplex(1024 * 64);
        let ferry_task =
            tokio::spawn(Self::ferry(outer_stream, inner_stream_ferry).in_current_span());

        let ssl = server_tls_config.ssl()?;
        let mut inner_stream = tokio_openssl::SslStream::new(ssl, inner_stream)?;
        Pin::new(&mut inner_stream).accept().await?;
        tracing::debug!("Accepted new inner TLS connection from a client");

        Ok(Nestls {
            inner_stream,
            ferry_task,
        })
    }
}
