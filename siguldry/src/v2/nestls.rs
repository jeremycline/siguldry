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
//! implement the Siguldry protocol, it only provides a tunneled socket over which the
//! protocol can be implemented. Refer to [`siguldry::v2::protocol`] for the higher-level
//! protocol.

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

use openssl::{nid::Nid, ssl::Ssl};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpStream, ToSocketAddrs},
    task::JoinHandle,
};
use tokio_openssl::SslStream;
use tracing::{instrument, Instrument};
use uuid::Uuid;
use zerocopy::IntoBytes;

use crate::v2::{
    error::ConnectionError as Error,
    protocol::{ProtocolAck, ProtocolHeader, Role},
    tls::ServerConfig,
};

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
    role: Role,
}

/// A nested TLS session.
///
/// Use [`AsyncRead`] and [`AsyncWrite`] to read and write to the inner TLS session.
pub struct Nestls {
    /// The TLS connection to the Sigul server.
    inner_stream: SslStream<DuplexStream>,
    /// The task holding the TLS connection to the bridge.
    ferry_task: JoinHandle<Result<SslStream<TcpStream>, Error>>,
    /// A shared ID between the client and the server identifying this connection.
    session_id: Uuid,
}

impl Nestls {
    /// Get a [`NestlsBuilder`] to configure the connection details.
    ///
    /// Once the connection has been configured, you can create a [`Nestls`] instance by calling
    /// [`NestlsBuilder::connect`] or [`NestlsBuilder::accept`].
    pub fn builder(bridge_ssl: Ssl, role: Role) -> NestlsBuilder {
        NestlsBuilder::new(bridge_ssl, role)
    }

    /// Get the connection's session ID.
    ///
    /// This ID is shared between the client and the server and is primarily useful for logging.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Get the remote connection's commonName from its certificate.
    pub fn peer_common_name(&self) -> Option<String> {
        self.inner_stream
            .ssl()
            .peer_certificate()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
            })
            .map(|common_name| common_name.to_string())
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
    pub fn new(bridge_ssl: Ssl, role: Role) -> Self {
        Self { bridge_ssl, role }
    }

    #[instrument(err, skip_all)]
    async fn connect_to_bridge<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        role: Role,
    ) -> Result<(SslStream<TcpStream>, Uuid), Error> {
        let outer_stream = TcpStream::connect(&bridge_addr).await?;
        tracing::debug!(?bridge_addr, "TCP connection to the bridge established");
        let mut outer_stream = tokio_openssl::SslStream::new(bridge_ssl, outer_stream)?;
        Pin::new(&mut outer_stream).connect().await?;
        let username = outer_stream
            .ssl()
            .certificate()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
            })
            .map(|common_name| common_name.to_string());
        tracing::debug!(?username, "TLS session with the bridge established");

        let protocol_header: ProtocolHeader = role.into();
        let protocol_header = protocol_header.as_bytes();
        outer_stream.write_all(&protocol_header).await?;
        tracing::debug!(
            bytes_sent = protocol_header.len(),
            "Protocol header sent to the bridge"
        );
        let session_id = ProtocolAck::check(&mut outer_stream).await?;

        tracing::info!(
            ?bridge_addr,
            ?session_id,
            "Connection to the bridge established."
        );
        Ok((outer_stream, session_id))
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
        let (outer_stream, session_id) =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.role).await?;

        let (inner_stream, inner_stream_ferry) = tokio::io::duplex(1024 * 64);
        let ferry_task =
            tokio::spawn(Self::ferry(outer_stream, inner_stream_ferry).in_current_span());

        let mut inner_stream = tokio_openssl::SslStream::new(server_ssl, inner_stream)?;
        Pin::new(&mut inner_stream).connect().await?;
        tracing::debug!(?session_id, "Inner TLS session with the server established");

        Ok(Nestls {
            inner_stream,
            ferry_task,
            session_id,
        })
    }

    /// Accept a new incoming nested TLS connection.
    #[instrument(err, skip(self, server_tls_config))]
    pub async fn accept<S: ToSocketAddrs + std::fmt::Debug>(
        self,
        bridge_addr: S,
        server_tls_config: ServerConfig,
    ) -> Result<Nestls, Error> {
        let (outer_stream, session_id) =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.role).await?;

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
            session_id,
        })
    }
}
