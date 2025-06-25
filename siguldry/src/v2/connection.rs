// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

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
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpStream, ToSocketAddrs},
    task::JoinHandle,
};
use tokio_openssl::SslStream;
use tracing::{instrument, Instrument};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::error::ConnectionError as Error;

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
enum Role {
    Client,
    Server,
}

#[derive(IntoBytes, Immutable, KnownLayout, Debug, Clone)]
pub(crate) struct ProtocolHeader {
    magic: [u8; 8],
    version: [u8; 4],
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

struct Frame {
    content_type: ContentType,
    size: u64,
}

mod state {
    /// Used for connections to the bridge that have not communicated with the server.
    #[derive(Debug)]
    pub struct New;

    pub struct Server;

    pub struct Client;

    /// Used for the connection to the bridge  
    #[derive(Debug)]
    pub(crate) struct Inner;

    /// Used for connections that have sent their request to the server.
    #[derive(Debug)]
    pub(crate) struct InnerFinished;
}

/// A connection that nests a TLS session within a TLS session.
///
/// This behaves like a normal TLS connection, except that it is proxied through a third party
/// "bridge" which requires TLS with mutual TLS certificates.
pub struct Nestls<State = state::New> {
    /// The TLS connection to the Sigul server.
    inner_stream: SslStream<DuplexStream>,
    /// The task holding the TLS connection to the bridge.
    ferry_task: JoinHandle<Result<SslStream<TcpStream>, Error>>,
    /// Tracks if this connection has communicated with the Sigul server yet.
    state: std::marker::PhantomData<State>,
}

impl Nestls<state::New> {
    /// Open a new connection to the Sigul bridge.
    #[instrument(err, skip_all)]
    pub async fn connect<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        server_ssl: Ssl,
    ) -> Result<Nestls<state::Client>, Error> {
        let outer_stream = Self::connect_to_bridge(bridge_addr, bridge_ssl, Role::Client).await?;

        // Now establish the inner TLS session as a client
        let (client_write_half, client_read_half) = tokio::io::duplex(1024 * 64);
        let ferry_task = tokio::spawn(
            async move {
                let mut outer_stream = outer_stream;
                let mut client_read_half = client_read_half;
                let size = 1024 * 64;
                let (client_sent_bytes, server_sent_bytes) =
                    tokio::io::copy_bidirectional_with_sizes(
                        &mut outer_stream,
                        &mut client_read_half,
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
            .in_current_span(),
        );

        let mut inner_stream = tokio_openssl::SslStream::new(server_ssl, client_write_half)?;
        Pin::new(&mut inner_stream).connect().await?;
        tracing::debug!("TLS session with the Sigul server established");

        Ok(Nestls {
            inner_stream,
            ferry_task,
            state: std::marker::PhantomData,
        })
    }

    #[instrument(err, skip_all)]
    pub async fn accept<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        server_ssl: &SslAcceptor,
    ) -> Result<Nestls<state::Server>, Error> {
        let outer_stream = Self::connect_to_bridge(bridge_addr, bridge_ssl, Role::Server).await?;

        let (client_write_half, client_read_half) = tokio::io::duplex(1024 * 1024);
        let ferry_task = tokio::spawn(
            async move {
                let mut outer_stream = outer_stream;
                let mut client_read_half = client_read_half;
                let size = 1024 * 64;
                let (client_sent_bytes, server_sent_bytes) =
                    tokio::io::copy_bidirectional_with_sizes(
                        &mut outer_stream,
                        &mut client_read_half,
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
            .in_current_span(),
        );

        let ssl = Ssl::new(server_ssl.context())?;
        let mut inner_stream = tokio_openssl::SslStream::new(ssl, client_write_half)?;
        Pin::new(&mut inner_stream).accept().await?;
        tracing::debug!("Accepted new TLS connection from a client");

        Ok(Nestls {
            inner_stream,
            ferry_task,
            state: std::marker::PhantomData,
        })
    }

    async fn connect_to_bridge<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        role: Role,
    ) -> Result<SslStream<TcpStream>, Error> {
        let outer_stream = TcpStream::connect(&bridge_addr).await?;
        tracing::info!(
            ?bridge_addr,
            "TCP connection to the Sigul bridge established"
        );
        let mut outer_stream = tokio_openssl::SslStream::new(bridge_ssl, outer_stream)?;
        Pin::new(&mut outer_stream).connect().await?;
        tracing::info!("TLS session with the Sigul bridge established");

        let hello: ProtocolHeader = role.into();
        outer_stream.write_all(hello.as_bytes()).await?;
        tracing::debug!(
            protocol_version = PROTOCOL_VERSION,
            ?role,
            "Protocol header sent"
        );

        Ok(outer_stream)
    }

    /// Pipe data between the outer TLS session and the inner TLS session.
    #[instrument(err, skip_all)]
    async fn ferry(
        mut outer_stream: SslStream<TcpStream>,
        mut client_inner_tls: DuplexStream,
    ) -> Result<SslStream<TcpStream>, Error> {
        let mut sent_inner_eof = false;
        let mut from_bridge_buffer = BytesMut::new();
        let mut from_client_buffer = BytesMut::new();
        loop {
            tokio::select! {
                // Read data from the client to forward via the bridge to the server.
                num_bytes = client_inner_tls.read_buf(&mut from_client_buffer), if !sent_inner_eof => {
                    // We expect to have completely written out the buffer each time.
                    let num_bytes = num_bytes?;
                    let to_forward = from_client_buffer.split().freeze();
                    tracing::trace!(num_bytes, "Forwarding bytes client wrote to the inner TLS session");
                    outer_stream.write_all(&to_forward).await?;

                    if num_bytes == 0 {
                        tracing::debug!("EOF received for inner TLS session from client");
                        sent_inner_eof = true;
                    }
                },

                // Read data from the server to forward to the client
                num_bytes = outer_stream.read_buf(&mut from_bridge_buffer) => {
                    let num_bytes = num_bytes?;
                    tracing::trace!(num_bytes, "Received bytes from the Sigul bridge");
                    let to_forward = from_bridge_buffer.split().freeze();
                    client_inner_tls.write_all(&to_forward).await?;

                    if num_bytes == 0 {
                        tracing::debug!("EOF received for inner TLS session from server");
                        break;
                    }
                }
            }
        }

        Ok(outer_stream)
    }
}

impl Nestls<state::Client> {
    pub fn inner(&mut self) -> &mut SslStream<DuplexStream> {
        &mut self.inner_stream
    }
}

impl Nestls<state::Server> {
    pub fn inner(&mut self) -> &mut SslStream<DuplexStream> {
        &mut self.inner_stream
    }
}
