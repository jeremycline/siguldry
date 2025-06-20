use std::{fmt::Debug, pin::Pin};

use openssl::ssl::Ssl;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::mpsc,
};
use tokio_openssl::SslStream;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{instrument, Instrument};
use uuid::Uuid;
use zerocopy::IntoBytes;

use crate::v2::{
    error::ConnectionError,
    protocol::{self, peer_common_name, Role},
    tls::ServerConfig,
};

async fn accept_conn(
    tcp_listener: &TcpListener,
    ssl: Ssl,
    role: Role,
) -> Result<SslStream<TcpStream>, ConnectionError> {
    let (tcp_stream, client_addr) = tcp_listener.accept().await?;
    tracing::info!(listener=?tcp_listener.local_addr()?, ?client_addr, "New TCP connection established");

    let mut stream = tokio_openssl::SslStream::new(ssl, tcp_stream)?;
    let result = Pin::new(&mut stream).accept().await;
    tracing::info!(listener=?tcp_listener.local_addr()?, ?client_addr, ?result, "TLS session established");

    let header_result = protocol::ProtocolHeader::check(&mut stream, role).await;
    if let Err(ConnectionError::Protocol(error)) = &header_result {
        tracing::warn!(
            ?error,
            "Incoming connection sent an invalid header; dropping connection"
        );
        let ack = protocol::ProtocolAck::new(error.into());
        stream.write_all(ack.as_bytes()).await?;
    }
    header_result?;

    let peer_name = peer_common_name(&mut stream);
    match &peer_name {
        Ok(username) => {
            // We defer acking good connections until we have both sides so that they can share a session id
            tracing::info!(username, ?role, "Sigul connection established");
        }
        Err(error) => {
            tracing::warn!(?error, "Incoming connection presented a client certificate without a common name; dropping connection");
            let ack = protocol::ProtocolAck::new(error.into());
            stream.write_all(ack.as_bytes()).await?;
        }
    };
    peer_name?;

    Ok(stream)
}

/// Act as a Siguldry bridge on the provided socket addresses.
#[instrument(skip_all, err)]
pub async fn listen<S>(
    client_socket_addr: S,
    server_socket_addr: S,
    tls_config: ServerConfig,
    halt_token: CancellationToken,
) -> anyhow::Result<()>
where
    S: ToSocketAddrs + Debug,
{
    let client_listener = TcpListener::bind(client_socket_addr).await?;
    let server_listener = TcpListener::bind(server_socket_addr).await?;
    let request_tracker = TaskTracker::new();

    let (server_conns_tx, mut server_conns_rx) = mpsc::channel::<SslStream<TcpStream>>(32);
    let (client_conns_tx, mut client_conns_rx) = mpsc::channel::<SslStream<TcpStream>>(32);

    let server_acceptor_halt = halt_token.clone();
    let server_tls_config = tls_config.clone();
    let server_acceptor = tokio::spawn(async move {
        let tls_config = server_tls_config;
        loop {
            // `accept_conn` is not cancel safe, but we will never resume it if it is canceled, so
            // that's okay. However, we can't plop all these into a single select without
            // refactoring significantly to make accept_conn safe, so leave it like this for now
            tokio::select! {
                _ = server_acceptor_halt.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break;
                },
                maybe_conn = accept_conn(&server_listener, tls_config.ssl()?, Role::Server) => {
                    match maybe_conn {
                        Ok(conn) => server_conns_tx.send(conn).await?,
                        Err(error) => tracing::warn!(?error, "Failed to accept new server connection"),
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    let client_acceptor_halt = halt_token.clone();
    let client_acceptor = tokio::spawn(async move {
        loop {
            // `accept_conn` is not cancel safe, but we will never resume it if it is canceled, so
            // that's okay. However, we can't plop all these into a single select without
            // refactoring significantly to make accept_conn safe, so leave it like this for now
            tokio::select! {
                _ = client_acceptor_halt.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break;
                },
                maybe_conn = accept_conn(&client_listener, tls_config.ssl()?, Role::Client) => {
                    match maybe_conn {
                        Ok(conn) => client_conns_tx.send(conn).await?,
                        Err(error) => tracing::warn!(?error, "Failed to accept new client connection"),
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    'accept: loop {
        tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("Shutdown requested, no new requests will be bridged");
                break 'accept;
            },
            connections = async { tokio::join!(client_conns_rx.recv(), server_conns_rx.recv()) } => {
                match connections {
                    (Some(mut client_conn), Some(mut server_conn)) => {
                        let ack = protocol::ProtocolAck::new(protocol::BridgeStatus::Ok);
                        client_conn.write_all(ack.as_bytes()).await?;
                        tracing::trace!("Sent client ack");
                        server_conn.write_all(ack.as_bytes()).await?;
                        tracing::trace!("Sent server ack");

                        let session_id = Uuid::from_u128(ack.session_id.get());
                        tracing::info!(?session_id, "Bridging new connection");
                        request_tracker.spawn(
                            bridge(session_id, client_conn, server_conn).instrument(tracing::Span::current()),
                        );
                    },
                    _ => {
                        tracing::info!("Channels for incoming connections closed; beginning shutdown");
                        break 'accept;
                    }
                }
            }
        }
    }

    // TODO: probably drain and cancel any pendign connections in the channels.

    request_tracker.close();
    request_tracker.wait().await;
    server_acceptor.await??;
    client_acceptor.await??;
    Ok(())
}

#[instrument(skip(client_conn, server_conn), ret)]
async fn bridge(
    session_id: Uuid,
    mut client_conn: SslStream<TcpStream>,
    mut server_conn: SslStream<TcpStream>,
) -> anyhow::Result<()> {
    // TODO timeout all the things
    let size = 1024 * 64;
    let (client_sent_bytes, server_sent_bytes) =
        tokio::io::copy_bidirectional_with_sizes(&mut client_conn, &mut server_conn, size, size)
            .await?;
    tracing::info!(
        client_sent_bytes,
        server_sent_bytes,
        "Connection bridge completed"
    );

    Ok(())
}
