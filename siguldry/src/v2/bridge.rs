use std::{fmt::Debug, io::Read, path::Path, pin::Pin};

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use tokio_openssl::SslStream;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{instrument, Instrument};

async fn accept_conn(tcp_listener: &TcpListener, tls_config: &SslAcceptor) -> SslStream<TcpStream> {
    let (tcp_stream, client_addr) = tcp_listener.accept().await.unwrap();
    tracing::info!(listener=?tcp_listener, ?client_addr, "New TCP connection established");
    let ssl = Ssl::new(tls_config.context()).unwrap();
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp_stream).unwrap();
    let result = Pin::new(&mut stream).accept().await;
    tracing::info!(listener=?tcp_listener, ?client_addr, ?result, "TLS session established");

    stream
}

pub async fn listen<S>(
    client_socket_addr: S,
    server_socket_addr: S,
    tls_config: SslAcceptor,
    halt_token: CancellationToken,
) where
    S: ToSocketAddrs + Debug,
{
    let client_listener = TcpListener::bind(client_socket_addr).await.unwrap();
    let server_listener = TcpListener::bind(server_socket_addr).await.unwrap();
    let request_tracker = TaskTracker::new();

    'accept: loop {
        tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("Shutdown requested, no new requests will be accepted");
                break 'accept;
            },
            (client_conn, server_conn) = async {
                tokio::join!(accept_conn(&client_listener, &tls_config), accept_conn(&server_listener, &tls_config))
            } => {

                tracing::info!("Bridging new connection");
                request_tracker.spawn(bridge(client_conn, server_conn).instrument(tracing::Span::current()),
                );
            },
        }
    }

    request_tracker.close();
    request_tracker.wait().await;
}

fn acceptor<P: AsRef<Path>>(
    certificate: P,
    private_key: P,
    private_key_passphrase: Option<P>,

    client_ca: P,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut private_key_buf = vec![];
    std::fs::File::open(private_key)
        .unwrap()
        .read_to_end(&mut private_key_buf)
        .unwrap();
    let private_key = match &private_key_passphrase {
        Some(passphrase_path) => {
            let mut passphrase = vec![];
            std::fs::File::open(passphrase_path)
                .unwrap()
                .read_to_end(&mut passphrase)
                .unwrap();
            openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
        }
        None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
    };
    let f = std::fs::read_to_string(&client_ca).unwrap();
    let client_ca_cert = openssl::x509::X509::from_pem(f.as_bytes())?;

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    // TODO probaby should bump client up to 1.3
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.add_client_ca(&client_ca_cert)?;
    acceptor.set_ca_file(client_ca).unwrap();
    acceptor.set_private_key(&private_key)?;
    acceptor.set_certificate_file(&certificate, SslFiletype::PEM)?;
    acceptor.check_private_key()?;
    // TODO verify client CN matches username

    Ok(acceptor.build())
}

#[instrument(skip_all)]
async fn bridge(
    mut client_conn: SslStream<TcpStream>,
    mut server_conn: SslStream<TcpStream>,
) -> anyhow::Result<()> {
    // First, read and parse the client request
    // This includes the header, op, and payload. The operation and payload are sent on to the server
    // Then we should get an inner TLS session which we need to forward both ways
    // Then we get reply headers and payload from the server to forward to the client

    // If we want to support the "many-requests-in-a-connection" thing that is only in sign-rpms, after
    // the reply headers/payload, the client and server are free to chatter back and forth, but all that
    // logic is in the bridge. I don't love it, but if we don't do that we need to accept implementing a
    // whole v2 API

    // API improvements
    //
    // Consider using JSON or other common serialization format. Alternatively, zerocopy type structs on
    // the wire stream.
    //
    // Consider something like WebSockets which handles all the framing for us. Alternatively, make the framing
    // less of a headache. e.g. a frame is a whole message for one receipient and the header covers (total_size, recipient).
    // There should be no multi-frame requests/responses.
    //
    // Do away with sending the files to the server, require small payloads with the digest to be signed?
    //
    // Make the connection lifecycle be:
    //
    // TLS to bridge; announce API version supported, requested command (does the bridge need to know?).
    //
    // Inner connection client -> server for any secrets exchange (and afterwards no other inner session can be made).
    // The inner connection goes as long as both sides send blobs targeted for the other side.
    //
    // Client sends requests to bridge, server sends responses. Can continue however long they like, and each request
    // is separate from the prior one, except using the initially established secrets? Or put some restrictions on this,
    // e.g. must be for signing only and of the same type? Maybe split API into management and signing, management requests
    // are one-and-done? No, how about after the inner connection, a command can be composed of as much back and forth as
    // it wants, but concludes when either side sends the "I'm done" message to the bridge.
    //
    // Each request has an id that spans client/bridge/server

    // TODO READ HEADER
    let mut client_header = [0_u8; 13];
    _ = client_conn.read_exact(&mut client_header).await?;
    tracing::info!(?client_header, "client header received");
    let mut server_header = [0_u8; 13];
    _ = server_conn.read_exact(&mut server_header).await?;
    tracing::info!(?server_header, "client header received");

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
