use std::{io::Read, path::Path, pin::Pin, sync::Arc};

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{instrument, Instrument};

async fn accept_conn(tcp_listener: &TcpListener, tls_config: &SslAcceptor) -> SslStream<TcpStream> {
    let (tcp_stream, client_addr) = tcp_listener.accept().await.unwrap();
    tracing::info!(?client_addr, "New TCP connection established");
    let ssl = Ssl::new(tls_config.context()).unwrap();
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp_stream).unwrap();
    Pin::new(&mut stream).accept().await.unwrap();
    tracing::info!(?client_addr, "TLS session established");

    stream
}

// TODO see about tower service
pub async fn listen(halt_token: CancellationToken) {

    let addr = "127.0.0.1:8080";
    let client_listener = TcpListener::bind(addr).await.unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:8081").await.unwrap();
    let tls_config = Arc::new(acceptor("devel/creds/sigul.bridge.certificate.pem", "devel/creds/sigul.bridge.private_key.pem", None, "devel/creds/sigul.ca_certificate.pem").unwrap());
    let request_tracker = TaskTracker::new();

    let streams = tokio::join!(accept_conn(&client_listener, &tls_config), accept_conn(&server_listener, &tls_config));
    let (client_stream, server_stream) = streams;
    request_tracker.spawn(bridge(client_stream, server_stream).instrument(tracing::Span::current()));

    'accept: loop {
        let mut client_connection = None;
        let mut server_connection = None;

        // TODO: maybe accept a pool of client and server conns
        while client_connection.is_none() || server_connection.is_none() {
            tokio::select! {
                _ = halt_token.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break 'accept;
                }
                client_conn = accept_conn(&client_listener, &tls_config), if client_connection.is_none() => client_connection = Some(client_conn),
                server_conn = accept_conn(&server_listener, &tls_config), if server_connection.is_none() => server_connection = Some(server_conn),
            }
        }
        request_tracker.spawn(bridge(client_connection.unwrap(), server_connection.unwrap()).instrument(tracing::Span::current()));
    }
}

fn acceptor<P: AsRef<Path>>(
        certificate: P,
        private_key: P,
        private_key_passphrase: Option<P>,
    
    client_ca: P) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut private_key_buf = vec![];
    std::fs::File::open(private_key).unwrap().read_to_end(&mut private_key_buf).unwrap();
    let private_key = match &private_key_passphrase {
        Some(passphrase_path) => {
            let mut passphrase = vec![];
            std::fs::File::open(passphrase_path).unwrap().read_to_end(&mut passphrase).unwrap();
            openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
        }
        None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
    };
    let f = std::fs::read_to_string(client_ca).unwrap();
    let client_ca = openssl::x509::X509::from_pem(f.as_bytes())?;

    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    // TODO probaby should bump client up to 1.3
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.add_client_ca(&client_ca)?;
    acceptor.set_private_key(&private_key)?;
    acceptor.set_certificate_file(&certificate, SslFiletype::PEM)?;
    acceptor.check_private_key()?;
    // TODO verify client CN matches username

    Ok(acceptor.build())
}

#[instrument(skip_all)]
async fn bridge(client_conn: SslStream<TcpStream>, server_conn: SslStream<TcpStream>) {
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

}
