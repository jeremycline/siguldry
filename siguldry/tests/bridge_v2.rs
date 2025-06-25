use std::{
    io::Read,
    path::{Path, PathBuf},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn basic_bridge_config() {
    let log_filter = EnvFilter::builder().parse("DEBUG").unwrap();
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let creds_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        //.join("../")
        .canonicalize()
        .unwrap();
    let tls_config = acceptor(
        creds_directory.join("sigul.bridge.certificate.pem"),
        creds_directory.join("sigul.bridge.private_key.pem"),
        None,
        creds_directory.join("sigul.ca_certificate.pem"),
    )
    .unwrap();

    let halt_token = CancellationToken::new();
    let listener = tokio::spawn(siguldry::v2::bridge::listen(
        "127.0.0.1:8080",
        "127.0.0.1:8081",
        tls_config,
        halt_token.clone(),
    ));

    let tls_config = siguldry::client::TlsConfig::new(
        creds_directory.join("sigul.client.certificate.pem"),
        creds_directory.join("sigul.client.private_key.pem"),
        None,
        creds_directory.join("sigul.ca_certificate.pem"),
    )
    .unwrap();
    let client = tokio::spawn(siguldry::v2::connection::Nestls::connect(
        "sigul-bridge:8080",
        tls_config.ssl("sigul-bridge").unwrap(),
        tls_config.ssl("sigul-server").unwrap(),
    ));

    let server_tls_config = acceptor(
        creds_directory.join("sigul.server.certificate.pem"),
        creds_directory.join("sigul.server.private_key.pem"),
        None,
        creds_directory.join("sigul.ca_certificate.pem"),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        siguldry::v2::connection::Nestls::accept(
            "sigul-bridge:8081",
            tls_config.ssl("sigul-bridge").unwrap(),
            &server_tls_config,
        )
        .await
    });

    let mut client_conn = client.await.unwrap().unwrap();
    let inner_client = client_conn.inner();
    let mut server_conn = server.await.unwrap().unwrap();
    let inner_server = server_conn.inner();
    inner_client.write_all(&[1, 2, 3]).await.unwrap();
    drop(client_conn);

    let mut buf = [0_u8; 3];
    inner_server.read_exact(&mut buf).await.unwrap();
    drop(server_conn);

    assert_eq!(buf, [1, 2, 3]);

    halt_token.cancel();
    listener.await.unwrap();
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
