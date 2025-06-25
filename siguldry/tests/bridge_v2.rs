use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

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

    // TODO: generate keys on test run using siguldry_auth_keys.sh
    let creds_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        //.join("../")
        .canonicalize()
        .unwrap();

    let bridge_tls_config = siguldry::v2::tls::ServerConfig::new(
        creds_directory.join("sigul.bridge.certificate.pem"),
        creds_directory.join("sigul.bridge.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )
    .unwrap();
    let halt_token = CancellationToken::new();
    let listener = tokio::spawn(siguldry::v2::bridge::listen(
        "127.0.0.1:8080",
        "127.0.0.1:8081",
        bridge_tls_config,
        halt_token.clone(),
    ));

    let tls_config = siguldry::v2::tls::ClientConfig::new(
        creds_directory.join("sigul.client.certificate.pem"),
        creds_directory.join("sigul.client.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )
    .unwrap();
    let client = tokio::spawn(siguldry::v2::connection::Nestls::connect(
        "sigul-bridge:8080",
        tls_config.ssl("sigul-bridge").unwrap(),
        tls_config.ssl("sigul-server").unwrap(),
    ));

    let server_tls_config = siguldry::v2::tls::ServerConfig::new(
        creds_directory.join("sigul.server.certificate.pem"),
        creds_directory.join("sigul.server.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
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
