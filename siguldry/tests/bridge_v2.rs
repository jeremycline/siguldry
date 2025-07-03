// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Context};
use siguldry::v2::{
    client::{self, RetryPolicy},
    nestls::NestlsBuilder,
    protocol, server,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tower::{
    retry::backoff::MakeBackoff, util::rng::HasherRng, Service, ServiceBuilder, ServiceExt,
};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};
use zerocopy::IntoBytes;

use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn basic_bridge_config() -> anyhow::Result<()> {
    let log_filter = EnvFilter::builder().parse("DEBUG")?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let tempdir = tempfile::TempDir::new()?;
    let mut command = Command::new("bash");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devel/sigul_auth_keys.sh");
    let status = command
        .current_dir(tempdir.path())
        .args([script.as_path()])
        .status()
        .await?;
    if !status.success() {
        bail!("Failed to generate auth keys");
    }

    let creds_directory = tempdir.path().join("creds/");
    let bridge_tls_config = siguldry::v2::tls::ServerConfig::new(
        creds_directory.join("sigul.bridge.certificate.pem"),
        creds_directory.join("sigul.bridge.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )
    .context("Failed to load bridge credentials")?;
    let bridge_halt_token = CancellationToken::new();
    let client_bridge_addr = "127.0.0.1:8080";
    let server_bridge_addr = "127.0.0.1:8081";
    let bridge_task = tokio::spawn(siguldry::v2::bridge::listen(
        client_bridge_addr,
        server_bridge_addr,
        bridge_tls_config,
        bridge_halt_token.clone(),
    ));

    let client_tls_config = siguldry::v2::tls::ClientConfig::new(
        creds_directory.join("sigul.client.certificate.pem"),
        creds_directory.join("sigul.client.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )?;
    let server_tls_config = siguldry::v2::tls::ServerConfig::new(
        creds_directory.join("sigul.server.certificate.pem"),
        creds_directory.join("sigul.server.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )?;
    let client_service = client::ClientService::new(
        client_tls_config.clone(),
        client_bridge_addr.to_string(),
        "sigul-bridge".into(),
        "sigul-server".into(),
    );
    let policy = RetryPolicy::new();
    let mut client = ServiceBuilder::new()
        .retry(policy)
        .timeout(Duration::from_secs(30))
        .service(client_service);

    let server_halt_token = CancellationToken::new();
    let server = server::Server::new(
        client_tls_config,
        server_tls_config,
        server_bridge_addr,
        "sigul-bridge".into(),
        server_halt_token.clone(),
    );
    let server_task = tokio::spawn(server.run());

    let response = client.call(protocol::Request::Hello {}).await.unwrap();
    match response {
        protocol::Response::Hello { user } => assert_eq!(user, "whoever you are"),
    }

    server_halt_token.cancel();
    bridge_halt_token.cancel();
    server_task.await?;
    bridge_task.await?;

    Ok(())
}
