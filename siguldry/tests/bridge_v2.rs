// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use anyhow::{bail, Context};
use siguldry::v2::{
    nestls::NestlsBuilder,
    protocol::{ProtocolHeader, Role},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
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
    )?;
    let bridge_payload: ProtocolHeader = Role::Client.into();
    let conn = NestlsBuilder::new(tls_config.ssl("sigul-bridge")?)
        .with_bridge_payload(bytes::Bytes::copy_from_slice(bridge_payload.as_bytes()))
        .connect("sigul-bridge:8080", tls_config.ssl("sigul-server")?);
    let client = tokio::spawn(conn);

    let server_tls_config = siguldry::v2::tls::ServerConfig::new(
        creds_directory.join("sigul.server.certificate.pem"),
        creds_directory.join("sigul.server.private_key.pem"),
        None,
        creds_directory.join("sigul.ca.certificate.pem"),
    )?;
    let bridge_payload: ProtocolHeader = Role::Server.into();
    let conn = NestlsBuilder::new(tls_config.ssl("sigul-bridge")?)
        .with_bridge_payload(bytes::Bytes::copy_from_slice(bridge_payload.as_bytes()))
        .accept("sigul-bridge:8081", server_tls_config);
    let server = tokio::spawn(conn);

    let mut client = client.await??;
    let mut server = server.await??;
    client.write_all(&[1, 2, 3]).await?;
    drop(client);

    let mut buf = [0_u8; 3];
    server.read_exact(&mut buf).await?;
    drop(server);

    assert_eq!(buf, [1, 2, 3]);

    halt_token.cancel();
    listener.await?;

    Ok(())
}
