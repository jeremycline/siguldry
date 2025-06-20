// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
#![cfg(all(feature = "v2-server", feature = "v2-client"))]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use siguldry::v2::{
    bridge, client,
    config::Credentials,
    error::{ClientError, ConnectionError},
    server,
};
use tokio::process::Command;
use tracing::Instrument;

struct Creds {
    pub server: Credentials,
    pub bridge: Credentials,
    pub client: Credentials,
}

// Generate a set of credentials in the given directory.
async fn create_credentials(
    dir: &Path,
    bridge_hostname: &str,
    server_hostname: &str,
) -> anyhow::Result<Creds> {
    let mut command = Command::new("bash");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devel/siguldry_auth_keys.sh");
    let status = command
        .current_dir(dir)
        .arg(script.as_path())
        .args([server_hostname, bridge_hostname, "sigul-client"])
        .status()
        .await?;
    if !status.success() {
        bail!("Failed to generate auth keys");
    }

    let creds_directory = dir.join("creds/");
    Ok(Creds {
        server: siguldry::v2::config::Credentials {
            private_key: creds_directory.join("sigul.server.private_key.pem"),
            certificate: creds_directory.join("sigul.server.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
        },
        bridge: siguldry::v2::config::Credentials {
            private_key: creds_directory.join("sigul.bridge.private_key.pem"),
            certificate: creds_directory.join("sigul.bridge.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
        },
        client: siguldry::v2::config::Credentials {
            private_key: creds_directory.join("sigul.client.private_key.pem"),
            certificate: creds_directory.join("sigul.client.certificate.pem"),
            ca_certificate: creds_directory.join("sigul.ca.certificate.pem"),
        },
    })
}

struct Instance {
    pub server: server::service::Listener,
    pub bridge: bridge::Listener,
    pub client: client::Client,
    // Dropping TempDir cleans up the directory, but it needs to live to the end of the test.
    #[allow(dead_code)]
    pub state_dir: tempfile::TempDir,
}

async fn create_instance() -> anyhow::Result<Instance> {
    // Unlike the server, which involves no DNS resolution from the client, the
    // bridge hostname needs to resolve and match the certificate it presents.
    let bridge_hostname = "localhost";
    let server_hostname = "sigul-server";
    let tempdir = tempfile::TempDir::new()?;
    let creds = create_credentials(tempdir.path(), bridge_hostname, server_hostname).await?;

    let bridge_config = bridge::Config {
        server_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        client_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        credentials: creds.bridge,
    };
    let bridge = siguldry::v2::bridge::listen(bridge_config)
        .instrument(tracing::info_span!("bridge"))
        .await?;

    let server_config = siguldry::v2::server::config::Config {
        state_directory: tempdir.path().into(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: bridge.server_port(),
        credentials: creds.server,
    };
    let server = server::service::Server::new(server_config).await?;
    server.migrate().await?;
    server.create_user("sigul-client", true).await?;
    let server = server.run();

    let client_config = client::Config {
        server_hostname: server_hostname.to_string(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: bridge.client_port(),
        credentials: creds.client,
    };
    let client = client::Client::new(client_config)?;

    Ok(Instance {
        server,
        bridge,
        client,
        state_dir: tempdir,
    })
}

#[tokio::test]
#[tracing_test::traced_test]
async fn basic_bridge_config() -> anyhow::Result<()> {
    let instance = create_instance().await?;
    let mut client = instance.client;

    client
        .new_user("another-sigul-client".to_string(), false)
        .await
        .unwrap();
    for _ in 0..5 {
        let username = client.who_am_i().await.unwrap();
        assert_eq!(username, "sigul-client");
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}

// If the bridge presents a certificate signed by a different CA, the client should reject it.
#[tokio::test]
#[tracing_test::traced_test]
async fn client_rejects_bridge_cert() -> anyhow::Result<()> {
    let bridge_hostname = "localhost";
    let server_hostname = "sigul-server";
    let instance = create_instance().await?;

    let tempdir = tempfile::TempDir::new()?;
    let creds = create_credentials(tempdir.path(), bridge_hostname, server_hostname).await?;
    let client_config = client::Config {
        server_hostname: server_hostname.to_string(),
        bridge_hostname: bridge_hostname.to_string(),
        bridge_port: instance.bridge.client_port(),
        credentials: creds.client,
    };
    let mut client = client::Client::new(client_config)?;

    let username = client.who_am_i().await;
    match username {
        Ok(_) => panic!("The request should not succeed"),
        Err(ClientError::Connection(ConnectionError::Ssl(error))) => {
            let error = error.ssl_error().unwrap().errors().first().unwrap();
            assert_eq!(error.reason_code(), 134);
            assert_eq!(error.reason(), Some("certificate verify failed"));
            assert!(logs_contain("certificate verify failed"));
        }
        Err(other) => panic!("Incorrect error variant returned: {other:?}"),
    }

    drop(client);
    instance.server.halt().await?;
    instance.bridge.halt().await?;

    Ok(())
}
