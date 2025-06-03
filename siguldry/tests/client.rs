// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
//
// Integration tests for the siguldry client.
//
// These tests are expected to work against sigul v1.3+.

use std::path::PathBuf;

use siguldry::error::{ClientError, Sigul};

fn get_client() -> siguldry::client::Client {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../")
        .canonicalize()
        .unwrap();
    let creds_directory = repo_root.join("devel/creds/");
    let tls_config = siguldry::client::TlsConfig::new(
        creds_directory.join("sigul.client.certificate.pem"),
        creds_directory.join("sigul.client.private_key.pem"),
        None,
        creds_directory.join("sigul.ca_certificate.pem"),
    )
    .unwrap();
    let ci = std::env::var("GITHUB_ACTIONS").is_ok_and(|val| val.contains("true"));
    siguldry::client::Client::new(
        tls_config,
        if ci {
            "sigul-bridge".into()
        } else {
            "localhost".into()
        },
        44334,
        if ci {
            "sigul-server".into()
        } else {
            "localhost".into()
        },
        "sigul-client".into(),
    )
}

#[tokio::test]
async fn list_users() -> anyhow::Result<()> {
    let client = get_client();
    let users = client.users("my-admin-password".into()).await?;

    assert!(users.contains(&"sigul-client".to_string()));
    Ok(())
}

#[tokio::test]
async fn get_user() -> anyhow::Result<()> {
    let client = get_client();
    let user = client
        .get_user("my-admin-password".into(), "sigul-client".to_string())
        .await?;

    assert!(user.admin());
    assert_eq!(user.name(), "sigul-client");
    Ok(())
}

#[tokio::test]
async fn get_user_does_not_exist() -> anyhow::Result<()> {
    let client = get_client();
    let user = client
        .get_user("my-admin-password".into(), "not-sigul-client".to_string())
        .await;
    match user {
        Err(ClientError::Sigul(Sigul::UserNotFound)) => {}
        _ => panic!("Expected a Sigul error, got {:?}", user),
    }

    Ok(())
}

#[tokio::test]
async fn get_user_invalid_password() -> anyhow::Result<()> {
    let client = get_client();
    let user = client
        .get_user("not-my-admin-password".into(), "sigul-client".to_string())
        .await;
    if let Err(ClientError::Sigul(Sigul::AuthenticationFailed)) = user {
        // This is obviously a terrible error structure
    } else {
        panic!("Expected a Sigul error, got {:?}", user)
    }
    Ok(())
}
