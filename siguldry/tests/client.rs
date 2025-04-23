// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.
//
// Integration tests for the siguldry client.
//
// These tests are expected to work against sigul v1.3+.

use std::path::PathBuf;

use siguldry::error::{ClientError, Sigul};
use tokio::sync::RwLock;

/// Some tests fiddle with the `sigul-client` account
static SIGUL_CLIENT: std::sync::LazyLock<RwLock<()>> = std::sync::LazyLock::new(|| RwLock::new(()));

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

// Assert our user is in the list somewhere; since this runs at the same time
// as tests that create and remove users this is the best we can do.
#[tokio::test]
async fn list_users() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let expected_user = "sigul-client".to_string();
    let users = client.users("my-admin-password".into()).await?;

    assert!(users.contains(&expected_user));
    Ok(())
}

#[tokio::test]
async fn get_user() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
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
    let _guard = SIGUL_CLIENT.read().await;
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
    if !matches!(user, Err(ClientError::Sigul(Sigul::AuthenticationFailed))) {
        panic!("Expected a Sigul error, got {:?}", user)
    }

    Ok(())
}

#[tokio::test]
async fn create_user_no_password() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), "no-password-user".to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    client
        .create_user(
            "my-admin-password".into(),
            "no-password-user".to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), "no-password-user".to_string())
        .await?;

    assert_eq!(user.name(), "no-password-user");
    assert!(!user.admin());
    Ok(())
}

#[tokio::test]
async fn create_user_with_password() -> anyhow::Result<()> {
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), "with-password-user".to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }

    client
        .create_user(
            "my-admin-password".into(),
            "with-password-user".to_string(),
            true,
            Some("with-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), "with-password-user".to_string())
        .await?;

    assert_eq!(user.name(), "with-password-user");
    assert!(user.admin());
    Ok(())
}

#[tokio::test]
async fn modify_user_toggle_admin() -> anyhow::Result<()> {
    let test_user = "modify-admin-user";
    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), test_user.to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }
    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(!user.admin());

    // Promote the user to admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            Some(true),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(user.admin());

    // Return the user to non-admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            Some(false),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert!(!user.admin());
    Ok(())
}

#[tokio::test]
async fn modify_user_change_name() -> anyhow::Result<()> {
    let test_user = "modify-user-change-name";
    let test_user_new_name = "modified-name";

    let client = get_client();
    let _guard = SIGUL_CLIENT.read().await;
    let cleanup = client
        .delete_user("my-admin-password".into(), test_user.to_string())
        .await;
    if cleanup.is_err() && !matches!(cleanup, Err(ClientError::Sigul(Sigul::UserNotFound))) {
        panic!("Expected a Sigul error, got {:?}", cleanup)
    }
    client
        .create_user(
            "my-admin-password".into(),
            test_user.to_string(),
            false,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);

    // Change the user's name
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            Some(test_user_new_name.to_string()),
            None,
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user_new_name.to_string())
        .await?;
    assert_eq!(user.name(), test_user_new_name);
    assert!(!user.admin());

    // Return the user to the original name and promote it to admin
    client
        .modify_user(
            "my-admin-password".into(),
            test_user_new_name.to_string(),
            Some(test_user.to_string()),
            Some(true),
            None,
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);
    assert!(user.admin());

    Ok(())
}

#[tokio::test]
async fn modify_user_change_password() -> anyhow::Result<()> {
    let test_user = "sigul-client";

    let client = get_client();
    let _guard = SIGUL_CLIENT.write().await;
    _ = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;

    // Change the user's password and verify the old one doesn't work
    client
        .modify_user(
            "my-admin-password".into(),
            test_user.to_string(),
            None,
            None,
            Some("my-new-admin-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await;
    if !matches!(user, Err(ClientError::Sigul(Sigul::AuthenticationFailed))) {
        panic!("The user's old password still works!");
    }
    _ = client
        .get_user("my-new-admin-password".into(), test_user.to_string())
        .await?;

    // Set the password back to the original
    client
        .modify_user(
            "my-new-admin-password".into(),
            test_user.to_string(),
            None,
            Some(true),
            Some("my-admin-password".into()),
        )
        .await?;
    let user = client
        .get_user("my-admin-password".into(), test_user.to_string())
        .await?;
    assert_eq!(user.name(), test_user);
    assert!(user.admin());

    Ok(())
}
