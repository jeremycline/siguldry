// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A Sigul client.

use std::path::Path;
use std::{collections::HashMap, io::Read};

use anyhow::Context;
use bytes::{Buf, Bytes};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncWrite};
use tracing::{instrument, Instrument};

use crate::connection::Connection;
use crate::error::ClientError as Error;

/// String newtype with custom Display and Debug impls to avoid logging passphrases.
pub struct Password(String);

impl Password {
    /// Convert this password to bytes to send.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"*****").finish()
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"*****").finish()
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl TryFrom<&Path> for Password {
    type Error = Error;

    /// Read a passphrase from the file.
    ///
    /// If the first line does not contain a string, an error is returned.
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        let passphrase = std::fs::read_to_string(value)?
            .lines()
            .next()
            .and_then(|pass| {
                let pass = pass.trim();
                if !pass.is_empty() {
                    Some(pass)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Passphrase file {} does not contain a password on the first line",
                    value.display()
                )
            })?
            .to_string();

        Ok(Self(passphrase))
    }
}

/// Sigul commands supported by this client.
#[derive(Serialize, Debug, Clone)]
pub(crate) enum Command {
    SignPe {
        /// The user to authenticate as.
        user: String,
        key: String,
        cert_name: String,
    },
    ListUsers {
        /// The user to authenticate as.
        user: String,
    },
    UserInfo {
        /// The user to authenticate as.
        user: String,
        /// The user to retrieve info for.
        name: String,
    },
    NewUser {
        /// The user to authenticate as.
        user: String,
        /// The name of the new user.
        name: String,
        /// Whether the new user is an administrator.
        admin: bool,
    },
    DeleteUser {
        /// The user to authenticate as.
        user: String,
        /// The user to delete.
        name: String,
    },
    ModifyUser {
        /// The user to authenticate as.
        user: String,

        /// The user to modify.
        name: String,

        /// Whether or not the user should be an admin. Providing `None` means no change.
        #[serde(skip_serializing_if = "Option::is_none")]
        admin: Option<bool>,

        /// The new user name, if a change is desired. Providing `None` means no change.
        #[serde(skip_serializing_if = "Option::is_none")]
        new_name: Option<String>,
    },
}

/// Response types used by the client.
pub mod responses {
    /// A Sigul user.
    #[derive(Debug, Clone)]
    pub struct User {
        /// The username.
        pub(crate) name: String,
        /// True if the user is a sigul administrator
        pub(crate) admin: bool,
    }

    impl User {
        /// The user's name.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Returns true if the user is a Sigul administrator.
        pub fn admin(&self) -> bool {
            self.admin
        }
    }
}

/// Connect to a sigul server.
#[derive(Debug, Clone)]
pub struct Client {
    /// The TLS configuration to use for connections to the bridge and server.
    tls_config: TlsConfig,
    /// The bridge's hostname used to connect to it as well as validate its TLS certificate.
    bridge_hostname: String,
    /// The port to use when connecting to the bridge.
    bridge_port: u16,
    /// The server's hostname, used to validate its TLS certificate.
    server_hostname: String,
    /// The username to authenticate as.
    user_name: String,
}

/// The TLS configuration used by the Sigul client.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    connector: SslConnector,
}

impl TlsConfig {
    /// Create a new TLS configuration for a Sigul client.
    pub fn new<P: AsRef<std::path::Path>>(
        certificate: P,
        private_key: P,
        private_key_passphrase: Option<P>,
        certificate_authority: P,
    ) -> Result<Self, Error> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        // The Python version makes this configurable, and fails if the min version is less than 1.2
        connector.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_ca_file(&certificate_authority)?;

        let mut private_key_buf = vec![];
        std::fs::File::open(private_key)?.read_to_end(&mut private_key_buf)?;
        let private_key = match &private_key_passphrase {
            Some(passphrase_path) => {
                let mut passphrase = vec![];
                std::fs::File::open(passphrase_path)?.read_to_end(&mut passphrase)?;
                openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
            }
            None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
        };
        connector.set_private_key(&private_key)?;
        connector.set_certificate_file(&certificate, SslFiletype::PEM)?;
        connector.check_private_key()?;

        Ok(Self {
            connector: connector.build(),
        })
    }

    /// Retrieve an SSL configuration acceptable to use when connecting to the provided hostname.
    fn ssl(&self, hostname: &str) -> Result<openssl::ssl::Ssl, Error> {
        let ssl = self.connector.configure()?.into_ssl(hostname)?;
        tracing::debug!(verify_mode=?ssl.ssl_context().verify_mode(), hostname=hostname, "Created SSL connection config");
        Ok(ssl)
    }
}

/// Utility for commands that don't expect large (or any) payload response.
fn get_payload_pipe() -> (
    tokio::task::JoinHandle<Result<Vec<u8>, std::io::Error>>,
    tokio::io::WriteHalf<tokio::io::SimplexStream>,
) {
    let (mut payload_reader, payload_writer) = tokio::io::simplex(4096);
    let payload = tokio::spawn(
        async move {
            let mut payload = vec![];
            payload_reader.read_to_end(&mut payload).await?;
            tracing::debug!(payload_length = payload.len(), "Response payload received",);
            Ok::<_, std::io::Error>(payload)
        }
        .in_current_span(),
    );

    (payload, payload_writer)
}

impl Client {
    /// Create a new Sigul client.
    ///
    /// This can fail if the OpenSSL library available doesn't support the required TLS configuration.
    pub fn new(
        tls_config: TlsConfig,
        bridge_hostname: String,
        bridge_port: u16,
        server_hostname: String,
        user_name: String,
    ) -> Self {
        Self {
            tls_config,
            bridge_hostname,
            bridge_port,
            server_hostname,
            user_name,
        }
    }

    /// Connect to the Sigul bridge.
    async fn connect(&self) -> Result<Connection, Error> {
        let ssl = self.tls_config.ssl(&self.bridge_hostname)?;
        Ok(Connection::connect((self.bridge_hostname.as_str(), self.bridge_port), ssl).await?)
    }

    /// List the users on the Sigul server
    ///
    /// The user you are authenticated as must be an administrator.
    #[instrument(skip_all)]
    pub async fn users(&self, admin_passphrase: Password) -> Result<Vec<String>, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ListUsers {
                    user: self.user_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let mut num_users = response
            .fields
            .get("num-users")
            .map(|b| Bytes::from(b.to_vec()))
            .ok_or(anyhow::anyhow!("missing expected field 'num-users'"))?;

        if num_users.len() != 4 {
            // The expected value of this field is a u32.
            return Err(anyhow::anyhow!(
                "the 'num-users' field was {} bytes; expected 4",
                num_users.len()
            )
            .into());
        }
        let num_users: usize = num_users
            .get_u32()
            .try_into()
            .context("the number of users couldn't be converted to usize")?;
        let users = payload
            .split(|byte| *byte == 0)
            .filter_map(|name| {
                if !name.is_empty() {
                    String::from_utf8(name.into()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if users.len() != num_users {
            return Err(anyhow::anyhow!(
                "Server response indicated {} users, but {} names were sent!",
                num_users,
                users.len()
            )
            .into());
        }

        Ok(users)
    }

    /// Get information about the given user
    #[instrument(skip_all)]
    pub async fn get_user(
        &self,
        admin_passphrase: Password,
        name: String,
    ) -> Result<responses::User, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::UserInfo {
                    user: self.user_name.clone(),
                    name: name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        let admin = response
            .fields
            .get("admin")
            .and_then(|b| b.first())
            .map(|b| *b == 1)
            .ok_or(anyhow::anyhow!("missing expected field 'admin'"))?;

        Ok(responses::User { name, admin })
    }

    /// Add a new user to the Sigul server.
    ///
    /// If the `admin` parameter is `true`, the new user is created as a server administrator.
    /// Optionally, the new user's password can be set. If it is not set when the user is created,
    /// it can be set using [`Client::modify_user`].
    #[instrument(skip_all)]
    pub async fn create_user(
        &self,
        admin_passphrase: Password,
        name: String,
        admin: bool,
        user_passphrase: Option<Password>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        user_passphrase
            .as_ref()
            .map(|p| inner_request.insert("new-password", p.as_bytes()));
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::NewUser {
                    user: self.user_name.clone(),
                    name,
                    admin,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Modify an existing user on the Sigul server.
    ///
    /// Users can have new names, their password changed, and be set as admins or not.
    /// Providing `None` for any optional parameters will leave that setting unchanged.
    #[instrument(skip_all)]
    pub async fn modify_user(
        &self,
        admin_passphrase: Password,
        name: String,
        new_name: Option<String>,
        admin: Option<bool>,
        user_passphrase: Option<Password>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        user_passphrase
            .as_ref()
            .map(|p| inner_request.insert("new-password", p.as_bytes()));
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ModifyUser {
                    user: self.user_name.clone(),
                    name,
                    new_name,
                    admin,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Remove a user from the Sigul server.
    ///
    /// Users can only be deleted if they do not have access to any keys, and this call will
    /// fail with [`crate::error::Sigul::UserHasKeyAccess`] if an attempt is made to delete a
    /// user with key access.
    #[instrument(skip_all)]
    pub async fn delete_user(&self, admin_passphrase: Password, name: String) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::DeleteUser {
                    user: self.user_name.clone(),
                    name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Sign a platform executable (PE) file for Secure Boot.
    #[instrument(skip_all)]
    pub async fn sign_pe<I, O>(
        &self,
        input: I,
        output: O,
        key_passphrase: Password,
        key_name: String,
        cert_name: String,
    ) -> Result<(), Error>
    where
        I: AsyncRead + AsyncSeek + Unpin,
        O: AsyncWrite + Unpin,
    {
        let connection = self.connect().await?;

        let op = Command::SignPe {
            user: self.user_name.to_string(),
            key: key_name,
            cert_name,
        };

        let mut inner_request = HashMap::new();
        inner_request.insert("passphrase", key_passphrase.as_bytes());

        let response = connection
            .outer_request(op, Some(input))
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(output)
            .await?;

        tracing::info!(?response.fields, response.status_code, "Got response fields");
        Ok(())
    }
}
