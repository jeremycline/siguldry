// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::v2::config::Credentials;

/// Configuration for the siguldry server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The location where the server should store its state.
    ///
    /// This includes an SQLite database as well as encrypted private keys,
    /// certificates, and any other state required to operate. To back up
    /// the service, back up this directory.
    pub state_directory: PathBuf,

    /// The hostname of the Sigul bridge; this is used to verify the bridge's
    /// TLS certificate.
    pub bridge_hostname: String,

    /// The port to connect to the Sigul bridge; the default port is 44333 for
    /// the server.
    pub bridge_port: u16,

    /// The credentials to use when connecting to the bridge and when accepting client connections
    /// tunneled through the bridge. Note that the certificate must have both `clientAuth` and
    /// `serverAuth` in its extended key usage extension.
    pub credentials: Credentials,
}

impl Config {
    pub fn database(&self) -> PathBuf {
        self.state_directory.join("siguldry.sqlite")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_directory: PathBuf::from("/var/lib/siguldry/"),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44333,
            credentials: Credentials {
                private_key: PathBuf::from("sigul.server.private_key.pem"),
                certificate: PathBuf::from("sigul.server.certificate.pem"),
                ca_certificate: PathBuf::from("sigul.ca.certificate.pem"),
            },
        }
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}
