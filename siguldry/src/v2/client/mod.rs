// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.

use std::path::PathBuf;

use crate::v2::config::Credentials;

mod api;
mod service;

pub use api::Client;
use serde::{Deserialize, Serialize};

/// Configuration for the siguldry client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The Siguldry server hostname. This is used to validate the server's TLS certificate.
    pub server_hostname: String,
    /// The Siguldry bridge hostname. This is used to validate the bridge's TLS certificate.
    pub bridge_hostname: String,
    /// The port on the Siguldry bridge to connect to; the default is 44334.
    pub bridge_port: u16,
    /// The credentials to use when authenticating to the Siguldry bridge and server. Note that
    /// the certificate must have the `clientAuth` extended key usage extension.
    pub credentials: Credentials,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_hostname: "server.example.com".to_string(),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44334,
            credentials: Credentials {
                private_key: PathBuf::from("sigul.client.private_key.pem"),
                certificate: PathBuf::from("sigul.client.certificate.pem"),
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
