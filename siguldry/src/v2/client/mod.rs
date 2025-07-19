// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.

use bytes::Bytes;

use crate::v2::{protocol::Request, tls};

mod api;
mod service;

pub use api::Client;

/// The client connection configuration.
#[derive(Debug)]
pub struct ConnectionConfig {
    pub(crate) tls_config: tls::ClientConfig,
    pub(crate) bridge_address: String,
    pub(crate) bridge_hostname: String,
    pub(crate) server_hostname: String,
}

impl ConnectionConfig {
    /// Create a new client connection configuration.
    pub fn new(
        tls_config: tls::ClientConfig,
        bridge_address: String,
        bridge_hostname: String,
        server_hostname: String,
    ) -> Self {
        Self {
            tls_config,
            bridge_address,
            bridge_hostname,
            server_hostname,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Req {
    message: Request,
    binary: Option<Bytes>,
}
