// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A sigul server.

use tokio::net::ToSocketAddrs;
use zerocopy::IntoBytes;

use crate::v2::{
    error::{ClientError as Error, ConnectionError},
    nestls::{Nestls, NestlsBuilder},
    protocol::{ProtocolHeader, Role},
    tls,
};

/// A sigul client.
#[derive(Debug)]
pub struct Server<S: ToSocketAddrs + std::fmt::Debug> {
    tls_config: tls::ClientConfig,
    server_tls_config: tls::ServerConfig,
    bridge_address: S,
    bridge_hostname: String,
}

impl<S: ToSocketAddrs + std::fmt::Debug> Server<S> {
    pub fn new(
        tls_config: tls::ClientConfig,
        server_tls_config: tls::ServerConfig,
        bridge_address: S,
        bridge_hostname: String,
    ) -> Self {
        Self {
            tls_config,
            server_tls_config,
            bridge_address,
            bridge_hostname,
        }
    }

    async fn accept(&self) -> Result<Nestls, Error> {
        let bridge_payload: ProtocolHeader = Role::Server.into();
        let conn = NestlsBuilder::new(self.tls_config.ssl(&self.bridge_hostname)?)
            .with_bridge_payload(bytes::Bytes::copy_from_slice(bridge_payload.as_bytes()))
            .accept(&self.bridge_address, self.server_tls_config.clone())
            .await?;

        Ok(conn)
    }
}
