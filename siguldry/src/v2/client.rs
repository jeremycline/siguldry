// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

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
pub struct Client<S: ToSocketAddrs + std::fmt::Debug> {
    tls_config: tls::ClientConfig,
    bridge_address: S,
    bridge_hostname: String,
    server_hostname: String,
}

impl<S: ToSocketAddrs + std::fmt::Debug> Client<S> {
    pub fn new(
        tls_config: tls::ClientConfig,
        bridge_address: S,
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

    async fn connect(&self) -> Result<Nestls, Error> {
        let bridge_payload: ProtocolHeader = Role::Client.into();
        let conn = NestlsBuilder::new(self.tls_config.ssl(&self.bridge_hostname)?)
            .with_bridge_payload(bytes::Bytes::copy_from_slice(bridge_payload.as_bytes()))
            .connect(
                &self.bridge_address,
                self.tls_config.ssl(&self.server_hostname)?,
            )
            .await?;

        Ok(conn)
    }
}
