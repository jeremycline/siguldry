// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

use std::time::Duration;

use tower::{reconnect::Reconnect, Service, ServiceExt};

use crate::v2::{
    client::{service::MakeClientService, ConnectionConfig, Req},
    error::ClientError,
    protocol::{self, Response},
};

/// A siguldry client.
pub struct Client {
    inner: Reconnect<MakeClientService, ()>,
}

impl Client {
    /// Create a new client
    pub fn new(config: ConnectionConfig) -> Self {
        let inner = Reconnect::new(MakeClientService::new(config), ());
        Self { inner }
    }

    async fn send(&mut self, request: Req) -> Result<Response, ClientError> {
        self.inner
            .ready()
            .await
            .map_err(|err| *err.downcast::<ClientError>().expect("TODO"))?
            .call(request)
            .await
            .map_err(|err| *err.downcast::<ClientError>().expect("huh"))
    }

    async fn reconnecting_send(&mut self, request: Req) -> Result<Response, ClientError> {
        loop {
            match self.send(request.clone()).await {
                Ok(response) => break Ok(response),
                Err(ClientError::Connection(error)) => {
                    tracing::info!(?error, "Failed to connect");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(err) => break Err(err),
            }
        }
    }

    /// Attempt to authenticate against the server.
    ///
    /// Returns the username you successfully authenticated as.
    pub async fn who_am_i(&mut self) -> Result<String, ClientError> {
        let request = protocol::Request::WhoAmI {};
        let request = Req {
            message: request,
            binary: None,
        };
        let response = self.reconnecting_send(request).await?;
        match response {
            Response::WhoAmI { user } => Ok(user),
        }
    }
}
