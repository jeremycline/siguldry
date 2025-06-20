// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

use std::time::Duration;

use tower::{reconnect::Reconnect, Service, ServiceExt};

use crate::v2::{
    client::{service::MakeClientService, Config},
    error::{ClientError, ConnectionError},
    protocol::{self, json::Response, Request},
};

/// A siguldry client.
pub struct Client {
    inner: Reconnect<MakeClientService, ()>,
}

impl Client {
    /// Create a new client
    pub fn new(config: Config) -> Result<Self, ClientError> {
        let inner = Reconnect::new(MakeClientService::new(config)?, ());
        Ok(Self { inner })
    }

    async fn send(&mut self, request: Request) -> Result<Response, ClientError> {
        self.inner
            .ready()
            .await
            .map_err(|err| *err.downcast::<ClientError>().expect("TODO"))?
            .call(request)
            .await
            .map_err(|err| *err.downcast::<ClientError>().expect("huh"))
    }

    async fn reconnecting_send(&mut self, request: Request) -> Result<Response, ClientError> {
        loop {
            match self.send(request.clone()).await {
                Ok(response) => break Ok(response),
                Err(ClientError::Connection(ConnectionError::Io(error))) => {
                    tracing::info!(
                        ?error,
                        "An I/O error occurred while connecting; retrying..."
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                Err(err) => break Err(err),
            }
        }
    }

    /// Attempt to authenticate against the server.
    ///
    /// Returns the username you successfully authenticated as.
    pub async fn who_am_i(&mut self) -> Result<String, ClientError> {
        let request = protocol::json::Request::WhoAmI {};
        let request = Request {
            message: request,
            binary: None,
        };
        let response = self.reconnecting_send(request).await?;
        match response {
            Response::WhoAmI { user } => Ok(user),
            Response::Error { reason } => Err(reason.into()),
            _other => panic!("don't panic here"),
        }
    }
}
