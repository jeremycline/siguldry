// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::v2::{
    client::{service::ClientService, Config},
    error::{ClientError, ConnectionError},
    nestls::Nestls,
    protocol::{self, json::Response, Request, Role},
};

/// A siguldry client.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<Config>,
    service: Arc<Mutex<Option<ClientService>>>,
}

impl Client {
    /// Create a new client
    pub fn new(config: Config) -> Result<Self, ClientError> {
        Ok(Self {
            config: Arc::new(config),
            service: Arc::new(Mutex::new(None)),
        })
    }

    async fn reconnecting_send(&self, request: Request) -> Result<Response, ClientError> {
        loop {
            let mut service_lock = self.service.lock().await;
            if let Some(mut service) = service_lock.take() {
                match service.call(request.clone()).await {
                    Ok(response) => {
                        *service_lock = Some(service);
                        break Ok(response);
                    }
                    Err(ClientError::Connection(ConnectionError::Io(error))) => {
                        tracing::info!(
                            ?error,
                            "An I/O error occurred while connecting; retrying..."
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Err(err) => break Err(err),
                }
            } else {
                let tls_config = self.config.credentials.ssl_connector()?;
                let bridge_ssl = tls_config
                    .configure()?
                    .into_ssl(&self.config.bridge_hostname)?;
                let server_ssl = tls_config
                    .configure()?
                    .into_ssl(&self.config.server_hostname)?;
                let conn = Nestls::builder(bridge_ssl, Role::Client)
                    .connect(
                        format!(
                            "{}:{}",
                            &self.config.bridge_hostname, self.config.bridge_port
                        ),
                        server_ssl,
                    )
                    .await?;
                *service_lock = Some(ClientService::new(conn));
            }
        }
    }

    /// Attempt to authenticate against the server.
    ///
    /// Returns the username you successfully authenticated as.
    pub async fn who_am_i(&self) -> Result<String, ClientError> {
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

    pub async fn list_users(&self) -> Result<Vec<String>, ClientError> {
        let request = Request {
            message: protocol::json::Request::ListUsers {},
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response {
            Response::ListUsers { users } => Ok(users),
            Response::Error { reason } => Err(reason.into()),
            _other => panic!("don't panic here"),
        }
    }
}
