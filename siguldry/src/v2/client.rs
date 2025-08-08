// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.
use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Receiver;
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
};
use tracing::instrument;
use uuid::Uuid;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    error::{ClientError, ConnectionError},
    nestls::Nestls,
    protocol::{
        self,
        json::{OuterRequest, OuterResponse, Response},
        Frame, Request, Role,
    },
};

use crate::v2::config::Credentials;

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

/// A siguldry client.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<Config>,
    inner: Arc<Mutex<Option<InnerClient>>>,
}

impl Client {
    /// Create a new client
    pub fn new(config: Config) -> Result<Self, ClientError> {
        Ok(Self {
            config: Arc::new(config),
            inner: Arc::new(Mutex::new(None)),
        })
    }

    /// Get the current client configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    async fn reconnecting_send(&self, request: Request) -> Result<Response, ClientError> {
        let response = loop {
            let mut service_lock = self.inner.lock().await;
            if let Some(mut service) = service_lock.take() {
                match service.send(request.clone()).await {
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
                *service_lock = Some(InnerClient::new(conn));
            }
        }?;

        // A RecvError happens if the sending/receiving task fails due to a network error.
        // TODO consider piping the error back before the task exits.
        response
            .await
            .map_err(|error| ClientError::Connection(ConnectionError::Io(io::Error::other(error))))
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

// This structure maps to a single connection to the server.
#[derive(Clone, Debug)]
struct InnerClient {
    request_tx: mpsc::Sender<(Bytes, oneshot::Sender<Response>)>,
    session_id: Uuid,
    request_id: u64,
}

impl InnerClient {
    fn new(connection: Nestls) -> Self {
        let (request_tx, request_rx) = mpsc::channel(128);
        let session_id = connection.session_id();
        tokio::spawn(Self::request_handler(connection, request_rx));
        Self {
            request_tx,
            session_id,
            request_id: 0,
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn request_handler(
        mut connection: Nestls,
        mut request_rx: mpsc::Receiver<(Bytes, oneshot::Sender<Response>)>,
    ) -> anyhow::Result<()> {
        // Unfortunately, currently the stream provided by OpenSSL doesn't allow splitting into
        // read/write halves, so the implementation to read/write concurrently is trickier.

        // Buffers incoming reads before they're parsed out into frames
        let mut incoming_buffer = BytesMut::new();

        // The bytes backing the incoming frame
        let mut incoming_frame_bytes;
        let mut incoming_frame: Option<&Frame> = None;

        let mut incoming_json: Option<Bytes> = None;
        let mut pending_responses = VecDeque::new();

        // TODO pop all the respond_to's  and send an error if needed
        let result = loop {
            tokio::select! {
                request = request_rx.recv() => {
                    if let Some((request, respond_to)) = request {
                        tracing::debug!("Request received");
                        connection.write_all(request.as_bytes()).await?;
                        pending_responses.push_back(respond_to);
                        continue;
                    } else {
                        tracing::debug!("Sending empty frame to signal the end of the connection.");
                        connection.write_all(Frame::empty().as_bytes()).await?;
                        break Ok::<_, anyhow::Error>(());
                    }
                }
                bytes_read = connection.read_buf(&mut incoming_buffer) => {
                    let bytes_read = bytes_read?;
                    tracing::trace!(bytes_read, "Handling incoming response data");
                }
            }

            let current_frame = match incoming_frame {
                // Need more bytes to do anything
                None if std::mem::size_of::<Frame>() > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the response frame");
                    continue;
                }
                None => {
                    incoming_frame_bytes = incoming_buffer
                        .split_to(std::mem::size_of::<Frame>())
                        .freeze();
                    let frame = Frame::try_ref_from_bytes(&incoming_frame_bytes)
                        .map_err(|e| anyhow::anyhow!(format!("{e:?}")))?;
                    incoming_frame = Some(frame);
                    tracing::debug!(
                        ?frame,
                        pending_responses = pending_responses.len(),
                        "Client received response frame from server"
                    );
                    frame
                }
                Some(frame) => frame,
            };

            let json_size: usize = current_frame.json_size.get().try_into()?;
            let binary_size: usize = current_frame.binary_size.get().try_into()?;

            match &incoming_json {
                None if json_size > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the JSON response");
                    continue;
                }
                None => {
                    let json = incoming_buffer.split_to(json_size).freeze();
                    if binary_size > incoming_buffer.len() {
                        tracing::debug!("Received JSON response; awaiting binary payload");
                        incoming_json = Some(json);
                    } else {
                        let respond_to = pending_responses
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("Unexpected response received!"))?;
                        // TODO include binary
                        let binary = incoming_buffer.split_to(binary_size).freeze();
                        let json_response: OuterResponse = serde_json::from_slice(&json)?;
                        tracing::debug!(
                            request_id = json_response.request_id,
                            "Full server response received"
                        );
                        let _ = respond_to.send(json_response.response);
                        incoming_frame = None;
                    }
                }
                Some(_) if binary_size > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the binary response");
                    continue;
                }
                Some(json) => {
                    let respond_to = pending_responses
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("Unexpected response received!"))?;
                    // TODO include binary
                    let binary = incoming_buffer.split_to(binary_size).freeze();
                    let json_response: OuterResponse = serde_json::from_slice(json)?;
                    tracing::debug!(
                        request_id = json_response.request_id,
                        "Full server response received"
                    );
                    let _ = respond_to.send(json_response.response);
                    incoming_json = None;
                    incoming_frame = None;
                }
            };
        };

        result
    }

    #[instrument(skip_all, fields(session_id = self.session_id.to_string()))]
    async fn send(&mut self, request: Request) -> Result<Receiver<Response>, ClientError> {
        let json = OuterRequest {
            session_id: self.session_id,
            request_id: self.request_id,
            request: request.message,
        };
        self.request_id += 1;
        let json = serde_json::to_string(&json)?;
        let json = Bytes::from_owner(json);
        let binary = request.binary.unwrap_or_default();
        let json_size: u64 = json
            .as_bytes()
            .len()
            .try_into()
            .context("JSON payload larger than a u64")?;
        let binary_size: u64 = binary
            .as_bytes()
            .len()
            .try_into()
            .context("Binary payload larger than a u64")?;
        let request_frame = protocol::Frame::new(json_size, binary_size);
        let mut payload =
            BytesMut::with_capacity(request_frame.as_bytes().len() + json.len() + binary.len());
        payload.put(request_frame.as_bytes());
        payload.put(json);
        payload.put(binary);
        let payload = payload.freeze();

        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send((payload, response_tx))
            .await
            .context("Couldn't send request to actor")?;
        Ok(response_rx)
    }
}
