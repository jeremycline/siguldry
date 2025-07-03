// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

use std::{future::Future, pin::Pin, sync::Arc, task::Poll, time::Duration};

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};
use tower::{
    retry::backoff::{Backoff, ExponentialBackoff, MakeBackoff},
    util::rng::HasherRng,
    MakeService, Service,
};
use tracing::instrument;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    error::{ClientError, ConnectionError},
    nestls::{Nestls, NestlsBuilder},
    protocol::{self, Hello, ProtocolHeader, Request, Response, Role},
    tls,
};

/// A sigul client.
#[derive(Debug)]
pub struct Client {
    tls_config: tls::ClientConfig,
    bridge_address: String,
    bridge_hostname: String,
    server_hostname: String,
}

impl Client {
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

    async fn connect(&self) -> Result<Nestls, ConnectionError> {
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

    #[instrument(skip_all)]
    async fn send(&self, request: Request) -> Result<Response, ClientError> {
        let mut connection = self.connect().await?;

        let request = serde_json::to_string(&request).unwrap();
        let request_frame = protocol::Frame::new(
            request.as_bytes().len().try_into().unwrap(),
            protocol::ContentType::Json,
        );
        connection.write_all(request_frame.as_bytes()).await?;
        connection.write_all(request.as_bytes()).await?;

        let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
        connection.read_exact(&mut frame_buffer).await?;
        let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer).unwrap();
        tracing::info!(?frame, "New frame received");

        let frame_size: usize = frame.size.get().try_into().unwrap();
        let mut response_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
        while response_buffer.remaining_mut() != 0 {
            connection.read_buf(&mut response_buffer).await?;
        }

        let response_bytes = response_buffer.into_inner().freeze();
        match frame.content_type {
            protocol::ContentType::Json => {
                let response: Response = serde_json::from_slice(&response_bytes).unwrap();
                Ok(response)
            }
            protocol::ContentType::Binary => todo!(),
        }
    }

    // TODO not an enum, that's wonky
    pub async fn hello(&self) -> Result<Hello, ClientError> {
        let response = self.send(Request::Hello {}).await?;
        match response {
            Response::Hello { user } => Ok(Hello { user }),
        }
    }
}

#[derive(Debug)]
struct ConnectionInfo {
    tls_config: tls::ClientConfig,
    bridge_address: String,
    bridge_hostname: String,
    server_hostname: String,
}

#[derive(Debug, Clone)]
pub struct ClientService {
    connection_info: Arc<ConnectionInfo>,
}

impl ClientService {
    pub fn new(
        tls_config: tls::ClientConfig,
        bridge_address: String,
        bridge_hostname: String,
        server_hostname: String,
    ) -> Self {
        let connection_info = Arc::new(ConnectionInfo {
            tls_config,
            bridge_address,
            bridge_hostname,
            server_hostname,
        });
        Self { connection_info }
    }

    pub async fn hello(&mut self) -> Result<Hello, ClientError> {
        let response = self.call(Request::Hello {}).await?;
        match response {
            Response::Hello { user } => Ok(Hello { user }),
        }
    }
}

impl Service<Request> for ClientService {
    type Response = Response;
    type Error = ClientError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let request = serde_json::to_string(&request).unwrap();
        let request_frame = protocol::Frame::new(
            request.as_bytes().len().try_into().unwrap(),
            protocol::ContentType::Json,
        );
        let conn_info = self.connection_info.clone();

        let fut = async move {
            let bridge_payload: ProtocolHeader = Role::Client.into();
            let mut connection =
                NestlsBuilder::new(conn_info.tls_config.ssl(&conn_info.bridge_hostname)?)
                    .with_bridge_payload(bytes::Bytes::copy_from_slice(bridge_payload.as_bytes()))
                    .connect(
                        &conn_info.bridge_address,
                        conn_info.tls_config.ssl(&conn_info.server_hostname)?,
                    )
                    .await?;

            connection.write_all(request_frame.as_bytes()).await?;
            connection.write_all(request.as_bytes()).await?;

            let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
            connection.read_exact(&mut frame_buffer).await?;
            let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer).unwrap();
            tracing::info!(?frame, "New frame received");

            let frame_size: usize = frame.size.get().try_into().unwrap();
            let mut response_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
            while response_buffer.remaining_mut() != 0 {
                connection.read_buf(&mut response_buffer).await?;
            }

            let response_bytes = response_buffer.into_inner().freeze();
            match frame.content_type {
                protocol::ContentType::Json => {
                    let response: Response = serde_json::from_slice(&response_bytes).unwrap();
                    Ok(response)
                }
                protocol::ContentType::Binary => todo!(),
            }
        };

        Box::pin(fut)
    }
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    attempts: usize,
    backoff: ExponentialBackoff,
}

impl RetryPolicy {
    pub fn new() -> Self {
        let backoff = tower::retry::backoff::ExponentialBackoffMaker::new(
            Duration::from_millis(500),
            Duration::from_secs(3),
            50.0,
            HasherRng::new(),
        )
        .unwrap()
        .make_backoff();
        Self {
            attempts: 0,
            backoff,
        }
    }
}

impl<ClientError> tower::retry::Policy<Request, Response, ClientError> for RetryPolicy {
    type Future = <ExponentialBackoff as Backoff>::Future;

    fn retry(
        &mut self,
        req: &mut Request,
        result: &mut Result<Response, ClientError>,
    ) -> Option<Self::Future> {
        match result {
            Ok(_) => None,
            Err(error) => {
                // TODO sort through errors to retry vs not
                self.attempts += 1;
                let backoff = self.backoff.next_backoff();
                let retry_in = backoff
                    .deadline()
                    .saturating_duration_since(tokio::time::Instant::now());
                tracing::info!(?retry_in, attempt = self.attempts, "Retrying request");
                Some(self.backoff.next_backoff())
            }
        }
    }

    fn clone_request(&mut self, req: &Request) -> Option<Request> {
        Some(req.clone())
    }
}
