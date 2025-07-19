// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Tower service implementing the basic siguldry client.
use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc, task::Poll, time::Duration};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
    time::Instant,
};
use tower::{
    retry::backoff::{Backoff, ExponentialBackoff, MakeBackoff},
    util::rng::HasherRng,
    Service,
};
use tracing::{instrument, Instrument};
use uuid::Uuid;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    client::{ConnectionConfig, Req},
    error::ClientError,
    nestls::Nestls,
    protocol::{
        self,
        json::{OuterRequest, OuterResponse, Response},
        Frame, Role,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct MakeClientService {
    config: Arc<Mutex<ConnectionConfig>>,
    last_connection: Option<Instant>,
}

impl MakeClientService {
    pub(crate) fn new(config: ConnectionConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            last_connection: None,
        }
    }
}

impl<R> Service<R> for MakeClientService {
    type Response = tower::retry::Retry<RetryPolicy, tower::timeout::Timeout<ClientService>>;
    type Error = ClientError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: R) -> Self::Future {
        let conn_info = self.config.clone();
        let last_connection_time = self.last_connection;
        let interval = Duration::from_secs(1);
        self.last_connection = Some(Instant::now());
        let fut = async move {
            if let Some(last_connection_time) = last_connection_time {
                let duration_since = Instant::now() - last_connection_time;
                tokio::time::sleep(interval.saturating_sub(duration_since)).await;
            }
            tracing::debug!("Creating new service connection");
            let conn_info = conn_info.lock().await;
            let conn = Nestls::builder(
                conn_info
                    .tls_config
                    .ssl(&conn_info.bridge_hostname)
                    .unwrap(),
                Role::Client,
            )
            .connect(
                &conn_info.bridge_address,
                conn_info
                    .tls_config
                    .ssl(&conn_info.server_hostname)
                    .unwrap(),
            )
            .await?;

            let policy = RetryPolicy::new();
            let client = tower::ServiceBuilder::new()
                .retry(policy)
                .timeout(Duration::from_secs(30))
                .service(ClientService::new(conn));
            tracing::info!("new client service created");
            Ok(client)
        };
        Box::pin(fut)
    }
}

#[derive(Clone)]
pub(crate) struct ClientService {
    request_tx: mpsc::Sender<(Frame, Bytes, oneshot::Sender<Response>)>,
    connection_actor: Arc<JoinHandle<Result<(), ClientError>>>,
    session_id: Uuid,
    request_id: u64,
}

impl ClientService {
    fn new(connection: Nestls) -> Self {
        let (request_tx, request_rx) = mpsc::channel(128);
        let session_id = connection.session_id();
        let connection_actor =
            Arc::new(tokio::spawn(Self::request_handler(connection, request_rx)));
        Self {
            request_tx,
            connection_actor,
            session_id,
            request_id: 0,
        }
    }

    async fn request_handler(
        mut connection: Nestls,
        mut request_rx: mpsc::Receiver<(Frame, Bytes, oneshot::Sender<Response>)>,
    ) -> Result<(), ClientError> {
        // TODO split in read/write half and select
        while let Some((request_frame, request, respond_to)) = request_rx.recv().await {
            tracing::info!("Request received");
            connection.write_all(request_frame.as_bytes()).await?;
            connection.write_all(request.as_bytes()).await?;

            let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
            connection.read_exact(&mut frame_buffer).await?;
            let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer).unwrap();
            tracing::info!(?frame, "New frame received");

            let json_size: usize = frame.json_size.get().try_into().unwrap();
            let binary_size: usize = frame.binary_size.get().try_into().unwrap();
            let frame_size = json_size + binary_size;
            let mut response_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
            while response_buffer.remaining_mut() != 0 {
                connection.read_buf(&mut response_buffer).await?;
            }

            let mut response_bytes = response_buffer.into_inner().freeze();
            let binary_bytes = response_bytes.split_off(json_size);
            let json_response: OuterResponse = serde_json::from_slice(&response_bytes).unwrap();
            respond_to.send(json_response.response).unwrap();
        }

        Ok(())
    }
}

impl Service<Req> for ClientService {
    type Response = Response;
    type Error = ClientError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.connection_actor.is_finished() {
            // The actor should only exit if the connection failed
            Poll::Ready(Err(ClientError::Fatal(anyhow::anyhow!("placeholder"))))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    #[instrument(skip_all, fields(session_id = self.session_id.to_string()))]
    fn call(&mut self, request: Req) -> Self::Future {
        let json = OuterRequest {
            session_id: self.session_id,
            request_id: self.request_id,
            request: request.message,
        };
        self.request_id += 1;
        let json = serde_json::to_string(&json).unwrap();
        let json = Bytes::from_owner(json);
        let binary = request.binary.unwrap_or_else(|| bytes::Bytes::new());
        let request_frame = protocol::Frame::new(
            json.as_bytes().len().try_into().unwrap(),
            binary.as_bytes().len().try_into().unwrap(),
        );
        let mut request = BytesMut::from(json);
        request.put(binary);
        let request = request.freeze();

        let (response_tx, response_rx) = oneshot::channel();
        let request_tx = self.request_tx.clone();

        let fut = async move {
            request_tx
                .send((request_frame, request, response_tx))
                .await
                .context("Couldn't send request to actor")?;
            let response = response_rx.await.context("Actor channel didn't respond")?;
            Ok(response)
        }
        .instrument(tracing::Span::current());

        Box::pin(fut)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RetryPolicy {
    attempts: usize,
    backoff: ExponentialBackoff,
}

impl RetryPolicy {
    fn new() -> Self {
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

impl tower::retry::Policy<Req, Response, tower::BoxError> for RetryPolicy {
    type Future = <ExponentialBackoff as Backoff>::Future;

    fn retry(
        &mut self,
        _req: &mut Req,
        result: &mut Result<Response, tower::BoxError>,
    ) -> Option<Self::Future> {
        match result {
            Ok(_) => None,
            //Err(ClientError::Fatal(error)) => {
            //    tracing::error!(?error, "fatal error, not retrying");
            //    None
            //}
            Err(error) => {
                // TODO sort through errors to retry vs not
                if self.attempts > 3 {
                    return None;
                }
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

    fn clone_request(&mut self, req: &Req) -> Option<Req> {
        Some(req.clone())
    }
}
