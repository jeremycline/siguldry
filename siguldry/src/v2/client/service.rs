// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Tower service implementing the basic siguldry client.
use std::sync::Arc;

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::instrument;
use uuid::Uuid;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    error::ClientError,
    nestls::Nestls,
    protocol::{
        self,
        json::{OuterRequest, OuterResponse, Response},
        Frame, Request,
    },
};

#[derive(Clone, Debug)]
pub(crate) struct ClientService {
    request_tx: mpsc::Sender<(Frame, Bytes, oneshot::Sender<Response>)>,
    connection_actor: Arc<JoinHandle<Result<(), ClientError>>>,
    session_id: Uuid,
    request_id: u64,
}

impl ClientService {
    pub(crate) fn new(connection: Nestls) -> Self {
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
            let _binary_bytes = response_bytes.split_off(json_size);
            let json_response: OuterResponse = serde_json::from_slice(&response_bytes).unwrap();
            respond_to.send(json_response.response).unwrap();
        }

        tracing::debug!("Sending empty frame to signal the end of the connection.");
        connection.write_all(Frame::empty().as_bytes()).await?;

        Ok(())
    }

    #[instrument(skip_all, fields(session_id = self.session_id.to_string()))]
    pub(crate) async fn call(&mut self, request: Request) -> Result<Response, ClientError> {
        let json = OuterRequest {
            session_id: self.session_id,
            request_id: self.request_id,
            request: request.message,
        };
        self.request_id += 1;
        let json = serde_json::to_string(&json).unwrap();
        let json = Bytes::from_owner(json);
        let binary = request.binary.unwrap_or_default();
        let request_frame = protocol::Frame::new(
            json.as_bytes().len().try_into().unwrap(),
            binary.as_bytes().len().try_into().unwrap(),
        );
        let mut request = BytesMut::from(json);
        request.put(binary);
        let request = request.freeze();

        let (response_tx, response_rx) = oneshot::channel();
        let request_tx = self.request_tx.clone();

        request_tx
            .send((request_frame, request, response_tx))
            .await
            .context("Couldn't send request to actor")?;
        let response = response_rx.await.context("Actor channel didn't respond")?;
        Ok(response)
    }
}
