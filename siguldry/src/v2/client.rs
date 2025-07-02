// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module provides a Sigul client.

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};
use tracing::instrument;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    error::{ClientError as Error, ConnectionError},
    nestls::{Nestls, NestlsBuilder},
    protocol::{self, Hello, ProtocolHeader, Request, Response, Role},
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

    #[instrument(skip_all)]
    async fn send(&self, request: Request) -> Result<Response, Error> {
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
    pub async fn hello(&self) -> Result<Hello, Error> {
        let response = self.send(Request::Hello {  }).await?;
        match response {
            Response::Hello { user } => Ok(Hello {user}),
        }
    }
}
