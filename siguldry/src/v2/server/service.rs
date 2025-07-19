// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A sigul server.

use anyhow::Context;
use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{instrument, Instrument};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::v2::{
    error::ClientError as Error,
    nestls::Nestls,
    protocol::{
        self,
        json::{Request, Response},
        Role,
    },
    server::handlers,
    tls,
};

/// A sigul client.
#[derive(Debug)]
pub struct Server<S: ToSocketAddrs + std::fmt::Debug> {
    tls_config: tls::ClientConfig,
    server_tls_config: tls::ServerConfig,
    bridge_address: S,
    bridge_hostname: String,
    halt_token: CancellationToken,
}

impl<S: ToSocketAddrs + std::fmt::Debug> Server<S> {
    /// Create a new server.
    pub fn new(
        tls_config: tls::ClientConfig,
        server_tls_config: tls::ServerConfig,
        bridge_address: S,
        bridge_hostname: String,
        halt_token: CancellationToken,
    ) -> Self {
        Self {
            tls_config,
            server_tls_config,
            bridge_address,
            bridge_hostname,
            halt_token,
        }
    }

    /// Run the server.
    #[instrument(skip_all, name = "server")]
    pub async fn run(self) {
        let request_tracker = TaskTracker::new();

        'accept: loop {
            tokio::select! {
                _ = self.halt_token.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break 'accept;
                },
                conn = self.accept() => {
                    match conn {
                        Ok(conn) => {
                            tracing::info!("New request accepted");
                            request_tracker.spawn(handle(conn).instrument(tracing::Span::current()));
                        },
                        Err(error) => tracing::error!(?error, "Failed to accept incoming client connection"),
                    }
                },
            }
        }
    }

    async fn accept(&self) -> Result<Nestls, Error> {
        let conn = Nestls::builder(self.tls_config.ssl(&self.bridge_hostname)?, Role::Server)
            .accept(&self.bridge_address, self.server_tls_config.clone())
            .await?;

        Ok(conn)
    }
}

#[instrument(skip_all, fields(session_id = conn.session_id().to_string(), client = conn.peer_common_name()))]
async fn handle(mut conn: Nestls) -> Result<(), anyhow::Error> {
    // Read request frame
    // parse request
    // dispatch to handler
    // TODO test out this flow with tower
    let user = conn
        .peer_common_name()
        .ok_or(protocol::Error::MissingCommonName)?;

    loop {
        let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
        conn.read_exact(&mut frame_buffer).await?;
        let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer)
            .map_err(|e| protocol::Error::Framing(format!("Invalid frame: {:?}", e)))?;
        tracing::debug!(?frame, "New request frame received");

        let json_size: usize = frame
            .json_size
            .get()
            .try_into()
            .context("frame size must fit in usize")?;
        let binary_size: usize = frame
            .binary_size
            .get()
            .try_into()
            .context("frame size must fit in usize")?;
        let frame_size = json_size + binary_size;
        let mut request_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
        while request_buffer.remaining_mut() != 0 {
            conn.read_buf(&mut request_buffer).await?;
        }
        let mut request_bytes = request_buffer.into_inner().freeze();

        let binary_bytes = request_bytes.split_off(json_size);
        let outer_request: protocol::json::OuterRequest = serde_json::from_slice(&request_bytes)
            .context("The request's JSON could not be deserialized")?;
        let response = match outer_request.request {
            Request::WhoAmI {} => handlers::who_am_i(user.clone()).await,
            Request::NewUser { username } => todo!(),
        };

        match response {
            Ok(response) => {
                let json_response = protocol::json::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response: response.json,
                };
                let json_response = serde_json::to_string(&json_response)?;
                let binary_size = response.binary.as_ref().map(|b| b.len()).unwrap_or(0);

                let response_frame = protocol::Frame::new(
                    json_response.as_bytes().len().try_into()?,
                    binary_size.try_into()?,
                );
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
                if let Some(binary) = &response.binary {
                    conn.write_all(binary).await?;
                }
            }
            Err(reason) => {
                //let json = serde_json::to_string(protocol::json::)
                let json_response = protocol::json::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response: protocol::json::Response::Error { reason },
                };
                let json_response = serde_json::to_string(&json_response)?;
                let response_frame =
                    protocol::Frame::new(json_response.as_bytes().len().try_into()?, 0);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
            }
        }
    }

    Ok(())
}
