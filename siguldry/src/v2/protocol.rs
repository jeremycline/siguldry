// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The structures used in the Sigul protocol.
//!
//! All structures described in this documenation are to be sent in network byte order (big endian).
//!
//! ## Protocol Header
//!
//! Every connection to the bridge must begin with the protocol header, which announces the protocol
//! version to follow. The server may reject the request if the version is unknown or unsupported. A
//! server may support multiple versions, but must always use the version requested by the client if
//! it is supported.
//!
//! |--------------------------|
//! |      Protocol Header     |
//! |--------------------------|
//! | u64 | Magic number       |
//! | u32 | Protocol version   |
//! | u8  | Role               |
//! |--------------------------|
//!
//! If the bridge does not support the requested protocol, the connection is closed.
//!
//! The protocol version is increased whenever any of the following structures are changed. Thus,
//! all structures described below are specific to version 2 of the protocol.
//!
//! ## Inner TLS Session
//!
//! After the protocol header, the client starts a second TLS session within the first one. In
//! this session, the client must configure the TLS session to accept the Sigul server's hostname
//! and must present its client TLS certificate. All future communication occurs over this nested
//! TLS session.
//!
//! ## Frames
//!
//! Each message in the inner TLS session must start with a frame, which describes the
//! content type and size.
//!
//! |--------------------------|
//! |      Frame Header        |
//! |--------------------------|
//! | u64 | Frame size (bytes) |
//! | u8  | Content-Type       |
//! |--------------------------|
//!
//! The content type is represented as a u8; refer to [`ContentType`] for examples.  The frame size
//! is an unsigned 64 bit integer.

use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use tower::{
    retry::backoff::{Backoff, ExponentialBackoff, MakeBackoff},
    util::rng::HasherRng,
};
use zerocopy::{
    byteorder::network_endian::{U32, U64},
    Immutable, IntoBytes, KnownLayout, TryFromBytes,
};

use crate::v2::error::{ClientError, ConnectionError};

/// Magic number used in the protocol header.
pub const MAGIC: U64 = U64::from_bytes([83, 73, 71, 85, 76, 68, 82, 89]);
/// The Sigul wire protocol version this implementation supports
pub const PROTOCOL_VERSION: U32 = U32::new(2);

#[derive(IntoBytes, Immutable, KnownLayout, TryFromBytes, Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum ContentType {
    Json = 0,
    Binary = 1,
}

/// The possible roles a connection can have.
///
/// This is sent in the [`ProtocolHeader`]. The bridge listens on two separate ports for client
/// connections and server connections, but it is easy to misconfigure the client, server, or bridge
/// such that a client connects to the server port or vice versa. This header field exists to ensure
/// such misconfigurations are clearly reported by the bridge.
#[derive(IntoBytes, Immutable, KnownLayout, TryFromBytes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Clients should use this role in their protocol header.
    Client = 0,
    /// Server should use this role in their protocol header.
    Server = 1,
}

/// Every connection to the bridge begins with a protocol header to announce the version it expects
/// to use as well as the [`Role`] it intends to take.
#[derive(IntoBytes, Immutable, KnownLayout, TryFromBytes, Debug, Clone)]
pub(crate) struct ProtocolHeader {
    /// Each connection starts with a [`MAGIC`] number. While the version and role also have a fairly
    /// restricted set of valid values, this makes it even more likely a random incoming connection
    /// doesn't send a valid header so the bridge can hang up sooner. This isn't a security thing, just
    /// a "make it very likely you can log the right error" thing.
    magic: U64,
    /// The protocol version being requested by the connection; the current version is
    /// [`PROTOCOL_VERSION`].
    version: U32,
    /// The [`Role`] of this connection; the bridge should listen on entirely different ports and so it
    /// should know whether each connection is a client or a server. This exists primarily to help catch
    /// mis-configurations where the client or server connects to the other's port on the bridge.
    role: Role,
}

impl ProtocolHeader {
    /// Create a new protocol header for the given role.
    pub(crate) fn new(role: Role) -> Self {
        Self {
            magic: MAGIC,
            version: PROTOCOL_VERSION,
            role,
        }
    }

    pub(crate) async fn check<C: AsyncRead + Unpin>(
        conn: &mut C,
        expected_role: Role,
    ) -> Result<(), ConnectionError> {
        let mut header_buf = [0_u8; std::mem::size_of::<Self>()];
        conn.read_exact(&mut header_buf).await?;
        let header = Self::try_ref_from_bytes(&header_buf)?;

        if header.magic != MAGIC {
            Err(ConnectionError::ProtocolViolation(format!(
                "Protocol header magic number '{}' did not match expected '{MAGIC}'",
                header.magic
            )))
        } else if header.version != PROTOCOL_VERSION {
            Err(ConnectionError::ProtocolViolation(format!(
                "Protocol header version number '{}' did not match expected '{PROTOCOL_VERSION}'",
                header.version
            )))
        } else if header.role != expected_role {
            Err(ConnectionError::ProtocolViolation(format!(
                "Protocol header role '{:?}' did not match expected '{expected_role:?}'",
                header.role
            )))
        } else {
            tracing::debug!(header=?header, "Protocol header passed validation");
            Ok(())
        }
    }
}

impl From<Role> for ProtocolHeader {
    fn from(role: Role) -> Self {
        ProtocolHeader::new(role)
    }
}

/// Each client request or server response starts with a frame that declares the payload's content
/// type and size (in bytes).
///
/// TODO: if something like JSON doesn't work for all commands, we could do something where a
/// request/response is a list of frames so they can have mixed content types. But I think JSON will
/// be fine for everything, so let's keep it simple for now.
#[derive(IntoBytes, Immutable, KnownLayout, TryFromBytes, Debug, Clone)]
pub(crate) struct Frame {
    pub(crate) size: U64,
    pub(crate) content_type: ContentType,
}

impl Frame {
    /// Create a new frame.
    pub fn new(size: u64, content_type: ContentType) -> Self {
        Self {
            size: U64::new(size),
            content_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Hello {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Hello { user: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructResponse {
    command: String,
    response: Value,
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub user: String,
}
