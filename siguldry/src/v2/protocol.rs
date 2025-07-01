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
//! | u32 | Content-Type       |
//! | u64 | Frame size (bytes) |
//! |--------------------------|
//!
//! The content type is represented as a u32; refer to [`ContentType`] for examples.  The frame size
//! is an unsigned 64 bit integer.

use zerocopy::{Immutable, IntoBytes, KnownLayout};

/// Magic number used in the protocol header.
pub const MAGIC: u64 = u64::from_le_bytes([83, 73, 71, 85, 76, 68, 82, 89]);
/// The Sigul wire protocol version this implementation supports
pub const PROTOCOL_VERSION: u32 = 2;

enum ContentType {
    Json,
    Binary,
}

/// The possible roles a connection can have.
///
/// This is sent in the [`ProtocolHeader`]. The bridge listens on two separate ports for client
/// connections and server connections, but it is easy to misconfigure the client, server, or bridge
/// such that a client connects to the server port or vice versa. This header field exists to ensure
/// such misconfigurations are clearly reported by the bridge.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    /// Clients should use this role in their protocol header.
    Client,
    /// Server should use this role in their protocol header.
    Server,
}

/// Every connection to the bridge begins with a protocol header to announce the version it expects
/// to use as well as the [`Role`] it intends to take.
#[derive(IntoBytes, Immutable, KnownLayout, Debug, Clone)]
pub struct ProtocolHeader {
    /// Each connection starts with a [`MAGIC`] number. While the version and role also have a fairly
    /// restricted set of valid values, this makes it even more likely a random incoming connection
    /// doesn't send a valid header so the bridge can hang up sooner. This isn't a security thing, just
    /// a "make it very likely you can log the right error" thing.
    magic: [u8; 8],
    /// The protocol version being requested by the connection; the current version is
    /// [`PROTOCOL_VERSION`].
    version: [u8; 4],
    /// The [`Role`] of this connection; the bridge should listen on entirely different ports and so it
    /// should know whether each connection is a client or a server. This exists primarily to help catch
    /// mis-configurations where the client or server connects to the other's port on the bridge.
    role: u8,
}

impl TryFrom<&[u8]> for ProtocolHeader {
    type Error = crate::v2::error::ClientError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<Role> for ProtocolHeader {
    fn from(value: Role) -> Self {
        Self {
            magic: MAGIC.to_be_bytes(),
            version: PROTOCOL_VERSION.to_be_bytes(),
            role: match value {
                Role::Client => 0_u8,
                Role::Server => 1_u8,
            },
        }
    }
}

/// Each client request or server response starts with a frame that declares the payload's content
/// type and size (in bytes).
///
/// TODO: if something like JSON doesn't work for all commands, we could do something where a
/// request/response is a list of frames so they can have mixed content types. But I think JSON will
/// be fine for everything, so let's keep it simple for now.
struct Frame {
    content_type: ContentType,
    size: u64,
}
