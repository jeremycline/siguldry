// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.

use crate::v2::config::Credentials;

mod api;
mod service;

pub use api::Client;
use serde::{Deserialize, Serialize};

/// Configuration for the siguldry client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_hostname: String,
    pub bridge_hostname: String,
    pub bridge_port: u16,
    pub credentials: Credentials,
}
