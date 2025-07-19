// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use crate::v2::protocol::{json, ServerError};

pub(super) struct Response {
    pub(super) json: json::Response,
    pub(super) binary: Option<bytes::Bytes>,
}

impl From<json::Response> for Response {
    fn from(json: json::Response) -> Self {
        Self { json, binary: None }
    }
}

impl Response {
    fn with_binary(&mut self, bytes: bytes::Bytes) {
        self.binary = Some(bytes);
    }
}

pub(crate) async fn who_am_i(user: String) -> Result<Response, ServerError> {
    Ok(json::Response::WhoAmI { user }.into())
}
