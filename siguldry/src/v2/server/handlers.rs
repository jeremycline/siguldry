// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use sqlx::SqliteConnection;

use crate::v2::{
    protocol::{json, Response, ServerError},
    server::db::{self, User},
};

pub(crate) async fn who_am_i(user: &User) -> Result<Response, ServerError> {
    Ok(json::Response::WhoAmI {
        user: user.name.clone(),
    }
    .into())
}
