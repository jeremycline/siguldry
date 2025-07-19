// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Sqlite, SqliteConnection, SqlitePool,
};
use tracing::instrument;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/");

/// Ensure the database is migrated to the latest version.
///
/// # Example
///
/// ```rust,no_run
/// let pool = migrate("sqlite::memory:").await?;
/// ```
#[instrument]
pub(crate) async fn migrate(db_uri: &str) -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::from_str(db_uri)
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(true)
        .foreign_keys(true)
        .optimize_on_close(true, Some(400));
    let pool = SqlitePool::connect_with(opts).await?;

    MIGRATIONS
        .run(&pool)
        .await
        .context("Migrations could not be applied")?;

    Ok(pool)
}

#[derive(Debug, Clone)]
pub struct User {
    id: i64,
    name: String,
    admin: bool,
}

pub async fn get_user(conn: &mut SqliteConnection, name: &str) -> anyhow::Result<User> {
    Ok(sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE users.name = ?;
        "#,
        name
    )
    .fetch_one(&mut *conn)
    .await
    .context("Failed to find user")?)
}
