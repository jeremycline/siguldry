// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    ConnectOptions, Pool, Sqlite,
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
    // Create the DB if it doesn't exist
    _ = SqliteConnectOptions::from_str(db_uri)
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(true)
        .connect()
        .await
        .context("Failed to create database")?;

    let pool = SqlitePoolOptions::new()
        .connect(db_uri)
        .await
        .context("Failed to connect to the database")?;
    MIGRATIONS
        .run(&pool)
        .await
        .context("Migrations could not be applied")?;

    Ok(pool)
}
