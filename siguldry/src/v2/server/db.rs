// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::str::FromStr;

use anyhow::Context;
use sqlx::{sqlite::SqliteConnectOptions, Pool, Sqlite, SqliteConnection, SqlitePool};
use tracing::instrument;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/");

/// Ensure the database is migrated to the latest version.
///
/// # Example
///
/// ```rust,no_run
/// let db = pool("sqlite::memory:")?;
/// migrate(&db).await?;
/// ```
#[instrument]
pub(crate) async fn migrate(pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    MIGRATIONS
        .run(pool)
        .await
        .context("Migrations could not be applied")?;
    Ok(())
}

pub(crate) async fn pool(db_uri: &str) -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::from_str(db_uri)
        .context("The database URL couldn't be parsed.")?
        .create_if_missing(true)
        .foreign_keys(true)
        .optimize_on_close(true, Some(400));
    SqlitePool::connect_with(opts)
        .await
        .context("Failed to connect to the database")
}

#[derive(Debug, Clone)]
pub struct User {
    pub(crate) id: i64,
    pub name: String,
    pub admin: bool,
}

impl User {
    #[instrument(skip(conn))]
    pub async fn get(conn: &mut SqliteConnection, name: &str) -> Result<User, sqlx::Error> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE users.name = ?;", name)
            .fetch_one(&mut *conn)
            .await
    }

    #[instrument(skip(conn))]
    pub async fn create(
        conn: &mut SqliteConnection,
        name: &str,
        admin: bool,
    ) -> Result<User, sqlx::Error> {
        sqlx::query!(
            "INSERT INTO users (name, admin) VALUES (?, ?) RETURNING id",
            name,
            admin
        )
        .fetch_one(&mut *conn)
        .await
        .map(|record| User {
            id: record.id,
            name: name.to_string(),
            admin,
        })
    }

    #[instrument(skip(conn))]
    pub async fn delete(conn: &mut SqliteConnection, name: &str) -> Result<u64, sqlx::Error> {
        sqlx::query!("DELETE FROM users WHERE name = $1", name)
            .execute(&mut *conn)
            .await
            .map(|result| result.rows_affected())
    }

    #[instrument(skip(conn))]
    pub async fn update(&self, conn: &mut SqliteConnection) -> Result<u64, sqlx::Error> {
        sqlx::query!(
            "UPDATE users SET admin = $1 WHERE id = $2",
            self.admin,
            self.id
        )
        .execute(&mut *conn)
        .await
        .map(|result| result.rows_affected())
    }
}
