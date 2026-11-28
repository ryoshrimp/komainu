//! PostgreSQL adapter for komainu.
//!
//! Implements the application's storage ports (`UnitOfWorkFactory`, `UnitOfWork` and the
//! repositories) on top of sqlx. Token identifiers are stored as SHA-256 hashes only; no
//! plaintext token is ever written.

mod access_token;
mod audit;
mod authorization_code;
mod authorization_request;
mod client;
mod codec;
mod consent;
mod error;
mod grant;
mod purge;
mod refresh_token;
mod session;
mod subject_mapping;
mod trusted_issuer;
mod uow;
mod used_assertion;
mod user;

use std::borrow::Cow;
use std::time::Duration;

use komainu_application::StoreError;
use komainu_domain::Secret;
use sqlx::PgPool;
use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::PgPoolOptions;

use crate::error::map_sqlx;

pub use crate::uow::PgUnitOfWorkFactory;

/// Connection settings for [`connect`].
#[derive(Debug)]
pub struct PgStoreConfig {
    /// Connection URL, for example `postgres://user:pass@host/db`.
    pub url: Secret<String>,
    /// Upper bound of pooled connections.
    pub max_connections: u32,
    /// How long to wait for a free connection.
    pub acquire_timeout: Duration,
}

impl PgStoreConfig {
    /// Settings with the default pool size (10) and acquire timeout (5 seconds).
    pub fn new(url: Secret<String>) -> Self {
        Self {
            url,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

/// Opens a connection pool. Does not run migrations; see [`migrate`].
pub async fn connect(config: &PgStoreConfig) -> Result<PgPool, StoreError> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect(config.url.expose_secret_ref())
        .await
        .map_err(map_sqlx)
}

/// Applies the embedded migrations. Safe to run repeatedly.
pub async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
    let init = Migration::new(
        1,
        Cow::Borrowed("init"),
        MigrationType::Simple,
        include_str!("../migrations/0001_init.sql").into_sql_str(),
        false,
    );
    let client_request = Migration::new(
        2,
        Cow::Borrowed("client_request_revocation"),
        MigrationType::Simple,
        include_str!("../migrations/0002_client_request_revocation.sql").into_sql_str(),
        false,
    );
    let pkce = Migration::new(
        3,
        Cow::Borrowed("pkce"),
        MigrationType::Simple,
        include_str!("../migrations/0003_pkce.sql").into_sql_str(),
        false,
    );
    let assertion = Migration::new(
        4,
        Cow::Borrowed("assertion"),
        MigrationType::Simple,
        include_str!("../migrations/0004_assertion.sql").into_sql_str(),
        false,
    );
    Migrator::with_migrations(vec![init, client_request, pkce, assertion])
        .run(pool)
        .await
        .map_err(|e| StoreError::Other(format!("migration failed: {e}")))
}
