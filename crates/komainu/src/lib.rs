//! An embeddable OAuth 2.0 authorization server.
//!
//! `komainu` re-exports the komainu crates behind features and provides
//! [`KomainuBuilder`], which wires a store, an authenticator and the browser screens into
//! a [`Komainu`]: the use case services and an axum `Router`.
//!
//! # Features
//!
//! | Feature | Enables |
//! |---|---|
//! | `std` (default) | [`adapter_std`]: system clock, OS randomness, Argon2id hasher; builder defaults |
//! | `postgres` (default) | [`adapter_postgres`]: the PostgreSQL store |
//! | `http` (default) | [`http`]: the axum router and the screens; [`Komainu::router`] |
//!
//! The router is built for axum 0.8; add `axum = "0.8"` to your own dependencies to merge or
//! nest it. komainu does not re-export axum.
//!
//! # Signing keys
//!
//! When `ApplicationConfig::signing` is set, give the builder a [`KeySealer`] with
//! [`KomainuBuilder::key_sealer`]. The router then serves `GET /jwks` and the metadata has a
//! `jwks_uri`. `build` creates no keys: call `rotate_due` at startup and periodically, for
//! example every hour.
//!
//! ```no_run
//! # async fn rotate(komainu: &komainu::Komainu) -> Result<(), Box<dyn std::error::Error>> {
//! use komainu::application::RequestContext;
//!
//! if let Some(signing_keys) = komainu.signing_keys() {
//!     let ctx = RequestContext { request_id: "rotation".to_owned(), client_ip: None };
//!     let report = signing_keys.rotate_due(&ctx).await?;
//! # let _ = report;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(all(feature = "http", feature = "postgres", feature = "std"))]
//! # mod demo {
//! use komainu::adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
//! use komainu::domain::Secret;
//! use komainu::http::HttpConfig;
//! use komainu::Komainu;
//!
//! # pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PgStoreConfig::new(Secret::new(std::env::var("DATABASE_URL")?));
//! let pool = connect(&config).await?;
//! migrate(&pool).await?;
//! let komainu = Komainu::builder()
//!     .store(PgUnitOfWorkFactory::new(pool))
//!     .http_config(HttpConfig::new("https://auth.example.com")?)
//!     .build()?;
//! let router = komainu.router();
//! # let _ = router;
//! # Ok(())
//! # }
//! # }
//! ```

mod builder;

pub use komainu_application as application;
pub use komainu_domain as domain;

#[cfg(feature = "std")]
pub use komainu_adapter_std as adapter_std;

#[cfg(feature = "postgres")]
pub use komainu_adapter_postgres as adapter_postgres;

#[cfg(feature = "jwks-uri")]
pub use komainu_adapter_http as adapter_http;

#[cfg(feature = "http")]
pub use komainu_http as http;

pub use komainu_application::{
    ApplicationConfigError, KeySealer, RevokeOutcome, RotationReport, SealError, SigningConfig,
    SigningConfigError, SigningKeyError, SigningKeyService, SigningKeySummary,
};
pub use komainu_domain::{SigningAlgorithm, SigningPolicy};

#[cfg(feature = "std")]
pub use komainu_adapter_std::AesGcmKeySealer;

pub use builder::{BuildError, Komainu, KomainuBuilder};
