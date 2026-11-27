//! Maps the configuration onto the settings of each crate and builds the services.

use std::net::SocketAddr;
use std::time::Duration;

use komainu::Komainu;
use komainu::adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory};
use komainu::adapter_std::{OsSecureRandom, SystemClock};
use komainu::application::{ApplicationConfig, RequestContext, ScopeDefinition, new_uuid_v7};
use komainu::domain::ScopeToken;
use komainu::http::{ContentSecurityPolicy, HttpConfig};

use crate::config::{CleanupConfig, Config, LogConfig};

/// Request body limit of the form endpoints (server.md: fixed, not configurable).
const MAX_BODY_BYTES: usize = 16 * 1024;

/// A validated [`Config`] split into the settings each part needs.
pub struct Settings {
    pub pg: PgStoreConfig,
    pub application: ApplicationConfig,
    pub http: HttpConfig,
    pub listen: SocketAddr,
    pub ops_listen: SocketAddr,
    pub shutdown_timeout: Duration,
    pub cleanup: CleanupConfig,
    pub log: LogConfig,
}

fn secs(value: u64) -> time::Duration {
    time::Duration::seconds(i64::try_from(value).unwrap_or(i64::MAX))
}

impl Settings {
    /// Takes the configuration by value so that `database.url` is moved, not copied.
    ///
    /// The scope names and descriptions must have passed `config::validate`.
    pub fn from_config(config: Config) -> anyhow::Result<Self> {
        let Config {
            server,
            ops,
            database,
            session,
            oauth,
            clients,
            scopes,
            cleanup,
            log,
        } = config;
        let scopes = scopes
            .into_iter()
            .map(|scope| {
                Ok(ScopeDefinition {
                    name: ScopeToken::try_new(scope.name)?,
                    description: scope.description,
                })
            })
            .collect::<Result<Vec<_>, komainu::domain::DomainError>>()?;
        let application = ApplicationConfig::default()
            .with_authorization_code_ttl(secs(oauth.authorization_code_ttl_secs))
            .with_access_token_ttl(secs(oauth.access_token_ttl_secs))
            .with_refresh_token_ttl(secs(oauth.refresh_token_ttl_secs))
            .with_authorization_request_ttl(secs(oauth.authorization_request_ttl_secs))
            .with_login_session_ttl(secs(session.ttl_secs))
            .with_require_state(oauth.require_state)
            .with_allow_public_clients(clients.allow_public)
            .with_scopes(scopes)
            .with_purge_grace(secs(cleanup.grace_secs))
            .with_audit_retention(time::Duration::days(
                i64::try_from(cleanup.audit_retention_days).unwrap_or(i64::MAX),
            ));
        let http = if server.allow_insecure_http {
            HttpConfig::new_insecure(&server.public_base_url)
        } else {
            HttpConfig::new(&server.public_base_url)
        }
        .map_err(|e| anyhow::anyhow!("server.public_base_url: {e}"))?
        .with_cookie_secure(session.cookie_secure)
        .with_max_body_bytes(MAX_BODY_BYTES)
        .with_csrf_cookie_ttl(application.authorization_request_ttl);
        let http = match &server.content_security_policy {
            Some(policy) => http.with_content_security_policy(
                ContentSecurityPolicy::custom(policy)
                    .map_err(|e| anyhow::anyhow!("server.content_security_policy: {e}"))?,
            ),
            None => http,
        };
        // The issuer is the normalized public base URL; it enables private_key_jwt.
        let application = application.with_issuer(http.public_base_url());
        let pg = PgStoreConfig {
            url: database.url,
            max_connections: database.max_connections,
            acquire_timeout: Duration::from_secs(database.acquire_timeout_secs),
        };
        Ok(Self {
            pg,
            application,
            http,
            listen: server.listen,
            ops_listen: ops.listen,
            shutdown_timeout: Duration::from_secs(server.shutdown_timeout_secs),
            cleanup,
            log,
        })
    }
}

/// The authorization server built on one store.
pub struct Services {
    pub komainu: Komainu,
}

/// Wires the production adapters (`SystemClock`, `OsSecureRandom`, Argon2id and the built-in
/// authenticator) around `store`.
pub fn services(
    store: PgUnitOfWorkFactory,
    application: ApplicationConfig,
    http: HttpConfig,
) -> anyhow::Result<Services> {
    let komainu = Komainu::builder()
        .store(store)
        .application_config(application)
        .http_config(http)
        .build()?;
    Ok(Services { komainu })
}

/// A context for work that is not an HTTP request (CLI and jobs): fresh UUIDv7 request id,
/// no client address.
pub fn background_context() -> RequestContext {
    RequestContext {
        request_id: new_uuid_v7(&SystemClock, &OsSecureRandom).to_string(),
        client_ip: None,
    }
}
