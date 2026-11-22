//! Maps the configuration onto the settings of each crate and builds the services.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use komainu_adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory};
use komainu_adapter_std::{Argon2PasswordHasher, OsSecureRandom, SystemClock};
use komainu_application::{
    AdminService, ApplicationConfig, AuthorizationService, BuiltinAuthenticator, Dependencies,
    MaintenanceService, RequestContext, ScopeDefinition, TokenService, new_uuid_v7,
};
use komainu_domain::ScopeToken;
use komainu_http::{AppState, HttpConfig};

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
            .collect::<Result<Vec<_>, komainu_domain::DomainError>>()?;
        let application = ApplicationConfig {
            authorization_code_ttl: secs(oauth.authorization_code_ttl_secs),
            access_token_ttl: secs(oauth.access_token_ttl_secs),
            refresh_token_ttl: secs(oauth.refresh_token_ttl_secs),
            authorization_request_ttl: secs(oauth.authorization_request_ttl_secs),
            login_session_ttl: secs(session.ttl_secs),
            require_state: oauth.require_state,
            allow_public_clients: clients.allow_public,
            scopes,
            purge_grace: secs(cleanup.grace_secs),
            audit_retention: time::Duration::days(
                i64::try_from(cleanup.audit_retention_days).unwrap_or(i64::MAX),
            ),
        };
        let http = HttpConfig {
            public_base_url: server.public_base_url,
            cookie_secure: session.cookie_secure,
            max_body_bytes: MAX_BODY_BYTES,
            csrf_cookie_ttl: application.authorization_request_ttl,
        };
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

/// The use-case services built on one store.
pub struct Services {
    pub app_state: AppState,
    pub maintenance: MaintenanceService,
    pub admin: AdminService,
}

/// Wires the production adapters (`SystemClock`, `OsSecureRandom`, Argon2id and the built-in
/// authenticator) around `store`.
pub fn services(
    store: PgUnitOfWorkFactory,
    application: ApplicationConfig,
    http: HttpConfig,
) -> anyhow::Result<Services> {
    let hasher = Arc::new(Argon2PasswordHasher::new()?);
    let deps = Dependencies {
        store: Arc::new(store),
        clock: Arc::new(SystemClock),
        random: Arc::new(OsSecureRandom),
        password_hasher: hasher.clone(),
        authenticator: Arc::new(BuiltinAuthenticator::new(hasher)),
        config: Arc::new(application),
    };
    Ok(Services {
        app_state: AppState {
            authorization: AuthorizationService::new(deps.clone()),
            token: TokenService::new(deps.clone()),
            config: Arc::new(http),
        },
        maintenance: MaintenanceService::new(deps.clone()),
        admin: AdminService::new(deps),
    })
}

/// A context for work that is not an HTTP request (CLI and jobs): fresh UUIDv7 request id,
/// no client address.
pub fn background_context() -> RequestContext {
    RequestContext {
        request_id: new_uuid_v7(&SystemClock, &OsSecureRandom).to_string(),
        client_ip: None,
    }
}
