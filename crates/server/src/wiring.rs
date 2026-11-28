//! Maps the configuration onto the settings of each crate and builds the services.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use komainu::adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory};
use komainu::adapter_std::{OsSecureRandom, SystemClock};
use komainu::application::{ApplicationConfig, RequestContext, ScopeDefinition, new_uuid_v7};
use komainu::domain::{GrantType, ScopeToken, TokenEndpointAuthMethod};
use komainu::http::{ContentSecurityPolicy, HttpConfig};
use komainu::{
    AesGcmKeySealer, KeySealer, Komainu, SigningAlgorithm, SigningConfig, SigningPolicy,
};

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
    /// Seals the signing keys; `Some` exactly when `signing.encryption_key` is set.
    pub key_sealer: Option<Arc<dyn KeySealer>>,
    /// How often the signing keys are rotated (`signing.rotation_interval_secs`).
    pub rotation_interval: Duration,
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
            signing,
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
        let mut application = application
            .with_disabled_grant_types(parse_set::<GrantType>(
                "oauth.disabled_grant_types",
                &oauth.disabled_grant_types,
            )?)
            .with_disabled_auth_methods(parse_set::<TokenEndpointAuthMethod>(
                "oauth.disabled_auth_methods",
                &oauth.disabled_auth_methods,
            )?);
        let mut key_sealer: Option<Arc<dyn KeySealer>> = None;
        if signing.enabled() {
            let days = |value: u64| time::Duration::days(i64::try_from(value).unwrap_or(i64::MAX));
            let policy = SigningPolicy::new(
                days(signing.active_days),
                days(signing.prepublish_days),
                days(signing.retire_overlap_days),
            )
            .map_err(|e| anyhow::anyhow!("signing: {e}"))?;
            let algorithms = signing
                .algorithms
                .iter()
                .map(|a| a.parse::<SigningAlgorithm>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("signing.algorithms: {e}"))?;
            let signing_config = SigningConfig::new(algorithms, policy)
                .map_err(|e| anyhow::anyhow!("signing.algorithms: {e}"))?;
            application = application.with_signing(signing_config);
            // The error does not carry the key.
            let sealer =
                AesGcmKeySealer::from_base64(&signing.encryption_key, Arc::new(OsSecureRandom))
                    .map_err(|e| anyhow::anyhow!("signing.encryption_key: {e}"))?;
            key_sealer = Some(Arc::new(sealer));
        }
        application
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
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
            key_sealer,
            rotation_interval: Duration::from_secs(signing.rotation_interval_secs),
        })
    }
}

fn parse_set<T: std::str::FromStr + Ord>(
    key: &str,
    values: &[String],
) -> anyhow::Result<BTreeSet<T>> {
    values
        .iter()
        .map(|v| {
            v.parse::<T>()
                .map_err(|_| anyhow::anyhow!("{key}: unknown value: {v}"))
        })
        .collect()
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
    key_sealer: Option<Arc<dyn KeySealer>>,
) -> anyhow::Result<Services> {
    let mut builder = Komainu::builder()
        .store(store)
        .application_config(application)
        .http_config(http);
    if let Some(sealer) = key_sealer {
        builder = builder.key_sealer(sealer);
    }
    let komainu = builder.build()?;
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

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use figment::Jail;

    use komainu::application::ApplicationConfigError;

    use super::*;
    use crate::config;

    const EXAMPLE: &str = include_str!("../../../config/komainu.example.toml");
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn settings(extra_oauth: &str, extra_signing: &str) -> anyhow::Result<Settings> {
        let mut result = None;
        Jail::expect_with(|jail| {
            let mut file = EXAMPLE
                .replace("[signing]\n", "")
                .replace("[oauth]", &format!("[oauth]\n{extra_oauth}"));
            if !extra_signing.is_empty() {
                file.push_str(&format!("\n[signing]\n{extra_signing}\n"));
            }
            jail.create_file("komainu.toml", &file)?;
            let mut config = config::load(None).expect("load");
            config::validate(&mut config).expect("validate");
            result = Some(Settings::from_config(config));
            Ok(())
        });
        result.expect("ran")
    }

    fn signing(extra: &str) -> String {
        format!("encryption_key = \"{KEY}\"\n{extra}")
    }

    fn rejection(extra_oauth: &str, extra_signing: &str) -> String {
        let error = settings(extra_oauth, extra_signing)
            .err()
            .expect("rejected");
        let text = format!("{error:#}");
        assert!(!text.contains(KEY), "{text}");
        text
    }

    #[test]
    fn retire_overlap_shorter_than_access_token_ttl_is_rejected() {
        let text = rejection("", &signing("retire_overlap_days = 0"));
        let expected = ApplicationConfigError::RetireOverlapTooShort.to_string();
        assert!(text.contains(&expected), "{text}");
    }

    #[test]
    fn disabling_every_auth_method_is_rejected() {
        let all = "disabled_auth_methods = [\"client_secret_basic\", \"client_secret_post\", \
                   \"private_key_jwt\", \"none\"]";
        let text = rejection(all, "");
        let expected = ApplicationConfigError::NoAuthMethod.to_string();
        assert!(text.contains(&expected), "{text}");
    }

    #[test]
    fn empty_and_duplicate_algorithms_are_rejected() {
        for line in ["algorithms = []", "algorithms = [\"ES256\", \"ES256\"]"] {
            let text = rejection("", &signing(line));
            assert!(text.contains("signing.algorithms"), "{line}: {text}");
        }
    }

    #[test]
    fn signing_builds_a_sealer_only_when_enabled() {
        assert!(settings("", "").expect("ok").key_sealer.is_none());
        let on = settings("", &format!("encryption_key = \"{KEY}\"")).expect("ok");
        assert!(on.key_sealer.is_some());
    }
}
