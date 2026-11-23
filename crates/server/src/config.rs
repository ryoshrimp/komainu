//! Configuration: defaults, TOML file, `KOMAINU_` environment variables, and validation.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use komainu::domain::{ScopeToken, Secret};
use komainu::http::{ContentSecurityPolicy, HttpConfig, HttpConfigError};
use serde::Deserialize;

/// Defaults of every item that has one. `server.public_base_url` and `database.url` have
/// none and must come from the file or the environment.
const DEFAULTS: &str = r#"
[server]
listen = "0.0.0.0:8080"
allow_insecure_http = false
shutdown_timeout_secs = 30

[ops]
listen = "127.0.0.1:9090"

[database]
max_connections = 10
acquire_timeout_secs = 5

[session]
cookie_secure = true
ttl_secs = 28800

[oauth]
authorization_code_ttl_secs = 60
access_token_ttl_secs = 3600
refresh_token_ttl_secs = 2592000
authorization_request_ttl_secs = 600
require_state = false

[clients]
allow_public = false

[cleanup]
enabled = true
interval_secs = 600
grace_secs = 86400
audit_retention_days = 90

[log]
format = "json"
filter = "info"
"#;

/// Name of the file read from the current directory when `--config` is not given.
const DEFAULT_FILE: &str = "komainu.toml";

/// A configuration error. The process exits with code 2.
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// The whole configuration. No `Clone` or `PartialEq`: `database.url` is a `Secret`.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub ops: OpsConfig,
    pub database: DatabaseConfig,
    pub session: SessionConfig,
    pub oauth: OauthConfig,
    pub clients: ClientsConfig,
    #[serde(default)]
    pub scopes: Vec<ScopeConfig>,
    pub cleanup: CleanupConfig,
    pub log: LogConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub public_base_url: String,
    pub allow_insecure_http: bool,
    /// Optional `Content-Security-Policy` of the HTML screens; `frame-ancestors` is added.
    #[serde(default)]
    pub content_security_policy: Option<String>,
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct OpsConfig {
    pub listen: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: Secret<String>,
    pub max_connections: u32,
    pub acquire_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    pub cookie_secure: bool,
    pub ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct OauthConfig {
    pub authorization_code_ttl_secs: u64,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub authorization_request_ttl_secs: u64,
    pub require_state: bool,
}

#[derive(Debug, Deserialize)]
pub struct ClientsConfig {
    pub allow_public: bool,
}

#[derive(Debug, Deserialize)]
pub struct ScopeConfig {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct CleanupConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub grace_secs: u64,
    pub audit_retention_days: u64,
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub format: LogFormat,
    pub filter: String,
}

/// Output format of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Reads defaults, then the file, then `KOMAINU_*` environment variables.
///
/// With `path` set, the file must exist. Without it, `komainu.toml` in the current directory
/// is read when present. The result is not validated; see [`validate`].
pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
    let mut figment = Figment::new().merge(Toml::string(DEFAULTS));
    match path {
        Some(path) => {
            if !path.is_file() {
                return Err(invalid(format!(
                    "config file not found: {}",
                    path.display()
                )));
            }
            figment = figment.merge(Toml::file(path));
        }
        None => figment = figment.merge(Toml::file(DEFAULT_FILE)),
    }
    figment = figment.merge(Env::prefixed("KOMAINU_").split("__").ignore(&["scopes"]));
    figment
        .extract()
        .map_err(|e| invalid(format!("invalid configuration: {e}")))
}

/// Checks that `log.filter` is valid `tracing` `EnvFilter` syntax.
pub fn validate_log_filter(log: &LogConfig) -> Result<(), ConfigError> {
    tracing_subscriber::EnvFilter::try_new(&log.filter)
        .map(drop)
        .map_err(|e| invalid(format!("log.filter is not a valid filter: {e}")))
}

/// Checks the rules in server.md and normalizes `server.public_base_url` (no trailing `/`).
/// Returns the first error found.
pub fn validate(config: &mut Config) -> Result<(), ConfigError> {
    let server = &mut config.server;
    let checked = if server.allow_insecure_http {
        HttpConfig::new_insecure(&server.public_base_url)
    } else {
        HttpConfig::new(&server.public_base_url)
    };
    if let Err(error) = checked {
        return Err(match error {
            HttpConfigError::NotAbsolute(e) => invalid(format!(
                "server.public_base_url is not an absolute URL: {e}"
            )),
            HttpConfigError::QueryOrFragment => {
                invalid("server.public_base_url must not have a query or a fragment")
            }
            HttpConfigError::InsecureScheme => invalid(
                "server.public_base_url must use https (set server.allow_insecure_http = true for local development)",
            ),
            HttpConfigError::UnsupportedScheme(other) => invalid(format!(
                "server.public_base_url has an unsupported scheme: {other}"
            )),
            HttpConfigError::MissingHost => invalid("server.public_base_url must have a host"),
            // Unreachable today: `HttpConfigError` is `#[non_exhaustive]`, so the compiler
            // requires a wildcard arm for variants added later.
            other => invalid(format!("server.public_base_url: {other}")),
        });
    }
    let trimmed_len = server.public_base_url.trim_end_matches('/').len();
    server.public_base_url.truncate(trimmed_len);
    if let Some(policy) = &server.content_security_policy
        && let Err(error) = ContentSecurityPolicy::custom(policy)
    {
        return Err(invalid(format!("server.content_security_policy: {error}")));
    }

    let positive = [
        ("server.shutdown_timeout_secs", server.shutdown_timeout_secs),
        (
            "database.max_connections",
            u64::from(config.database.max_connections),
        ),
        (
            "database.acquire_timeout_secs",
            config.database.acquire_timeout_secs,
        ),
        ("session.ttl_secs", config.session.ttl_secs),
        (
            "oauth.authorization_code_ttl_secs",
            config.oauth.authorization_code_ttl_secs,
        ),
        (
            "oauth.access_token_ttl_secs",
            config.oauth.access_token_ttl_secs,
        ),
        (
            "oauth.refresh_token_ttl_secs",
            config.oauth.refresh_token_ttl_secs,
        ),
        (
            "oauth.authorization_request_ttl_secs",
            config.oauth.authorization_request_ttl_secs,
        ),
        ("cleanup.interval_secs", config.cleanup.interval_secs),
        ("cleanup.grace_secs", config.cleanup.grace_secs),
        (
            "cleanup.audit_retention_days",
            config.cleanup.audit_retention_days,
        ),
    ];
    for (name, value) in positive {
        if value == 0 {
            return Err(invalid(format!("{name} must be 1 or greater")));
        }
    }

    let mut seen = BTreeSet::new();
    for scope in &config.scopes {
        ScopeToken::try_new(scope.name.clone()).map_err(|e| invalid(format!("scopes: {e}")))?;
        if !seen.insert(scope.name.as_str()) {
            return Err(invalid(format!("scopes: duplicate name: {}", scope.name)));
        }
        let length = scope.description.chars().count();
        if !(1..=200).contains(&length) {
            return Err(invalid(format!(
                "scopes: description of {} must be 1 to 200 characters",
                scope.name
            )));
        }
    }

    if config.server.listen == config.ops.listen {
        return Err(invalid("server.listen and ops.listen must differ"));
    }

    validate_log_filter(&config.log)?;

    if config.server.public_base_url.starts_with("https://") && !config.session.cookie_secure {
        tracing::warn!("session.cookie_secure is false although public_base_url uses https");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use figment::Jail;

    use super::*;

    const EXAMPLE: &str = include_str!("../../../config/komainu.example.toml");

    fn load_validated(jail: &Jail) -> Result<Config, ConfigError> {
        let _ = jail;
        let mut config = load(None)?;
        validate(&mut config)?;
        Ok(config)
    }

    #[test]
    fn example_file_is_valid() {
        Jail::expect_with(|jail| {
            jail.create_file("komainu.toml", EXAMPLE)?;
            let config = load_validated(jail).expect("example config is valid");
            assert_eq!(config.scopes.len(), 2);
            assert_eq!(config.server.listen.port(), 8080);
            Ok(())
        });
    }

    #[test]
    fn non_string_database_url_is_reported() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "komainu.toml",
                "[server]\npublic_base_url = \"https://a.example\"\n[database]\nurl = 123\n",
            )?;
            let error = load(None).expect_err("url = 123 is rejected").to_string();
            assert!(error.contains("database.url"), "{error}");
            assert!(error.contains("failed to deserialize secret"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn environment_overrides_the_file() {
        Jail::expect_with(|jail| {
            jail.create_file("komainu.toml", EXAMPLE)?;
            jail.set_env("KOMAINU_DATABASE__URL", "postgres://other/db");
            let config = load_validated(jail).expect("valid");
            assert_eq!(
                config.database.url.expose_secret_ref(),
                "postgres://other/db"
            );
            Ok(())
        });
    }

    #[test]
    fn scopes_cannot_come_from_the_environment() {
        Jail::expect_with(|jail| {
            jail.create_file("komainu.toml", EXAMPLE)?;
            jail.set_env("KOMAINU_SCOPES", "[]");
            let config = load_validated(jail).expect("valid");
            assert_eq!(config.scopes.len(), 2);
            Ok(())
        });
    }

    #[test]
    fn missing_required_items_are_rejected() {
        Jail::expect_with(|_| {
            let error = load(None)
                .expect_err("required items are missing")
                .to_string();
            assert!(error.contains("database"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn explicit_config_file_must_exist() {
        let error = load(Some(Path::new("/nonexistent/komainu.toml"))).expect_err("missing");
        assert!(error.to_string().contains("not found"));
    }

    #[test]
    fn http_public_base_url_needs_the_opt_in() {
        Jail::expect_with(|jail| {
            let file = EXAMPLE.replace("https://auth.example.com", "http://auth.example.com");
            jail.create_file("komainu.toml", &file)?;
            let error = load_validated(jail)
                .expect_err("http is rejected")
                .to_string();
            assert!(error.contains("https"), "{error}");

            let file = file.replace("allow_insecure_http = false", "allow_insecure_http = true");
            jail.create_file("komainu.toml", &file)?;
            load_validated(jail).expect("http is allowed with the opt-in");
            Ok(())
        });
    }

    #[test]
    fn content_security_policy_is_validated() {
        Jail::expect_with(|jail| {
            let file = EXAMPLE.replace(
                "allow_insecure_http = false",
                "allow_insecure_http = false\ncontent_security_policy = \"default-src 'none'; frame-ancestors *\"",
            );
            jail.create_file("komainu.toml", &file)?;
            let error = load_validated(jail).expect_err("rejected").to_string();
            assert!(error.contains("server.content_security_policy"), "{error}");

            let file = EXAMPLE.replace(
                "allow_insecure_http = false",
                "allow_insecure_http = false\ncontent_security_policy = \"default-src 'none'\"",
            );
            jail.create_file("komainu.toml", &file)?;
            load_validated(jail).expect("valid");
            Ok(())
        });
    }

    #[test]
    fn trailing_slash_is_removed() {
        Jail::expect_with(|jail| {
            let file = EXAMPLE.replace("https://auth.example.com", "https://auth.example.com/");
            jail.create_file("komainu.toml", &file)?;
            let config = load_validated(jail).expect("valid");
            assert_eq!(config.server.public_base_url, "https://auth.example.com");
            Ok(())
        });
    }

    #[test]
    fn duplicate_scope_names_are_rejected() {
        Jail::expect_with(|jail| {
            let file = format!("{EXAMPLE}\n[[scopes]]\nname = \"read\"\ndescription = \"again\"\n");
            jail.create_file("komainu.toml", &file)?;
            let error = load_validated(jail).expect_err("duplicate").to_string();
            assert!(error.contains("duplicate"), "{error}");
            Ok(())
        });
    }

    #[test]
    fn zero_values_and_equal_listeners_are_rejected() {
        Jail::expect_with(|jail| {
            let file = EXAMPLE.replace("ttl_secs = 28800", "ttl_secs = 0");
            jail.create_file("komainu.toml", &file)?;
            assert!(load_validated(jail).is_err());

            let file = EXAMPLE.replace("127.0.0.1:9090", "0.0.0.0:8080");
            jail.create_file("komainu.toml", &file)?;
            assert!(load_validated(jail).is_err());
            Ok(())
        });
    }

    #[test]
    fn debug_output_hides_the_database_url() {
        Jail::expect_with(|jail| {
            let file = EXAMPLE.replace("komainu:komainu@", "komainu:hunter2-password@");
            jail.create_file("komainu.toml", &file)?;
            let config = load_validated(jail).expect("valid");
            let debug = format!("{config:?}");
            assert!(!debug.contains("hunter2-password"), "{debug}");
            assert!(debug.contains("[REDACTED]"), "{debug}");
            Ok(())
        });
    }
}
