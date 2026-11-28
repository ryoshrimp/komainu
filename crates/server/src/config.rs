//! Configuration: defaults, TOML file, `KOMAINU_` environment variables, and validation.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use komainu::AesGcmKeySealer;
use komainu::adapter_std::OsSecureRandom;
use komainu::domain::{GrantType, ScopeToken, Secret, SigningAlgorithm, TokenEndpointAuthMethod};
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
disabled_grant_types = []
disabled_auth_methods = []

[signing]
# Empty disables signing. Generate with `komainu key generate-encryption-key`.
encryption_key = ""
algorithms = ["ES256"]
active_days = 90
prepublish_days = 7
retire_overlap_days = 7
rotation_interval_secs = 3600

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
    pub signing: SigningSection,
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
    pub disabled_grant_types: Vec<String>,
    pub disabled_auth_methods: Vec<String>,
}

/// `[signing]`. An empty `encryption_key` leaves signing disabled.
#[derive(Debug, Deserialize)]
pub struct SigningSection {
    pub encryption_key: Secret<String>,
    pub algorithms: Vec<String>,
    pub active_days: u64,
    pub prepublish_days: u64,
    pub retire_overlap_days: u64,
    pub rotation_interval_secs: u64,
}

impl SigningSection {
    /// Whether signing is turned on.
    pub fn enabled(&self) -> bool {
        !self.encryption_key.expose_secret_ref().trim().is_empty()
    }
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

    validate_extension_points(&config.oauth)?;
    validate_signing(&config.signing)?;

    validate_log_filter(&config.log)?;

    if config.server.public_base_url.starts_with("https://") && !config.session.cookie_secure {
        tracing::warn!("session.cookie_secure is false although public_base_url uses https");
    }
    Ok(())
}

fn validate_extension_points(oauth: &OauthConfig) -> Result<(), ConfigError> {
    for value in &oauth.disabled_grant_types {
        match value.parse::<GrantType>() {
            Ok(GrantType::AuthorizationCode) => {
                return Err(invalid(
                    "oauth.disabled_grant_types: authorization_code cannot be disabled",
                ));
            }
            Ok(_) => {}
            Err(_) => {
                return Err(invalid(format!(
                    "oauth.disabled_grant_types: unknown grant type: {value}"
                )));
            }
        }
    }
    for value in &oauth.disabled_auth_methods {
        if value.parse::<TokenEndpointAuthMethod>().is_err() {
            return Err(invalid(format!(
                "oauth.disabled_auth_methods: unknown authentication method: {value}"
            )));
        }
    }
    Ok(())
}

/// Never puts `signing.encryption_key` into a message.
/// Upper bound for the `signing.*_days` settings, so date arithmetic cannot overflow.
const MAX_SIGNING_DAYS: u64 = 36_500;

fn validate_signing(signing: &SigningSection) -> Result<(), ConfigError> {
    if signing.enabled()
        && AesGcmKeySealer::from_base64(&signing.encryption_key, Arc::new(OsSecureRandom)).is_err()
    {
        return Err(invalid(
            "signing.encryption_key must be 32 bytes in standard base64 (see `komainu key generate-encryption-key`)",
        ));
    }
    for value in &signing.algorithms {
        if value.parse::<SigningAlgorithm>().is_err() {
            return Err(invalid(format!(
                "signing.algorithms: unknown algorithm: {value}"
            )));
        }
    }
    for (name, value) in [
        ("signing.active_days", signing.active_days),
        ("signing.prepublish_days", signing.prepublish_days),
    ] {
        if value == 0 {
            return Err(invalid(format!("{name} must be 1 or greater")));
        }
    }
    for (name, value) in [
        ("signing.active_days", signing.active_days),
        ("signing.prepublish_days", signing.prepublish_days),
        ("signing.retire_overlap_days", signing.retire_overlap_days),
    ] {
        if value > MAX_SIGNING_DAYS {
            return Err(invalid(format!(
                "{name} must be {MAX_SIGNING_DAYS} or less"
            )));
        }
    }
    if signing.prepublish_days >= signing.active_days {
        return Err(invalid(
            "signing.prepublish_days must be less than signing.active_days",
        ));
    }
    let prepublish_secs = signing.prepublish_days.saturating_mul(86_400);
    if signing.rotation_interval_secs < 60 || signing.rotation_interval_secs >= prepublish_secs {
        return Err(invalid(
            "signing.rotation_interval_secs must be 60 or greater and less than signing.prepublish_days in seconds",
        ));
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

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The example file with `extra` added to `section`. `[signing]` is added by the test itself.
    fn with_section(section: &str, extra: &str) -> String {
        if section == "[signing]" {
            let base = EXAMPLE.replace("[signing]\n", "");
            format!("{base}\n[signing]\n{extra}\n")
        } else {
            EXAMPLE.replace(section, &format!("{section}\n{extra}"))
        }
    }

    fn with_extra(jail: &Jail, section: &str, extra: &str) -> Result<Config, ConfigError> {
        let file = with_section(section, extra);
        jail.create_file("komainu.toml", &file).expect("write");
        load_validated(jail)
    }

    #[test]
    fn signing_is_disabled_by_default() {
        Jail::expect_with(|jail| {
            jail.create_file("komainu.toml", EXAMPLE)?;
            let config = load_validated(jail).expect("valid");
            assert!(!config.signing.enabled());
            assert!(config.oauth.disabled_grant_types.is_empty());
            Ok(())
        });
    }

    #[test]
    fn signing_settings_are_validated() {
        Jail::expect_with(|jail| {
            let ok = with_extra(jail, "[signing]", &format!("encryption_key = \"{KEY}\""))
                .expect("valid");
            assert!(ok.signing.enabled());
            let bad = [
                "encryption_key = \"hunter2-not-base64\"",
                "encryption_key = \"AAAA\"",
                "algorithms = [\"HS256\"]",
                "active_days = 0",
                "prepublish_days = 0",
                "prepublish_days = 90",
                "rotation_interval_secs = 59",
                "rotation_interval_secs = 604800",
                "active_days = 36501",
                "retire_overlap_days = 100000000000000000",
            ];
            for line in bad {
                let error = with_extra(jail, "[signing]", line)
                    .expect_err(line)
                    .to_string();
                assert!(error.contains("signing."), "{line}: {error}");
                assert!(!error.contains("hunter2"), "{error}");
            }
            Ok(())
        });
    }

    #[test]
    fn disabled_lists_are_validated() {
        Jail::expect_with(|jail| {
            with_extra(
                jail,
                "[oauth]",
                "disabled_grant_types = [\"client_credentials\"]\ndisabled_auth_methods = [\"none\"]",
            )
            .expect("valid");
            for line in [
                "disabled_grant_types = [\"authorization_code\"]",
                "disabled_grant_types = [\"bogus\"]",
                "disabled_auth_methods = [\"bogus\"]",
            ] {
                with_extra(jail, "[oauth]", line).expect_err(line);
            }
            Ok(())
        });
    }
}
