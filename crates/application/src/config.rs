use komainu_domain::ScopeToken;
use time::Duration;

/// A scope the server knows, with its consent-screen description.
#[derive(Debug, Clone)]
pub struct ScopeDefinition {
    pub name: ScopeToken,
    /// Shown on the consent screen. 1..=200 chars, validated by komainu-server when loading config
    /// (application does not re-validate).
    pub description: String,
}

/// Settings of the use cases.
#[derive(Debug, Clone)]
pub struct ApplicationConfig {
    pub authorization_code_ttl: Duration,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub authorization_request_ttl: Duration,
    pub login_session_ttl: Duration,
    pub require_state: bool,
    pub allow_public_clients: bool,
    /// Scopes the server knows. Client allowed_scopes must be a subset.
    pub scopes: Vec<ScopeDefinition>,
    /// Expired rows are deleted this long after expiry (F-13).
    pub purge_grace: Duration,
    pub audit_retention: Duration,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl: Duration::seconds(60),
            access_token_ttl: Duration::seconds(3600),
            refresh_token_ttl: Duration::days(30),
            authorization_request_ttl: Duration::seconds(600),
            login_session_ttl: Duration::hours(8),
            require_state: false,
            allow_public_clients: false,
            scopes: Vec::new(),
            purge_grace: Duration::hours(24),
            audit_retention: Duration::days(90),
        }
    }
}
