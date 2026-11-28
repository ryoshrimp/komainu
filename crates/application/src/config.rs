use std::collections::BTreeSet;

use komainu_domain::{GrantType, ScopeToken, TokenEndpointAuthMethod};
use time::Duration;

use crate::signing::SigningConfig;
use crate::token::AuthMethodRegistry;

/// A scope the server knows, with its consent-screen description.
#[derive(Debug, Clone)]
pub struct ScopeDefinition {
    pub name: ScopeToken,
    /// Shown on the consent screen. 1..=200 chars, validated by komainu-server when loading config
    /// (application does not re-validate).
    pub description: String,
}

/// Settings of the use cases.
///
/// Start from [`Default`] and adjust with the `with_*` methods; the struct is
/// `#[non_exhaustive]`, so it cannot be built with a struct expression outside this crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// The server's issuer identifier (for example `"https://as.example.com"`, no trailing `/`).
    /// Assertions must have this value or `"{issuer}/token"` as `aud`. `None` disables
    /// `private_key_jwt` and jwt-bearer. Defaults to `None`.
    pub issuer: Option<String>,
    /// Signing keys of the AS. `None` means the AS signs nothing. Defaults to `None`.
    pub signing: Option<SigningConfig>,
    /// Grant types turned off. Must not contain `AuthorizationCode` (see [`Self::validate`]).
    /// Defaults to empty.
    pub disabled_grant_types: BTreeSet<GrantType>,
    /// Client authentication methods turned off. Defaults to empty.
    pub disabled_auth_methods: BTreeSet<TokenEndpointAuthMethod>,
}

impl ApplicationConfig {
    /// Sets `authorization_code_ttl`.
    #[must_use]
    pub fn with_authorization_code_ttl(mut self, value: Duration) -> Self {
        self.authorization_code_ttl = value;
        self
    }

    /// Sets `access_token_ttl`.
    #[must_use]
    pub fn with_access_token_ttl(mut self, value: Duration) -> Self {
        self.access_token_ttl = value;
        self
    }

    /// Sets `refresh_token_ttl`.
    #[must_use]
    pub fn with_refresh_token_ttl(mut self, value: Duration) -> Self {
        self.refresh_token_ttl = value;
        self
    }

    /// Sets `authorization_request_ttl`.
    #[must_use]
    pub fn with_authorization_request_ttl(mut self, value: Duration) -> Self {
        self.authorization_request_ttl = value;
        self
    }

    /// Sets `login_session_ttl`.
    #[must_use]
    pub fn with_login_session_ttl(mut self, value: Duration) -> Self {
        self.login_session_ttl = value;
        self
    }

    /// Sets `require_state`.
    #[must_use]
    pub fn with_require_state(mut self, value: bool) -> Self {
        self.require_state = value;
        self
    }

    /// Sets `allow_public_clients`.
    #[must_use]
    pub fn with_allow_public_clients(mut self, value: bool) -> Self {
        self.allow_public_clients = value;
        self
    }

    /// Sets `scopes`.
    #[must_use]
    pub fn with_scopes(mut self, value: Vec<ScopeDefinition>) -> Self {
        self.scopes = value;
        self
    }

    /// Sets `purge_grace`.
    #[must_use]
    pub fn with_purge_grace(mut self, value: Duration) -> Self {
        self.purge_grace = value;
        self
    }

    /// Sets `audit_retention`.
    #[must_use]
    pub fn with_audit_retention(mut self, value: Duration) -> Self {
        self.audit_retention = value;
        self
    }

    /// Sets `issuer`.
    #[must_use]
    pub fn with_issuer(mut self, value: impl Into<String>) -> Self {
        self.issuer = Some(value.into());
        self
    }

    /// Sets `signing`.
    #[must_use]
    pub fn with_signing(mut self, value: SigningConfig) -> Self {
        self.signing = Some(value);
        self
    }

    /// Sets `disabled_grant_types`.
    #[must_use]
    pub fn with_disabled_grant_types(mut self, value: BTreeSet<GrantType>) -> Self {
        self.disabled_grant_types = value;
        self
    }

    /// Sets `disabled_auth_methods`.
    #[must_use]
    pub fn with_disabled_auth_methods(mut self, value: BTreeSet<TokenEndpointAuthMethod>) -> Self {
        self.disabled_auth_methods = value;
        self
    }

    /// Checks combinations of settings that cannot work together. Returns the first
    /// violation.
    pub fn validate(&self) -> Result<(), ApplicationConfigError> {
        if self
            .disabled_grant_types
            .contains(&GrantType::AuthorizationCode)
        {
            return Err(ApplicationConfigError::AuthorizationCodeDisabled);
        }
        if AuthMethodRegistry::builtin(self).available(self).is_empty() {
            return Err(ApplicationConfigError::NoAuthMethod);
        }
        if let Some(signing) = &self.signing
            && signing.policy().retire_overlap() < self.access_token_ttl
        {
            return Err(ApplicationConfigError::RetireOverlapTooShort);
        }
        Ok(())
    }
}

/// An invalid [`ApplicationConfig`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApplicationConfigError {
    /// `disabled_grant_types` contains `AuthorizationCode`.
    #[error("authorization_code cannot be disabled")]
    AuthorizationCodeDisabled,
    /// Every client authentication method is disabled or unavailable.
    #[error("at least one client authentication method must stay enabled")]
    NoAuthMethod,
    /// `signing.retire_overlap` is shorter than `access_token_ttl`.
    #[error("signing retire overlap must be at least the access token lifetime")]
    RetireOverlapTooShort,
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
            issuer: None,
            signing: None,
            disabled_grant_types: BTreeSet::new(),
            disabled_auth_methods: BTreeSet::new(),
        }
    }
}
