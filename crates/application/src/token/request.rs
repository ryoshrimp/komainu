use std::fmt;

use komainu_domain::{ClientId, GrantId, OpaqueToken, ScopeSet, Secret, Subject};
use time::OffsetDateTime;

use crate::support::collect_params;

/// Client credentials as presented to the token endpoint (parsed by the HTTP layer).
#[derive(Debug)]
pub enum ClientAuthentication {
    /// `Authorization: Basic`, already URL-decoded.
    Basic {
        client_id: String,
        secret: Secret<String>,
    },
    /// `client_id` and `client_secret` in the body.
    Post {
        client_id: String,
        secret: Secret<String>,
    },
    /// Only `client_id` in the body (public clients).
    PublicId { client_id: String },
    /// No credentials.
    None,
}

/// Form parameters of `POST /token`. Empty values are treated as absent.
#[derive(Clone, Default)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
    /// Names of the above parameters that appeared more than once.
    pub duplicated: Vec<&'static str>,
}

impl TokenRequest {
    /// `client_id` and `client_secret` are not read here (the HTTP layer extracts them).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let (
            [
                grant_type,
                code,
                redirect_uri,
                scope,
                refresh_token,
                code_verifier,
            ],
            duplicated,
        ) = collect_params(
            pairs,
            [
                "grant_type",
                "code",
                "redirect_uri",
                "scope",
                "refresh_token",
                "code_verifier",
            ],
        );
        Self {
            grant_type,
            code,
            redirect_uri,
            scope,
            refresh_token,
            code_verifier,
            duplicated,
        }
    }
}

/// Prints `Some([REDACTED])` or `None`.
struct Redacted<'a>(&'a Option<String>);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(_) => f.write_str("Some([REDACTED])"),
            None => f.write_str("None"),
        }
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &Redacted(&self.code))
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("refresh_token", &Redacted(&self.refresh_token))
            .field("code_verifier", &Redacted(&self.code_verifier))
            .field("duplicated", &self.duplicated)
            .finish()
    }
}

/// Successful token response.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: OpaqueToken,
    /// Always "Bearer".
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: Option<OpaqueToken>,
    /// Always included, even when identical to the request.
    pub scope: ScopeSet,
}

/// What a valid access token stands for.
#[derive(Debug, Clone)]
pub struct AccessTokenInfo {
    pub grant_id: GrantId,
    pub client_id: ClientId,
    /// None for `client_credentials`.
    pub subject: Option<Subject>,
    pub scope: ScopeSet,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// The `token_type_hint` values (RFC 7009 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

impl TokenTypeHint {
    /// Parses "access_token" / "refresh_token". Anything else is `None` (treated as no hint).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "access_token" => Some(Self::AccessToken),
            "refresh_token" => Some(Self::RefreshToken),
            _ => None,
        }
    }
}

/// Form parameters of `POST /revoke`. Empty values are treated as absent.
#[derive(Clone, Default)]
pub struct RevocationRequest {
    pub token: Option<String>,
    /// The raw value; interpreted with [`TokenTypeHint::parse`].
    pub token_type_hint: Option<String>,
    /// Names of the above parameters that appeared more than once.
    pub duplicated: Vec<&'static str>,
}

impl RevocationRequest {
    /// `client_id` and `client_secret` are not read here (the HTTP layer extracts them).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let ([token, token_type_hint], duplicated) =
            collect_params(pairs, ["token", "token_type_hint"]);
        Self {
            token,
            token_type_hint,
            duplicated,
        }
    }
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token", &Redacted(&self.token))
            .field("token_type_hint", &self.token_type_hint)
            .field("duplicated", &self.duplicated)
            .finish()
    }
}
