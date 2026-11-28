//! `GET /.well-known/oauth-authorization-server` (RFC 8414).

use axum::extract::State;
use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use komainu_application::ServerCapabilities;
use serde::Serialize;

use crate::oauth_error::JSON_CONTENT_TYPE;
use crate::state::{AppState, HttpConfig};

/// RFC 8414 authorization server metadata, serialized as the response body.
///
/// Field names are the RFC 8414 / RFC 7009 / RFC 7636 member names. It implements
/// [`IntoResponse`], so an embedder can return it from its own route (for example when the
/// issuer has a path, see `komainu::Komainu::metadata`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    /// Set when signing keys are enabled (see `AppState::with_signing_keys`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    /// Builds the metadata. The issuer is `config.public_base_url()` and the endpoints are
    /// that URL followed by `/authorize`, `/token` and `/revoke`.
    pub fn new(config: &HttpConfig, capabilities: &ServerCapabilities) -> Self {
        let issuer = config.public_base_url().to_owned();
        Self {
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            revocation_endpoint: format!("{issuer}/revoke"),
            issuer,
            jwks_uri: None,
            response_types_supported: capabilities
                .response_types
                .iter()
                .map(|v| v.as_str())
                .collect(),
            response_modes_supported: capabilities
                .response_modes
                .iter()
                .map(|v| v.as_str())
                .collect(),
            grant_types_supported: capabilities
                .grant_types
                .iter()
                .map(|v| v.as_str())
                .collect(),
            token_endpoint_auth_methods_supported: capabilities
                .token_endpoint_auth_methods
                .iter()
                .map(|v| v.as_str())
                .collect(),
            revocation_endpoint_auth_methods_supported: capabilities
                .revocation_endpoint_auth_methods
                .iter()
                .map(|v| v.as_str())
                .collect(),
            token_endpoint_auth_signing_alg_values_supported: capabilities
                .token_endpoint_auth_signing_algs
                .iter()
                .map(|v| v.as_str())
                .collect(),
            revocation_endpoint_auth_signing_alg_values_supported: capabilities
                .revocation_endpoint_auth_signing_algs
                .iter()
                .map(|v| v.as_str())
                .collect(),
            code_challenge_methods_supported: capabilities
                .code_challenge_methods
                .iter()
                .map(|v| v.as_str())
                .collect(),
            scopes_supported: capabilities
                .scopes
                .iter()
                .map(|v| v.as_str().to_owned())
                .collect(),
        }
    }
}

/// 200 with the JSON body, `Content-Type`, `Cache-Control: public, max-age=3600` and
/// `Access-Control-Allow-Origin: *`.
impl IntoResponse for AuthorizationServerMetadata {
    fn into_response(self) -> Response {
        metadata_response(&self)
    }
}

/// Same response as `IntoResponse`, without cloning. Used by the handler.
pub(crate) fn metadata_response(metadata: &AuthorizationServerMetadata) -> Response {
    // Plain strings and vectors of strings always serialize.
    let body = serde_json::to_vec(metadata).expect("metadata always serializes");
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE)),
            (
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
            (ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*")),
        ],
        body,
    )
        .into_response()
}

pub(crate) async fn serve(State(state): State<AppState>) -> Response {
    metadata_response(&state.metadata)
}
