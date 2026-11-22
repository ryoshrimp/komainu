use std::sync::Arc;

use komainu_application::{AuthorizationService, TokenService};

#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// External base URL, e.g. https://auth.example.com or https://example.com/oauth.
    /// Validated by komainu-server (absolute http(s) URL, no query/fragment) and stored as a
    /// string with the trailing '/' removed. Paths are built by plain concatenation:
    /// `format!("{public_base_url}/login")`.
    pub public_base_url: String,
    /// Adds `Secure` to cookies.
    pub cookie_secure: bool,
    /// Max request body for form posts.
    pub max_body_bytes: usize,
    /// Max-Age of the komainu_csrf cookie; set to `ApplicationConfig::authorization_request_ttl`.
    pub csrf_cookie_ttl: time::Duration,
}

#[derive(Clone)]
pub struct AppState {
    pub authorization: AuthorizationService,
    pub token: TokenService,
    pub config: Arc<HttpConfig>,
}
