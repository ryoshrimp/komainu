use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::HttpConfig;

const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");

/// Adds the clickjacking, CSP, caching and referrer headers to HTML responses (N-6).
///
/// `form-action` is deliberately not restricted: some browsers would block the redirect to
/// the client after consent.
pub(crate) async fn add_security_headers(
    State(config): State<Arc<HttpConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let is_html = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    if is_html {
        let headers = response.headers_mut();
        headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(config.content_security_policy().as_str())
                .expect("ContentSecurityPolicy only holds valid header values"),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    response
}
