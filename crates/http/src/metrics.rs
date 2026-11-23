use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics::{counter, histogram};

/// Records `komainu_http_requests_total` and `komainu_http_request_duration_seconds`.
pub(crate) async fn record_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    counter!(
        "komainu_http_requests_total",
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => response.status().as_u16().to_string(),
    )
    .increment(1);
    histogram!(
        "komainu_http_request_duration_seconds",
        "method" => method,
        "route" => route,
    )
    .record(started.elapsed().as_secs_f64());
    response
}

pub(crate) fn count_token_request(grant_type: &'static str, result: &str) {
    counter!(
        "komainu_token_requests_total",
        "grant_type" => grant_type,
        "result" => result.to_owned(),
    )
    .increment(1);
}

pub(crate) fn count_revocation_request(result: &str) {
    counter!("komainu_revocation_requests_total", "result" => result.to_owned()).increment(1);
}

pub(crate) fn count_authorization_request(result: &'static str) {
    counter!("komainu_authorization_requests_total", "result" => result).increment(1);
}

pub(crate) fn count_login_attempt(result: &'static str) {
    counter!("komainu_login_attempts_total", "result" => result).increment(1);
}
