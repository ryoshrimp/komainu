use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::header::HeaderName;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Response};
use axum::middleware::Next;
use komainu_application::RequestContext;
use tracing::Span;

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// The request id of the current request, stored as a request extension.
#[derive(Debug, Clone)]
pub(crate) struct RequestId(pub String);

/// A received `x-request-id` is kept when it is 1 to 128 characters of `%x21-7E`.
fn is_valid_request_id(value: &str) -> bool {
    (1..=128).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Outermost middleware: determines the request id and echoes it in the response.
pub(crate) async fn request_id(mut request: Request, next: Next) -> axum::response::Response {
    let id = request
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map_or_else(|| uuid::Uuid::now_v7().to_string(), str::to_owned);
    request.extensions_mut().insert(RequestId(id.clone()));
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

/// Span `http_request`. The path never includes the query, so `code` and `state` stay out of
/// the logs.
pub(crate) fn make_span(request: &Request) -> Span {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map_or("", |id| id.0.as_str());
    tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
    )
}

pub(crate) fn on_response<B>(response: &Response<B>, latency: Duration, _span: &Span) {
    tracing::info!(
        status = response.status().as_u16(),
        latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
        "request finished"
    );
}

/// The `RequestContext` of the use cases. `client_ip` is the peer address (never
/// `X-Forwarded-For`).
pub(crate) struct Ctx(pub RequestContext);

impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .map_or_else(|| uuid::Uuid::now_v7().to_string(), |id| id.0.clone());
        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        Ok(Ctx(RequestContext {
            request_id,
            client_ip,
        }))
    }
}
