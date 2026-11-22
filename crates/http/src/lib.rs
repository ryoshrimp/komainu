//! HTTP endpoints and screens of the komainu authorization server.
//!
//! The crate translates HTTP requests into calls of the application use cases and renders
//! their results: OAuth endpoints, login and consent screens, cookies, security headers,
//! request ids and HTTP metrics. It holds no business rules.

mod authorize;
mod client_auth;
mod consent;
mod cookies;
mod form;
mod login;
mod metrics;
mod middleware;
mod oauth_error;
mod security_headers;
mod state;
mod token;

use axum::Router;
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub use state::{AppState, HttpConfig};

/// All endpoints plus the middleware stack.
///
/// Mount at "/". The base path is part of `public_base_url` only for `Location` headers;
/// embedders using a prefix should nest this router under the same prefix.
pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    Router::new()
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/authorize/resume", get(authorize::resume))
        .route("/authorize/decision", post(consent::decision))
        .route("/login", get(login::login_get).post(login::login_post))
        .route("/logout", post(login::logout))
        .route("/token", post(token::token))
        .with_state(state)
        // Layers run from the last one added (outermost) to the first (innermost).
        .layer(axum::middleware::from_fn(
            security_headers::add_security_headers,
        ))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(axum::middleware::from_fn(metrics::record_http_metrics))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(middleware::make_span)
                .on_response(middleware::on_response),
        )
        .layer(axum::middleware::from_fn(middleware::request_id))
}
