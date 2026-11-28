//! `GET /jwks`: the public keys of the authorization server's signing keys.

use axum::extract::State;
use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::oauth_error::{JSON_CONTENT_TYPE, apply_headers, no_store_headers};
use crate::state::AppState;

pub(crate) async fn serve(State(state): State<AppState>) -> Response {
    let Some(service) = &state.signing_keys else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match service.jwks_json().await {
        Ok(json) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE)),
                (
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                ),
                (ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*")),
            ],
            json.to_string(),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to build the JWKS");
            let mut response = (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE))],
                r#"{"error":"server_error"}"#,
            )
                .into_response();
            apply_headers(&mut response, no_store_headers());
            response
        }
    }
}
