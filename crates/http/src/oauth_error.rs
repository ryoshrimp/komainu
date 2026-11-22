use axum::Json;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use komainu_application::TokenError;
use serde::Serialize;

pub(crate) const JSON_CONTENT_TYPE: &str = "application/json;charset=UTF-8";

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: &'static str,
}

/// Headers common to every `/token` response.
pub(crate) fn token_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

fn description(error: &TokenError) -> &'static str {
    match error {
        TokenError::InvalidRequest => "The request is malformed.",
        TokenError::InvalidClient { .. } => "Client authentication failed.",
        TokenError::InvalidGrant => "The grant is invalid, expired or already used.",
        TokenError::UnauthorizedClient => "The client may not use this grant type.",
        TokenError::UnsupportedGrantType => "The grant type is not supported.",
        TokenError::InvalidScope => "The requested scope is invalid.",
        TokenError::Server(_) => "Temporarily unavailable.",
    }
}

/// RFC 6749 section 5.2 error response.
pub(crate) fn token_error_response(error: &TokenError) -> Response {
    let (status, headers) = match error {
        TokenError::InvalidClient { basic_attempted } => {
            let mut headers = token_headers();
            if *basic_attempted {
                headers.insert(
                    WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Basic realm="komainu""#),
                );
            }
            (StatusCode::UNAUTHORIZED, headers)
        }
        TokenError::Server(_) => (StatusCode::INTERNAL_SERVER_ERROR, token_headers()),
        _ => (StatusCode::BAD_REQUEST, token_headers()),
    };
    let body = ErrorBody {
        error: error.code(),
        error_description: description(error),
    };
    let mut response = (status, Json(body)).into_response();
    apply_headers(&mut response, headers);
    response
}

/// Sets `headers` on `response`, replacing what `Json` put there (the spec requires the
/// explicit charset form of the content type).
pub(crate) fn apply_headers(response: &mut Response, headers: HeaderMap) {
    for (name, value) in &headers {
        response.headers_mut().insert(name, value.clone());
    }
}
