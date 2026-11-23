use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use komainu_application::{TokenError, TokenRequest};
use serde::Serialize;

use crate::client_auth::client_authentication;
use crate::form::{is_form_content_type, split_client_credentials};
use crate::metrics::count_token_request;
use crate::middleware::Ctx;
use crate::oauth_error::{apply_headers, token_error_response, token_headers};
use crate::state::AppState;

#[derive(Serialize)]
struct TokenBody {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

fn grant_type_label(grant_type: Option<&str>) -> &'static str {
    match grant_type {
        Some("authorization_code") => "authorization_code",
        Some("client_credentials") => "client_credentials",
        Some("refresh_token") => "refresh_token",
        _ => "other",
    }
}

fn failure(grant_type: &'static str, error: &TokenError) -> Response {
    if let TokenError::Server(source) = error {
        tracing::error!(error = %source, "token endpoint store error");
    }
    count_token_request(grant_type, error.code());
    token_error_response(error)
}

/// `POST /token`.
pub(crate) async fn token(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form_content_type(&headers) {
        return failure("other", &TokenError::InvalidRequest);
    }
    let (credentials, rest) = split_client_credentials(&body);
    let request = TokenRequest::from_pairs(rest);
    let label = grant_type_label(request.grant_type.as_deref());
    let Some(credentials) = credentials else {
        return failure(label, &TokenError::InvalidRequest);
    };
    let authentication = match client_authentication(&headers, credentials) {
        Ok(authentication) => authentication,
        Err(error) => return failure(label, &error),
    };
    match state.token.exchange(&ctx, authentication, request).await {
        Ok(response) => {
            count_token_request(label, "success");
            let body = TokenBody {
                access_token: response.access_token.expose().to_owned(),
                token_type: response.token_type,
                expires_in: response.expires_in,
                refresh_token: response
                    .refresh_token
                    .map(|token| token.expose().to_owned()),
                scope: response.scope.to_string(),
            };
            let mut http = Json(body).into_response();
            apply_headers(&mut http, token_headers());
            http
        }
        Err(error) => failure(label, &error),
    }
}
