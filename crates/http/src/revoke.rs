use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use komainu_application::{RevocationError, RevocationRequest, TokenError};

use crate::client_auth::client_authentication;
use crate::form::{is_form_content_type, split_client_credentials};
use crate::metrics::count_revocation_request;
use crate::middleware::Ctx;
use crate::oauth_error::{apply_headers, no_store_headers, revocation_error_response};
use crate::state::AppState;

fn failure(error: &RevocationError) -> Response {
    if let RevocationError::Server(source) = error {
        tracing::error!(error = %source, "revocation endpoint store error");
    }
    count_revocation_request(error.code());
    revocation_error_response(error)
}

/// `POST /revoke` (RFC 7009).
pub(crate) async fn revoke(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form_content_type(&headers) {
        return failure(&RevocationError::InvalidRequest);
    }
    let (credentials, rest) = split_client_credentials(&body);
    let Some(credentials) = credentials else {
        return failure(&RevocationError::InvalidRequest);
    };
    let request = RevocationRequest::from_pairs(rest);
    let authentication = match client_authentication(&headers, credentials) {
        Ok(authentication) => authentication,
        Err(TokenError::InvalidClient { basic_attempted }) => {
            return failure(&RevocationError::InvalidClient { basic_attempted });
        }
        Err(TokenError::Server(source)) => return failure(&RevocationError::Server(source)),
        // client_authentication only returns the variants above; anything else is a malformed request.
        Err(
            TokenError::InvalidRequest
            | TokenError::InvalidGrant
            | TokenError::UnauthorizedClient
            | TokenError::UnsupportedGrantType
            | TokenError::InvalidScope,
        ) => return failure(&RevocationError::InvalidRequest),
    };
    match state.token.revoke(&ctx, authentication, request).await {
        Ok(()) => {
            count_revocation_request("success");
            let mut response = StatusCode::OK.into_response();
            apply_headers(&mut response, no_store_headers());
            response
        }
        Err(error) => failure(&error),
    }
}
