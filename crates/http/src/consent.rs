use askama::Template;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use komainu_application::{NonRedirectableError, ScopeView};

use crate::authorize::{authorize_failure, bad_request, redirect, with_cookie};
use crate::cookies::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::form::{Form, parse_request_id, verified_csrf};
use crate::metrics::count_authorization_request;
use crate::middleware::Ctx;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "consent.html")]
pub(crate) struct ConsentPage {
    /// `public_base_url`, used for the form action.
    pub base_url: String,
    pub client_name: String,
    pub scopes: Vec<ScopeView>,
    pub request_id: String,
    pub csrf_token: String,
}

/// `POST /authorize/decision`.
pub(crate) async fn decision(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let not_found = || bad_request(NonRedirectableError::RequestNotFound);
    let Some(form) = Form::parse(&headers, &body) else {
        return not_found();
    };
    let (Some(request_id), Some(csrf_token), Some(decision)) = (
        form.get("request_id"),
        form.get("csrf_token"),
        form.get("decision"),
    ) else {
        return not_found();
    };
    let approve = match decision {
        "approve" => true,
        "deny" => false,
        _ => return not_found(),
    };
    let Some(request_id) = parse_request_id(request_id) else {
        return not_found();
    };
    let csrf = match verified_csrf(csrf_token, &headers) {
        Ok(csrf) => csrf,
        Err(error) => return bad_request(error),
    };
    let session = cookies::token(&headers, SESSION_COOKIE);
    let result = state
        .authorization
        .decide(&ctx, request_id, &csrf, session.as_ref(), approve)
        .await;
    match result {
        Ok(location) => {
            count_authorization_request(if approve { "code" } else { "redirect_error" });
            with_cookie(
                redirect(&location),
                cookies::delete(CSRF_COOKIE, state.config.cookie_secure),
            )
        }
        Err(error) => {
            let (response, label) = authorize_failure(&state, error, Some(request_id));
            count_authorization_request(label);
            response
        }
    }
}
