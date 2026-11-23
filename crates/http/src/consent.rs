use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use komainu_application::NonRedirectableError;

use crate::authorize::{authorize_failure, redirect, with_cookie};
use crate::cookies::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::form::{Form, parse_request_id, verified_csrf};
use crate::metrics::count_authorization_request;
use crate::middleware::Ctx;
use crate::screens::{ScreenCtx, form_fields};
use crate::state::AppState;

/// `POST /authorize/decision`.
pub(crate) async fn decision(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let screens = ScreenCtx {
        state: &state,
        headers: &headers,
        request_id: &ctx.request_id,
    };
    // Every early rejection is an error screen and is counted as such.
    let reject = |error: NonRedirectableError| {
        count_authorization_request("error_page");
        screens.bad_request(error)
    };
    let not_found = || reject(NonRedirectableError::RequestNotFound);
    let Some(form) = Form::parse(&headers, &body) else {
        return not_found();
    };
    let (Some(request_id), Some(csrf_token), Some(decision)) = (
        form.get(form_fields::REQUEST_ID),
        form.get(form_fields::CSRF_TOKEN),
        form.get(form_fields::DECISION),
    ) else {
        return not_found();
    };
    let approve = match decision {
        form_fields::DECISION_APPROVE => true,
        form_fields::DECISION_DENY => false,
        _ => return not_found(),
    };
    let Some(request_id) = parse_request_id(request_id) else {
        return not_found();
    };
    let csrf = match verified_csrf(csrf_token, &headers) {
        Ok(csrf) => csrf,
        Err(error) => return reject(error),
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
                cookies::delete(CSRF_COOKIE, state.config.cookie_secure()),
            )
        }
        Err(error) => {
            let (response, label) = authorize_failure(screens, error, Some(request_id));
            count_authorization_request(label);
            response
        }
    }
}
