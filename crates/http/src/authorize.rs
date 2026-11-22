use askama::Template;
use axum::body::Bytes;
use axum::extract::{Query, RawQuery, State};
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use komainu_application::{
    AuthorizeError, AuthorizeOutcome, AuthorizeParams, NonRedirectableError, StartResult,
};
use komainu_domain::{AuthorizationRequestId, OpaqueToken};
use serde::Deserialize;

use crate::consent::ConsentPage;
use crate::cookies::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::form::parse_request_id;
use crate::metrics::count_authorization_request;
use crate::middleware::Ctx;
use crate::state::AppState;

pub(crate) const TEMPORARILY_UNAVAILABLE: &str = "Temporarily unavailable.";

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorPage {
    pub message: &'static str,
}

#[derive(Template)]
#[template(path = "logged_out.html")]
pub(crate) struct LoggedOutPage;

/// Renders a template as an HTML response.
pub(crate) fn html<T: Template>(status: StatusCode, page: T) -> Response {
    match page.render() {
        Ok(body) => (status, [(CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render a template");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

pub(crate) fn error_page(status: StatusCode, message: &'static str) -> Response {
    html(status, ErrorPage { message })
}

/// `302` to `location`.
pub(crate) fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(_) => error_page(StatusCode::INTERNAL_SERVER_ERROR, TEMPORARILY_UNAVAILABLE),
    }
}

pub(crate) fn with_cookie(mut response: Response, cookie: HeaderValue) -> Response {
    response.headers_mut().append(SET_COOKIE, cookie);
    response
}

pub(crate) fn login_url(state: &AppState, request_id: AuthorizationRequestId) -> String {
    format!(
        "{}/login?request_id={}",
        state.config.public_base_url,
        request_id.as_inner()
    )
}

pub(crate) fn csrf_cookie(state: &AppState, token: &OpaqueToken) -> HeaderValue {
    cookies::set(
        CSRF_COOKIE,
        token.expose(),
        state.config.csrf_cookie_ttl.whole_seconds(),
        state.config.cookie_secure,
    )
}

fn non_redirectable_message(error: NonRedirectableError) -> &'static str {
    match error {
        NonRedirectableError::DuplicateParameter => "The request contains duplicated parameters.",
        NonRedirectableError::MissingClientId => "client_id is missing.",
        NonRedirectableError::UnknownClient => "Unknown client.",
        NonRedirectableError::InvalidRedirectUri => "redirect_uri is invalid.",
        NonRedirectableError::RedirectUriMismatch => {
            "redirect_uri does not match a registered URI."
        }
        NonRedirectableError::MissingRedirectUri => "redirect_uri is required for this client.",
        NonRedirectableError::RequestNotFound => {
            "This authorization request has expired or was already used. Please start again from the application."
        }
        NonRedirectableError::CsrfMismatch => {
            "The form has expired. Please start again from the application."
        }
        NonRedirectableError::LoginRequired => "Please sign in again.",
    }
}

/// The `400` error screen of a non-redirectable error.
pub(crate) fn bad_request(error: NonRedirectableError) -> Response {
    error_page(StatusCode::BAD_REQUEST, non_redirectable_message(error))
}

/// Converts a use case error to a response and the `komainu_authorization_requests_total`
/// result label. `request_id` turns `LoginRequired` into a redirect to the login screen.
pub(crate) fn authorize_failure(
    state: &AppState,
    error: AuthorizeError,
    request_id: Option<AuthorizationRequestId>,
) -> (Response, &'static str) {
    match error {
        AuthorizeError::NonRedirectable(NonRedirectableError::LoginRequired)
            if request_id.is_some() =>
        {
            let id = request_id.expect("checked by the guard");
            (redirect(&login_url(state, id)), "login_required")
        }
        AuthorizeError::NonRedirectable(error) => (bad_request(error), "error_page"),
        AuthorizeError::Redirect { location, .. } => (redirect(&location), "redirect_error"),
        AuthorizeError::Store(error) => {
            tracing::error!(%error, "store error");
            (
                error_page(StatusCode::INTERNAL_SERVER_ERROR, TEMPORARILY_UNAVAILABLE),
                "error_page",
            )
        }
    }
}

/// Renders the outcome of `start` or `resume`. `csrf` is the token for the consent form;
/// `set_cookie` stores it in `komainu_csrf` (only `start` creates a new request).
fn outcome_response(
    state: &AppState,
    outcome: AuthorizeOutcome,
    csrf: Option<OpaqueToken>,
    set_cookie: bool,
) -> (Response, &'static str) {
    let with_csrf_cookie = |response: Response| match (&csrf, set_cookie) {
        (Some(token), true) => with_cookie(response, csrf_cookie(state, token)),
        _ => response,
    };
    match outcome {
        AuthorizeOutcome::LoginRequired { request_id } => (
            with_csrf_cookie(redirect(&login_url(state, request_id))),
            "login_required",
        ),
        AuthorizeOutcome::ConsentRequired { request_id, prompt } => {
            let Some(csrf) = csrf.as_ref() else {
                return (
                    bad_request(NonRedirectableError::CsrfMismatch),
                    "error_page",
                );
            };
            let page = ConsentPage {
                base_url: state.config.public_base_url.clone(),
                client_name: prompt.client_name,
                scopes: prompt.scopes,
                request_id: request_id.as_inner().to_string(),
                csrf_token: csrf.expose().to_owned(),
            };
            (
                with_csrf_cookie(html(StatusCode::OK, page)),
                "consent_required",
            )
        }
        AuthorizeOutcome::Redirect { location } => (redirect(&location), "code"),
    }
}

async fn start(
    state: &AppState,
    ctx: &komainu_application::RequestContext,
    headers: &HeaderMap,
    pairs: Vec<(String, String)>,
) -> Response {
    let params = AuthorizeParams::from_pairs(pairs);
    let session = cookies::token(headers, SESSION_COOKIE);
    let (response, label) = match state
        .authorization
        .start(ctx, params, session.as_ref())
        .await
    {
        Ok(StartResult {
            outcome,
            csrf_token,
        }) => outcome_response(state, outcome, csrf_token, true),
        Err(error) => authorize_failure(state, error, None),
    };
    count_authorization_request(label);
    response
}

pub(crate) async fn authorize_get(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let pairs = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    start(&state, &ctx, &headers, pairs).await
}

pub(crate) async fn authorize_post(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let pairs = form_urlencoded::parse(&body).into_owned().collect();
    start(&state, &ctx, &headers, pairs).await
}

#[derive(Deserialize)]
pub(crate) struct ResumeQuery {
    request_id: String,
}

pub(crate) async fn resume(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    query: Result<Query<ResumeQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Some(request_id) = query
        .ok()
        .and_then(|Query(query)| parse_request_id(&query.request_id))
    else {
        count_authorization_request("error_page");
        return bad_request(NonRedirectableError::RequestNotFound);
    };
    let session = cookies::token(&headers, SESSION_COOKIE);
    let csrf = cookies::token(&headers, CSRF_COOKIE);
    let (response, label) = match state
        .authorization
        .resume(&ctx, request_id, session.as_ref())
        .await
    {
        Ok(outcome) => outcome_response(&state, outcome, csrf, false),
        Err(error) => authorize_failure(&state, error, None),
    };
    count_authorization_request(label);
    response
}
