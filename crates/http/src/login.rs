use askama::Template;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use komainu_application::{LoginCredentials, LoginError, NonRedirectableError};
use komainu_domain::{AuthorizationRequestId, Secret};
use serde::Deserialize;

use crate::authorize::{
    LoggedOutPage, TEMPORARILY_UNAVAILABLE, authorize_failure, bad_request, error_page, html,
    redirect, with_cookie,
};
use crate::cookies::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::form::{Form, parse_request_id, verified_csrf};
use crate::metrics::count_login_attempt;
use crate::middleware::Ctx;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    /// `public_base_url`, used for the form action.
    base_url: String,
    client_name: String,
    request_id: String,
    csrf_token: String,
    username: String,
    error: Option<&'static str>,
}

#[derive(Deserialize)]
pub(crate) struct LoginQuery {
    request_id: String,
}

/// `GET /login?request_id=...`.
pub(crate) async fn login_get(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    query: Result<Query<LoginQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Some(request_id) = query
        .ok()
        .and_then(|Query(query)| parse_request_id(&query.request_id))
    else {
        return bad_request(NonRedirectableError::RequestNotFound);
    };
    let Some(csrf) = cookies::token(&headers, CSRF_COOKIE) else {
        return bad_request(NonRedirectableError::CsrfMismatch);
    };
    match state.authorization.login_form(&ctx, request_id).await {
        Ok(view) => html(
            StatusCode::OK,
            LoginPage {
                base_url: state.config.public_base_url.clone(),
                client_name: view.client_name,
                request_id: request_id.as_inner().to_string(),
                csrf_token: csrf.expose().to_owned(),
                username: String::new(),
                error: None,
            },
        ),
        Err(error) => authorize_failure(&state, error, None).0,
    }
}

/// `POST /login`.
pub(crate) async fn login_post(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let not_found = || bad_request(NonRedirectableError::RequestNotFound);
    let Some(form) = Form::parse(&headers, &body) else {
        return not_found();
    };
    let (Some(request_id), Some(csrf_token), Some(username), Some(password)) = (
        form.get("request_id"),
        form.get("csrf_token"),
        form.get("username"),
        form.get("password"),
    ) else {
        return not_found();
    };
    let Some(request_id) = parse_request_id(request_id) else {
        return not_found();
    };
    let csrf = match verified_csrf(csrf_token, &headers) {
        Ok(csrf) => csrf,
        Err(error) => return bad_request(error),
    };
    let credentials = LoginCredentials {
        username: username.to_owned(),
        password: Secret::new(password.to_owned()),
    };
    match state
        .authorization
        .login(&ctx, request_id, &csrf, credentials)
        .await
    {
        Ok(logged_in) => {
            count_login_attempt("success");
            let location = format!(
                "{}/authorize/resume?request_id={}",
                state.config.public_base_url,
                request_id.as_inner()
            );
            let cookie = cookies::set(
                SESSION_COOKIE,
                logged_in.session_token.expose(),
                logged_in.max_age.whole_seconds(),
                state.config.cookie_secure,
            );
            with_cookie(redirect(&location), cookie)
        }
        Err(LoginError::InvalidCredentials) => {
            count_login_attempt("invalid_credentials");
            invalid_credentials_page(&state, &ctx, request_id, csrf_token, username).await
        }
        Err(LoginError::Authorize(error)) => {
            count_login_attempt("error");
            authorize_failure(&state, error, None).0
        }
        Err(LoginError::Store(error)) => {
            count_login_attempt("error");
            tracing::error!(%error, "store error");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, TEMPORARILY_UNAVAILABLE)
        }
    }
}

async fn invalid_credentials_page(
    state: &AppState,
    ctx: &komainu_application::RequestContext,
    request_id: AuthorizationRequestId,
    csrf_token: &str,
    username: &str,
) -> Response {
    match state.authorization.login_form(ctx, request_id).await {
        Ok(view) => html(
            StatusCode::OK,
            LoginPage {
                base_url: state.config.public_base_url.clone(),
                client_name: view.client_name,
                request_id: request_id.as_inner().to_string(),
                csrf_token: csrf_token.to_owned(),
                username: username.to_owned(),
                error: Some("Invalid username or password."),
            },
        ),
        Err(error) => authorize_failure(state, error, None).0,
    }
}

/// `POST /logout`.
pub(crate) async fn logout(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
) -> Response {
    let delete = cookies::delete(SESSION_COOKIE, state.config.cookie_secure);
    let response = match cookies::token(&headers, SESSION_COOKIE) {
        Some(session) => match state.authorization.logout(&ctx, &session).await {
            Ok(()) => html(StatusCode::OK, LoggedOutPage),
            Err(error) => {
                tracing::error!(%error, "store error");
                error_page(StatusCode::INTERNAL_SERVER_ERROR, TEMPORARILY_UNAVAILABLE)
            }
        },
        None => html(StatusCode::OK, LoggedOutPage),
    };
    with_cookie(response, delete)
}
