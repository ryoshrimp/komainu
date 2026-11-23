use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use komainu_application::{LoginCredentials, LoginError, NonRedirectableError};
use komainu_domain::{AuthorizationRequestId, Secret};
use serde::Deserialize;

use crate::authorize::{authorize_failure, redirect, with_cookie};
use crate::cookies::{self, CSRF_COOKIE, SESSION_COOKIE};
use crate::form::{Form, parse_request_id, verified_csrf};
use crate::metrics::count_login_attempt;
use crate::middleware::Ctx;
use crate::screens::{
    FormTarget, LoggedOutScreen, LoginErrorKind, LoginScreen, ScreenCtx, form_fields,
};
use crate::state::AppState;

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
    let screens = ScreenCtx {
        state: &state,
        headers: &headers,
        request_id: &ctx.request_id,
    };
    let Some(request_id) = query
        .ok()
        .and_then(|Query(query)| parse_request_id(&query.request_id))
    else {
        return screens.bad_request(NonRedirectableError::RequestNotFound);
    };
    let Some(csrf) = cookies::token(&headers, CSRF_COOKIE) else {
        return screens.bad_request(NonRedirectableError::CsrfMismatch);
    };
    login_screen(screens, &ctx, request_id, csrf.expose(), "", None).await
}

/// The login screen (status 200), or the error of `login_form`.
async fn login_screen(
    screens: ScreenCtx<'_>,
    ctx: &komainu_application::RequestContext,
    request_id: AuthorizationRequestId,
    csrf_token: &str,
    username: &str,
    error: Option<LoginErrorKind>,
) -> Response {
    match screens
        .state
        .authorization
        .login_form(ctx, request_id)
        .await
    {
        Ok(view) => {
            let request_id = request_id.as_inner().to_string();
            let action = format!("{}/login", screens.state.config.public_base_url());
            let screen = LoginScreen {
                request: screens.request(),
                form: FormTarget {
                    action: &action,
                    authorization_request_id: &request_id,
                    csrf_token,
                },
                client_name: &view.client_name,
                username,
                error,
            };
            screens.render(StatusCode::OK, |r| r.login(&screen))
        }
        Err(error) => authorize_failure(screens, error, None).0,
    }
}

/// `POST /login`.
pub(crate) async fn login_post(
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
    let not_found = || screens.bad_request(NonRedirectableError::RequestNotFound);
    let Some(form) = Form::parse(&headers, &body) else {
        return not_found();
    };
    let (Some(request_id), Some(csrf_token), Some(username), Some(password)) = (
        form.get(form_fields::REQUEST_ID),
        form.get(form_fields::CSRF_TOKEN),
        form.get(form_fields::USERNAME),
        form.get(form_fields::PASSWORD),
    ) else {
        return not_found();
    };
    let Some(request_id) = parse_request_id(request_id) else {
        return not_found();
    };
    let csrf = match verified_csrf(csrf_token, &headers) {
        Ok(csrf) => csrf,
        Err(error) => return screens.bad_request(error),
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
                state.config.public_base_url(),
                request_id.as_inner()
            );
            let cookie = cookies::set(
                SESSION_COOKIE,
                logged_in.session_token.expose(),
                logged_in.max_age.whole_seconds(),
                state.config.cookie_secure(),
            );
            with_cookie(redirect(&location), cookie)
        }
        Err(LoginError::InvalidCredentials) => {
            count_login_attempt("invalid_credentials");
            login_screen(
                screens,
                &ctx,
                request_id,
                csrf_token,
                username,
                Some(LoginErrorKind::InvalidCredentials),
            )
            .await
        }
        Err(LoginError::Authorize(error)) => {
            count_login_attempt("error");
            authorize_failure(screens, error, None).0
        }
        Err(LoginError::Store(error)) => {
            count_login_attempt("error");
            tracing::error!(%error, "store error");
            screens.unavailable()
        }
    }
}

/// `POST /logout`.
pub(crate) async fn logout(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
) -> Response {
    let screens = ScreenCtx {
        state: &state,
        headers: &headers,
        request_id: &ctx.request_id,
    };
    let screen = LoggedOutScreen {
        request: screens.request(),
    };
    let logged_out = || screens.render(StatusCode::OK, |r| r.logged_out(&screen));
    let delete = cookies::delete(SESSION_COOKIE, state.config.cookie_secure());
    let response = match cookies::token(&headers, SESSION_COOKIE) {
        Some(session) => match state.authorization.logout(&ctx, &session).await {
            Ok(()) => logged_out(),
            Err(error) => {
                tracing::error!(%error, "store error");
                screens.unavailable()
            }
        },
        None => logged_out(),
    };
    with_cookie(response, delete)
}
