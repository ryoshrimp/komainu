//! The browser-facing screens: the [`ScreenRenderer`] trait, its contexts and the built-in
//! English [`DefaultScreens`].

use askama::Template;
use axum::http::header::{ACCEPT_LANGUAGE, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use komainu_application::{NonRedirectableError, ScopeView};

use crate::state::AppState;

/// Names of the form fields the screens must send back.
pub mod form_fields {
    /// Hidden field with the authorization request id.
    pub const REQUEST_ID: &str = "request_id";
    /// Hidden field with the CSRF token.
    pub const CSRF_TOKEN: &str = "csrf_token";
    /// Login form: the user name.
    pub const USERNAME: &str = "username";
    /// Login form: the password.
    pub const PASSWORD: &str = "password";
    /// Consent form: the decision.
    pub const DECISION: &str = "decision";
    /// Value of [`DECISION`] to approve.
    pub const DECISION_APPROVE: &str = "approve";
    /// Value of [`DECISION`] to deny.
    pub const DECISION_DENY: &str = "deny";
}

/// Renders the HTML documents of the browser-facing screens.
///
/// komainu decides the status code, headers and cookies; an implementation only returns
/// the body. It must HTML-escape every string it takes from a context; a template engine with
/// automatic escaping, such as askama, is recommended over building strings by hand.
/// Methods are called synchronously inside async handlers, so they must not block or do heavy
/// work.
pub trait ScreenRenderer: Send + Sync + 'static {
    /// The login screen.
    ///
    /// # Errors
    ///
    /// Returns a [`RenderError`] when the document cannot be produced.
    fn login(&self, screen: &LoginScreen<'_>) -> Result<String, RenderError>;
    /// The consent screen.
    ///
    /// # Errors
    ///
    /// Returns a [`RenderError`] when the document cannot be produced.
    fn consent(&self, screen: &ConsentScreen<'_>) -> Result<String, RenderError>;
    /// The error screen (status 400 or 500).
    ///
    /// # Errors
    ///
    /// Returns a [`RenderError`] when the document cannot be produced.
    fn error(&self, screen: &ErrorScreen<'_>) -> Result<String, RenderError>;
    /// The screen shown after logout.
    ///
    /// # Errors
    ///
    /// Returns a [`RenderError`] when the document cannot be produced.
    fn logged_out(&self, screen: &LoggedOutScreen<'_>) -> Result<String, RenderError>;
}

/// Facts about the request that every screen receives.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ScreenRequest<'a> {
    /// Raw value of the `Accept-Language` header; `None` when absent or when
    /// `HeaderValue::to_str` fails.
    pub accept_language: Option<&'a str>,
    /// `HttpConfig::public_base_url`, without a trailing `/`.
    pub base_url: &'a str,
    /// The request id that komainu logs and returns in `x-request-id` (for support pages).
    pub request_id: &'a str,
}

/// A form the screen must render as-is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct FormTarget<'a> {
    /// Absolute URL for the `action` attribute. Method is always `post`.
    pub action: &'a str,
    /// Hidden field `request_id` (name: [`form_fields::REQUEST_ID`]).
    pub authorization_request_id: &'a str,
    /// Hidden field `csrf_token` (name: [`form_fields::CSRF_TOKEN`]).
    pub csrf_token: &'a str,
}

/// Context of the login screen.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct LoginScreen<'a> {
    /// Request facts.
    pub request: ScreenRequest<'a>,
    /// The form; `action` is `{base_url}/login`.
    pub form: FormTarget<'a>,
    /// Display name of the client.
    pub client_name: &'a str,
    /// Username to pre-fill; empty on the first display.
    pub username: &'a str,
    /// Set when the previous attempt failed.
    pub error: Option<LoginErrorKind>,
}

/// Context of the consent screen.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ConsentScreen<'a> {
    /// Request facts.
    pub request: ScreenRequest<'a>,
    /// The form; `action` is `{base_url}/authorize/decision`.
    pub form: FormTarget<'a>,
    /// Display name of the client.
    pub client_name: &'a str,
    /// Requested scopes, sorted by name.
    pub scopes: &'a [ScopeView],
}

/// Context of the error screen.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ErrorScreen<'a> {
    /// Request facts.
    pub request: ScreenRequest<'a>,
    /// What went wrong.
    pub kind: ErrorKind,
    /// Status komainu will send: 400 or 500.
    pub status: u16,
}

/// Context of the screen shown after logout.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct LoggedOutScreen<'a> {
    /// Request facts.
    pub request: ScreenRequest<'a>,
}

/// Why the login screen shows an error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginErrorKind {
    /// Wrong username or password.
    InvalidCredentials,
}

impl LoginErrorKind {
    /// The English text the default screens show.
    #[must_use]
    pub fn default_message(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid username or password.",
        }
    }
}

/// Why the error screen is shown.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// `client_id` or `redirect_uri` was sent more than once.
    DuplicateParameter,
    /// `client_id` is missing.
    MissingClientId,
    /// The client is unknown.
    UnknownClient,
    /// `redirect_uri` is malformed.
    InvalidRedirectUri,
    /// `redirect_uri` does not match a registered value.
    RedirectUriMismatch,
    /// `redirect_uri` is required but missing.
    MissingRedirectUri,
    /// The authorization request is unknown, expired or already used.
    RequestNotFound,
    /// The CSRF token does not match.
    CsrfMismatch,
    /// The user has to sign in again.
    LoginRequired,
    /// Store failure or another internal error (status 500).
    TemporarilyUnavailable,
}

impl ErrorKind {
    /// The English text the default screens show.
    #[must_use]
    pub fn default_message(self) -> &'static str {
        match self {
            Self::DuplicateParameter => "The request contains duplicated parameters.",
            Self::MissingClientId => "client_id is missing.",
            Self::UnknownClient => "Unknown client.",
            Self::InvalidRedirectUri => "redirect_uri is invalid.",
            Self::RedirectUriMismatch => "redirect_uri does not match a registered URI.",
            Self::MissingRedirectUri => "redirect_uri is required for this client.",
            Self::RequestNotFound => {
                "This authorization request has expired or was already used. Please start again from the application."
            }
            Self::CsrfMismatch => "The form has expired. Please start again from the application.",
            Self::LoginRequired => "Please sign in again.",
            Self::TemporarilyUnavailable => "Temporarily unavailable.",
        }
    }
}

impl From<NonRedirectableError> for ErrorKind {
    fn from(error: NonRedirectableError) -> Self {
        match error {
            NonRedirectableError::DuplicateParameter => Self::DuplicateParameter,
            NonRedirectableError::MissingClientId => Self::MissingClientId,
            NonRedirectableError::UnknownClient => Self::UnknownClient,
            NonRedirectableError::InvalidRedirectUri => Self::InvalidRedirectUri,
            NonRedirectableError::RedirectUriMismatch => Self::RedirectUriMismatch,
            NonRedirectableError::MissingRedirectUri => Self::MissingRedirectUri,
            NonRedirectableError::RequestNotFound => Self::RequestNotFound,
            NonRedirectableError::CsrfMismatch => Self::CsrfMismatch,
            NonRedirectableError::LoginRequired => Self::LoginRequired,
        }
    }
}

/// A failure inside a [`ScreenRenderer`]. Logged by komainu, never shown to the user.
#[derive(Debug)]
pub struct RenderError(Box<dyn std::error::Error + Send + Sync>);

impl RenderError {
    /// Wraps the cause of the failure.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(source.into())
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to render a screen: {}", self.0)
    }
}

impl std::error::Error for RenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    /// `public_base_url`, used for the form action.
    base_url: &'a str,
    client_name: &'a str,
    request_id: &'a str,
    csrf_token: &'a str,
    username: &'a str,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentPage<'a> {
    base_url: &'a str,
    client_name: &'a str,
    scopes: &'a [ScopeView],
    request_id: &'a str,
    csrf_token: &'a str,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    message: &'static str,
}

#[derive(Template)]
#[template(path = "logged_out.html")]
struct LoggedOutPage;

fn render<T: Template>(page: &T) -> Result<String, RenderError> {
    page.render().map_err(RenderError::new)
}

/// The built-in English screens (askama templates under `crates/http/templates`).
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultScreens;

impl ScreenRenderer for DefaultScreens {
    fn login(&self, screen: &LoginScreen<'_>) -> Result<String, RenderError> {
        render(&LoginPage {
            base_url: screen.request.base_url,
            client_name: screen.client_name,
            request_id: screen.form.authorization_request_id,
            csrf_token: screen.form.csrf_token,
            username: screen.username,
            error: screen.error.map(LoginErrorKind::default_message),
        })
    }

    fn consent(&self, screen: &ConsentScreen<'_>) -> Result<String, RenderError> {
        render(&ConsentPage {
            base_url: screen.request.base_url,
            client_name: screen.client_name,
            scopes: screen.scopes,
            request_id: screen.form.authorization_request_id,
            csrf_token: screen.form.csrf_token,
        })
    }

    fn error(&self, screen: &ErrorScreen<'_>) -> Result<String, RenderError> {
        render(&ErrorPage {
            message: screen.kind.default_message(),
        })
    }

    fn logged_out(&self, _screen: &LoggedOutScreen<'_>) -> Result<String, RenderError> {
        render(&LoggedOutPage)
    }
}

/// The 500 sent when a renderer fails (or a `Location` cannot be built).
pub(crate) fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Internal Server Error",
    )
        .into_response()
}

/// What a handler needs to build a [`ScreenRequest`] and call the renderer.
#[derive(Clone, Copy)]
pub(crate) struct ScreenCtx<'a> {
    pub state: &'a AppState,
    pub headers: &'a HeaderMap,
    pub request_id: &'a str,
}

impl<'a> ScreenCtx<'a> {
    pub(crate) fn request(&self) -> ScreenRequest<'a> {
        ScreenRequest {
            accept_language: self
                .headers
                .get(ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok()),
            base_url: self.state.config.public_base_url(),
            request_id: self.request_id,
        }
    }

    /// Calls the renderer and builds the HTML response with `status`.
    pub(crate) fn render(
        &self,
        status: StatusCode,
        f: impl FnOnce(&dyn ScreenRenderer) -> Result<String, RenderError>,
    ) -> Response {
        match f(self.state.screens.as_ref()) {
            Ok(body) => {
                (status, [(CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to render a screen");
                internal_error()
            }
        }
    }

    /// The error screen with `status` (400 or 500).
    pub(crate) fn error(&self, status: StatusCode, kind: ErrorKind) -> Response {
        let screen = ErrorScreen {
            request: self.request(),
            kind,
            status: status.as_u16(),
        };
        self.render(status, |r| r.error(&screen))
    }

    /// The `400` error screen of a non-redirectable error.
    pub(crate) fn bad_request(&self, error: NonRedirectableError) -> Response {
        self.error(StatusCode::BAD_REQUEST, ErrorKind::from(error))
    }

    /// The `500` error screen of a store failure.
    pub(crate) fn unavailable(&self) -> Response {
        self.error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::TemporarilyUnavailable,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: ScreenRequest<'static> = ScreenRequest {
        accept_language: None,
        base_url: "https://auth.example.com",
        request_id: "http-1",
    };

    fn form(action: &'static str) -> FormTarget<'static> {
        FormTarget {
            action,
            authorization_request_id: "req-1",
            csrf_token: "csrf-1",
        }
    }

    fn login(username: &'static str, error: Option<LoginErrorKind>) -> String {
        DefaultScreens
            .login(&LoginScreen {
                request: REQUEST,
                form: form("https://auth.example.com/login"),
                client_name: "Example <App>",
                username,
                error,
            })
            .unwrap()
    }

    #[test]
    fn login_matches_snapshot() {
        assert_eq!(login("", None), include_str!("snapshots/login.html"));
    }

    #[test]
    fn login_error_matches_snapshot() {
        assert_eq!(
            login("alice", Some(LoginErrorKind::InvalidCredentials)),
            include_str!("snapshots/login_error.html")
        );
    }

    #[test]
    fn consent_matches_snapshot() {
        let scopes = [
            ScopeView {
                name: "read".into(),
                description: "Read your data".into(),
            },
            ScopeView {
                name: "write".into(),
                description: "Write & delete".into(),
            },
        ];
        let body = DefaultScreens
            .consent(&ConsentScreen {
                request: REQUEST,
                form: form("https://auth.example.com/authorize/decision"),
                client_name: "Example <App>",
                scopes: &scopes,
            })
            .unwrap();
        assert_eq!(body, include_str!("snapshots/consent.html"));
    }

    #[test]
    fn error_matches_snapshot() {
        let body = DefaultScreens
            .error(&ErrorScreen {
                request: REQUEST,
                kind: ErrorKind::from(NonRedirectableError::CsrfMismatch),
                status: 400,
            })
            .unwrap();
        assert_eq!(body, include_str!("snapshots/error.html"));
    }

    #[test]
    fn logged_out_matches_snapshot() {
        let body = DefaultScreens
            .logged_out(&LoggedOutScreen { request: REQUEST })
            .unwrap();
        assert_eq!(body, include_str!("snapshots/logged_out.html"));
    }
}
