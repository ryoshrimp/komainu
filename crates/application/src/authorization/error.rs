use crate::port::StoreError;

/// Errors of the authorization endpoint use cases.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    /// Must not redirect to the client. Show an error page.
    #[error("non-redirectable authorization error: {0}")]
    NonRedirectable(NonRedirectableError),
    /// Redirect the user agent to `location`, which carries error/error_description/state.
    #[error("authorization error redirected to the client: {}", .error.as_str())]
    Redirect {
        location: String,
        error: AuthorizeErrorCode,
    },
    /// Store failure at any stage. Never redirected.
    #[error("store error: {0}")]
    Store(StoreError),
}

impl From<StoreError> for AuthorizeError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Errors that must not be reported to the client's redirect URI (RFC 6749 §4.1.2.1).
#[derive(Debug, thiserror::Error)]
pub enum NonRedirectableError {
    #[error("duplicate client_id or redirect_uri")]
    DuplicateParameter,
    #[error("client_id is missing")]
    MissingClientId,
    #[error("unknown client")]
    UnknownClient,
    #[error("redirect_uri is malformed")]
    InvalidRedirectUri,
    #[error("redirect_uri does not match a registered value")]
    RedirectUriMismatch,
    #[error("redirect_uri is missing")]
    MissingRedirectUri,
    /// Request id unknown, expired, or already approved/denied.
    #[error("authorization request not found")]
    RequestNotFound,
    #[error("CSRF token mismatch")]
    CsrfMismatch,
    /// `decide` was called without a valid session.
    #[error("login required")]
    LoginRequired,
}

/// Error codes of RFC 6749 §4.1.2.1 used by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
}

impl AuthorizeErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
        }
    }
}

/// Errors of `login`.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// Wrong credentials or a disabled user (indistinguishable on purpose).
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Request unknown/expired/handled, or CSRF mismatch.
    #[error(transparent)]
    Authorize(AuthorizeError),
    #[error("store error: {0}")]
    Store(StoreError),
}

impl From<StoreError> for LoginError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AuthorizeError> for LoginError {
    fn from(error: AuthorizeError) -> Self {
        Self::Authorize(error)
    }
}
