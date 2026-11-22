use crate::port::StoreError;

/// Errors of the token endpoint (RFC 6749 §5.2).
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid_request")]
    InvalidRequest,
    /// `basic_attempted`: the client tried HTTP Basic (the endpoint answers 401 with
    /// `WWW-Authenticate`).
    #[error("invalid_client")]
    InvalidClient { basic_attempted: bool },
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("store error: {0}")]
    Server(StoreError),
}

impl TokenError {
    /// RFC 6749 §5.2 error code. `Server` maps to `server_error`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient { .. } => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::Server(_) => "server_error",
        }
    }
}

impl From<StoreError> for TokenError {
    fn from(error: StoreError) -> Self {
        Self::Server(error)
    }
}
