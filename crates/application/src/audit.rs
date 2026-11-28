use std::collections::BTreeMap;
use std::net::IpAddr;

use komainu_domain::{ClientId, Subject};
use time::OffsetDateTime;

/// A record of a security-relevant action (F-12).
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// UUIDv7.
    pub id: uuid::Uuid,
    pub occurred_at: OffsetDateTime,
    pub kind: AuditKind,
    pub outcome: AuditOutcome,
    pub actor: AuditActor,
    pub request_id: String,
    pub client_ip: Option<IpAddr>,
    pub client_id: Option<ClientId>,
    pub subject: Option<Subject>,
    /// Extra fields. Keys are snake_case ASCII; values must never contain secrets (N-3).
    pub details: BTreeMap<&'static str, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditActor {
    Client,
    User,
    Admin,
    System,
}

impl AuditActor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::User => "user",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }
}

/// What happened. `as_str` gives the stable name stored in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    ClientRegistered,
    ClientUpdated,
    ClientSecretRotated,
    ClientDisabled,
    ClientEnabled,
    UserCreated,
    UserPasswordChanged,
    UserDisabled,
    UserEnabled,
    LoginSucceeded,
    LoginFailed,
    Logout,
    ConsentGranted,
    AuthorizationApproved,
    AuthorizationDenied,
    AuthorizationCodeIssued,
    AuthorizationCodeReplayDetected,
    RefreshTokenReplayDetected,
    GrantRevoked,
    TokenIssued,
    ClientAuthenticationFailed,
    TokenRevocationClientMismatch,
    IssuerRegistered,
    IssuerUpdated,
    IssuerDisabled,
    IssuerEnabled,
    SubjectMapped,
    SubjectUnmapped,
    AssertionRejected,
}

impl AuditKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientRegistered => "client.registered",
            Self::ClientUpdated => "client.updated",
            Self::ClientSecretRotated => "client.secret_rotated",
            Self::ClientDisabled => "client.disabled",
            Self::ClientEnabled => "client.enabled",
            Self::UserCreated => "user.created",
            Self::UserPasswordChanged => "user.password_changed",
            Self::UserDisabled => "user.disabled",
            Self::UserEnabled => "user.enabled",
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::Logout => "logout",
            Self::ConsentGranted => "consent.granted",
            Self::AuthorizationApproved => "authorization.approved",
            Self::AuthorizationDenied => "authorization.denied",
            Self::AuthorizationCodeIssued => "authorization_code.issued",
            Self::AuthorizationCodeReplayDetected => "authorization_code.replay_detected",
            Self::RefreshTokenReplayDetected => "refresh_token.replay_detected",
            Self::GrantRevoked => "grant.revoked",
            Self::TokenIssued => "token.issued",
            Self::ClientAuthenticationFailed => "client_authentication.failed",
            Self::TokenRevocationClientMismatch => "token_revocation.client_mismatch",
            Self::IssuerRegistered => "issuer.registered",
            Self::IssuerUpdated => "issuer.updated",
            Self::IssuerDisabled => "issuer.disabled",
            Self::IssuerEnabled => "issuer.enabled",
            Self::SubjectMapped => "issuer.subject_mapped",
            Self::SubjectUnmapped => "issuer.subject_unmapped",
            Self::AssertionRejected => "assertion.rejected",
        }
    }
}
