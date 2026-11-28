//! Repository traits. Every method takes `&mut self` because they all run inside
//! one transaction. Futures borrow only the repository, so adapters must copy
//! whatever they need from the arguments before the first `.await`.

use komainu_domain::{
    AccessToken, AuthorizationCode, AuthorizationRequest, AuthorizationRequestId, Client, ClientId,
    Consent, ExternalSubject, Grant, GrantId, IssuerId, LoginSession, RefreshToken,
    ServerSigningKey, SigningKeyId, Subject, SubjectMapping, TokenHash, TrustedIssuer, User,
    UserId, Username,
};
use time::OffsetDateTime;

use super::{BoxFuture, ListPage, PurgeCounts, StoreError};
use crate::audit::AuditEvent;

pub trait ClientRepository: Send {
    fn find(&mut self, id: &ClientId) -> BoxFuture<'_, Result<Option<Client>, StoreError>>;
    /// Takes a row lock.
    fn find_for_update(
        &mut self,
        id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Client>, StoreError>>;
    /// A duplicate ID is `Conflict`.
    fn insert(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>>;
    /// A missing row is `Other`.
    fn update(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>>;
    /// In ascending ID order.
    fn list(&mut self, page: &ListPage<ClientId>)
    -> BoxFuture<'_, Result<Vec<Client>, StoreError>>;
}

pub trait UserRepository: Send {
    fn find(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>>;
    /// Takes a row lock.
    fn find_for_update(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>>;
    fn find_by_username(
        &mut self,
        username: &Username,
    ) -> BoxFuture<'_, Result<Option<User>, StoreError>>;
    /// A duplicate username is `Conflict`.
    fn insert(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>>;
    /// In ascending username order.
    fn list(&mut self, page: &ListPage<Username>) -> BoxFuture<'_, Result<Vec<User>, StoreError>>;
}

pub trait LoginSessionRepository: Send {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<LoginSession>, StoreError>>;
    fn insert(&mut self, session: &LoginSession) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Not an error when the session does not exist.
    fn delete(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Returns the number of deleted sessions.
    fn delete_by_subject(&mut self, subject: &Subject) -> BoxFuture<'_, Result<u64, StoreError>>;
}

pub trait AuthorizationRequestRepository: Send {
    fn find_for_update(
        &mut self,
        id: AuthorizationRequestId,
    ) -> BoxFuture<'_, Result<Option<AuthorizationRequest>, StoreError>>;
    fn insert(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait AuthorizationCodeRepository: Send {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<AuthorizationCode>, StoreError>>;
    fn insert(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait ConsentRepository: Send {
    fn find(
        &mut self,
        subject: &Subject,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Consent>, StoreError>>;
    fn upsert(&mut self, consent: &Consent) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait GrantRepository: Send {
    fn find(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>>;
    /// Takes a row lock.
    fn find_for_update(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>>;
    fn insert(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Takes row locks.
    fn list_active_by_client(
        &mut self,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>>;
    /// Takes row locks.
    fn list_active_by_subject(
        &mut self,
        subject: &Subject,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>>;
}

pub trait AccessTokenRepository: Send {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<AccessToken>, StoreError>>;
    fn insert(&mut self, token: &AccessToken) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait RefreshTokenRepository: Send {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<RefreshToken>, StoreError>>;
    fn insert(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait AuditLogRepository: Send {
    fn append(&mut self, event: &AuditEvent) -> BoxFuture<'_, Result<(), StoreError>>;
}

pub trait PurgeRepository: Send {
    /// Deletes authorization requests, codes, access tokens, refresh tokens and login
    /// sessions with `expires_at <= cutoff`, then grants with `created_at <= cutoff` that no
    /// access token, refresh token or authorization code refers to. Used assertions are
    /// deleted when `expires_at < cutoff` (strictly before).
    fn purge_expired(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<PurgeCounts, StoreError>>;
    /// Deletes audit events with `occurred_at <= cutoff`.
    fn purge_audit_events(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<u64, StoreError>>;
}

pub trait TrustedIssuerRepository: Send {
    fn find(&mut self, id: &IssuerId) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>>;
    /// Like `find`, but takes a row lock until the unit of work ends.
    fn find_for_update(
        &mut self,
        id: &IssuerId,
    ) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>>;
    /// Returns `StoreError::Conflict` when the ID is taken.
    fn insert(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Replaces the issuer, including its allowed clients.
    fn update(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Issuers ordered by ID ascending.
    fn list(
        &mut self,
        page: &ListPage<IssuerId>,
    ) -> BoxFuture<'_, Result<Vec<TrustedIssuer>, StoreError>>;
}

pub trait SubjectMappingRepository: Send {
    fn find(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<Option<SubjectMapping>, StoreError>>;
    /// Inserts the mapping, or overwrites `user_id` and `updated_at` of the existing one.
    fn upsert(&mut self, mapping: &SubjectMapping) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Returns whether a mapping was deleted.
    fn delete(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<bool, StoreError>>;
    /// Mappings of one issuer ordered by subject ascending.
    fn list_by_issuer(
        &mut self,
        issuer_id: &IssuerId,
        page: &ListPage<ExternalSubject>,
    ) -> BoxFuture<'_, Result<Vec<SubjectMapping>, StoreError>>;
}

/// Where an assertion was presented. Part of the replay key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssertionKind {
    ClientAuthentication,
    AuthorizationGrant,
}

impl AssertionKind {
    /// The string stored in databases.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientAuthentication => "client_authentication",
            Self::AuthorizationGrant => "authorization_grant",
        }
    }
}

/// An assertion `jti` to remember until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedAssertion {
    pub kind: AssertionKind,
    /// The client ID for `ClientAuthentication`, the assertion's `iss` for
    /// `AuthorizationGrant`.
    pub issuer: String,
    /// The assertion's `jti` (1 to 255 bytes).
    pub jti: String,
    /// The assertion's `exp` plus `ASSERTION_LEEWAY`.
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded,
    Replayed,
}

pub trait UsedAssertionRepository: Send {
    /// Records `(kind, issuer, jti)`. Returns `Replayed` when it is already recorded,
    /// including expired records that are not purged yet. When units of work race on the
    /// same key, exactly one of them gets `Recorded`.
    fn record(
        &mut self,
        assertion: &UsedAssertion,
    ) -> BoxFuture<'_, Result<RecordOutcome, StoreError>>;
}

pub trait SigningKeyRepository: Send {
    /// Takes the exclusive rotation lock, held until the unit of work ends (commit or
    /// drop). Waits until it is available; there is no timeout (the database's
    /// `statement_timeout` applies).
    fn lock_rotation(&mut self) -> BoxFuture<'_, Result<(), StoreError>>;
    /// All keys in ascending `activates_at` order, then ascending `kid`.
    fn list(&mut self) -> BoxFuture<'_, Result<Vec<ServerSigningKey>, StoreError>>;
    /// A duplicate `kid` is `Conflict`.
    fn insert(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>>;
    /// Updates only `activates_at`, `retires_at` and `deletes_at`. A missing row is `Other`.
    fn update_schedule(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>>;
    /// `true` when a row was deleted, `false` when there was none.
    fn delete(&mut self, kid: &SigningKeyId) -> BoxFuture<'_, Result<bool, StoreError>>;
}
