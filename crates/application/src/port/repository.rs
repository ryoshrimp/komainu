//! Repository traits. Every method takes `&mut self` because they all run inside
//! one transaction. Futures borrow only the repository, so adapters must copy
//! whatever they need from the arguments before the first `.await`.

use komainu_domain::{
    AccessToken, AuthorizationCode, AuthorizationRequest, AuthorizationRequestId, Client, ClientId,
    Consent, Grant, GrantId, LoginSession, RefreshToken, Subject, TokenHash, User, UserId,
    Username,
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
    /// access token, refresh token or authorization code refers to.
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
