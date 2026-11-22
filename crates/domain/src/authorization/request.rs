use std::str::FromStr;

use ddd_toolkit::{AggregateRoot, Entity};
use time::{Duration, OffsetDateTime};

use super::event::AuthorizationRequestEvent;
use crate::error::DomainError;
use crate::{
    AuthorizationRequestId, ClientId, OpaqueToken, RedirectUri, ScopeSet, State, Subject, TokenHash,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthorizationRequestStatus {
    Pending,
    Approved,
    Denied,
}

impl AuthorizationRequestStatus {
    /// The string stored in databases and exchanged in wire formats.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

impl FromStr for AuthorizationRequestStatus {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            _ => Err(DomainError::invalid(
                "authorization_request_status",
                "unknown value",
            )),
        }
    }
}

/// Input of [`AuthorizationRequest::create`].
#[derive(Debug, Clone)]
pub struct NewAuthorizationRequest {
    pub id: AuthorizationRequestId,
    pub client_id: ClientId,
    /// Resolved by `Client::resolve_redirect_uri`.
    pub redirect_uri: RedirectUri,
    /// Whether redirect_uri was in the request (§4.1.3).
    pub redirect_uri_provided: bool,
    /// Resolved by `Client::resolve_scope`.
    pub scope: ScopeSet,
    pub state: Option<State>,
    pub csrf_token_hash: TokenHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationRequestError {
    NotPending,
    Expired,
}

/// A validated authorization request held until login and consent finish.
#[derive(Debug, Entity, AggregateRoot)]
pub struct AuthorizationRequest {
    #[entity(id)]
    id: AuthorizationRequestId,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    redirect_uri_provided: bool,
    scope: ScopeSet,
    state: Option<State>,
    csrf_token_hash: TokenHash,
    status: AuthorizationRequestStatus,
    subject: Option<Subject>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<AuthorizationRequestEvent>,
}

/// Persistence form of [`AuthorizationRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequestRecord {
    pub id: AuthorizationRequestId,
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub redirect_uri_provided: bool,
    pub scope: ScopeSet,
    pub state: Option<State>,
    pub csrf_token_hash: TokenHash,
    pub status: AuthorizationRequestStatus,
    pub subject: Option<Subject>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl AuthorizationRequest {
    pub fn create(
        new: NewAuthorizationRequest,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> AuthorizationRequest {
        AuthorizationRequest {
            id: new.id,
            client_id: new.client_id,
            redirect_uri: new.redirect_uri,
            redirect_uri_provided: new.redirect_uri_provided,
            scope: new.scope,
            state: new.state,
            csrf_token_hash: new.csrf_token_hash,
            status: AuthorizationRequestStatus::Pending,
            subject: None,
            created_at: now,
            updated_at: now,
            expires_at: now + ttl,
            events: Vec::new(),
        }
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn redirect_uri(&self) -> &RedirectUri {
        &self.redirect_uri
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    pub fn status(&self) -> AuthorizationRequestStatus {
        self.status
    }

    pub fn subject(&self) -> Option<&Subject> {
        self.subject.as_ref()
    }

    /// Whether the request carried a redirect_uri (needed by `AuthorizationCode::issue`).
    pub(super) fn redirect_uri_provided(&self) -> bool {
        self.redirect_uri_provided
    }

    /// `now >= expires_at`.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// Constant-time.
    pub fn verify_csrf(&self, presented: &OpaqueToken) -> bool {
        self.csrf_token_hash.ct_eq(&presented.hash())
    }

    pub fn approve(
        &mut self,
        subject: Subject,
        now: OffsetDateTime,
    ) -> Result<(), AuthorizationRequestError> {
        self.decide(subject, now, AuthorizationRequestStatus::Approved)
    }

    pub fn deny(
        &mut self,
        subject: Subject,
        now: OffsetDateTime,
    ) -> Result<(), AuthorizationRequestError> {
        self.decide(subject, now, AuthorizationRequestStatus::Denied)
    }

    fn decide(
        &mut self,
        subject: Subject,
        now: OffsetDateTime,
        status: AuthorizationRequestStatus,
    ) -> Result<(), AuthorizationRequestError> {
        if self.status != AuthorizationRequestStatus::Pending {
            return Err(AuthorizationRequestError::NotPending);
        }
        if self.is_expired(now) {
            return Err(AuthorizationRequestError::Expired);
        }
        self.status = status;
        self.subject = Some(subject.clone());
        self.updated_at = now;
        let (request_id, client_id, scope, occurred_at) =
            (self.id, self.client_id.clone(), self.scope.clone(), now);
        self.record_event(if status == AuthorizationRequestStatus::Approved {
            AuthorizationRequestEvent::Approved {
                request_id,
                client_id,
                subject,
                scope,
                occurred_at,
            }
        } else {
            AuthorizationRequestEvent::Denied {
                request_id,
                client_id,
                subject,
                scope,
                occurred_at,
            }
        });
        Ok(())
    }

    pub fn to_record(&self) -> AuthorizationRequestRecord {
        AuthorizationRequestRecord {
            id: self.id,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            redirect_uri_provided: self.redirect_uri_provided,
            scope: self.scope.clone(),
            state: self.state.clone(),
            csrf_token_hash: self.csrf_token_hash,
            status: self.status,
            subject: self.subject.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
        }
    }

    /// Restores a request from storage. Queues no events and does not validate.
    pub fn from_record(record: AuthorizationRequestRecord) -> Self {
        AuthorizationRequest {
            id: record.id,
            client_id: record.client_id,
            redirect_uri: record.redirect_uri,
            redirect_uri_provided: record.redirect_uri_provided,
            scope: record.scope,
            state: record.state,
            csrf_token_hash: record.csrf_token_hash,
            status: record.status,
            subject: record.subject,
            created_at: record.created_at,
            updated_at: record.updated_at,
            expires_at: record.expires_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::Secret;

    pub fn token(s: &str) -> OpaqueToken {
        OpaqueToken::try_new(Secret::new(s.to_owned())).unwrap()
    }

    pub fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    pub fn request(provided: bool) -> AuthorizationRequest {
        AuthorizationRequest::create(
            NewAuthorizationRequest {
                id: AuthorizationRequestId::new(uuid::Uuid::from_u128(1)),
                client_id: ClientId::try_new("c1".to_owned()).unwrap(),
                redirect_uri: RedirectUri::try_new("https://a.example/cb".to_owned()).unwrap(),
                redirect_uri_provided: provided,
                scope: ScopeSet::parse("read").unwrap(),
                state: Some(State::try_new("xyz".to_owned()).unwrap()),
                csrf_token_hash: token("csrf").hash(),
            },
            t0(),
            Duration::seconds(600),
        )
    }

    pub fn subject() -> Subject {
        Subject::try_new("u1".to_owned()).unwrap()
    }

    #[test]
    fn approve_and_deny_once() {
        let mut req = request(true);
        assert_eq!(req.status(), AuthorizationRequestStatus::Pending);
        req.approve(subject(), t0()).unwrap();
        assert_eq!(req.status(), AuthorizationRequestStatus::Approved);
        assert_eq!(req.subject(), Some(&subject()));
        assert_eq!(
            req.deny(subject(), t0()),
            Err(AuthorizationRequestError::NotPending)
        );
        assert!(matches!(
            req.pull_events().as_slice(),
            [AuthorizationRequestEvent::Approved { .. }]
        ));

        let mut req = request(true);
        req.deny(subject(), t0()).unwrap();
        assert!(matches!(
            req.pull_events().as_slice(),
            [AuthorizationRequestEvent::Denied { .. }]
        ));
    }

    #[test]
    fn expiry_boundary_and_priority() {
        let mut req = request(true);
        let expiry = t0() + Duration::seconds(600);
        assert!(!req.is_expired(expiry - Duration::seconds(1)));
        assert!(req.is_expired(expiry));
        assert_eq!(
            req.approve(subject(), expiry),
            Err(AuthorizationRequestError::Expired)
        );
        assert_eq!(req.status(), AuthorizationRequestStatus::Pending);

        req.approve(subject(), t0()).unwrap();
        // Both not pending and expired: NotPending wins.
        assert_eq!(
            req.approve(subject(), expiry),
            Err(AuthorizationRequestError::NotPending)
        );
    }

    #[test]
    fn csrf_check() {
        let req = request(true);
        assert!(req.verify_csrf(&token("csrf")));
        assert!(!req.verify_csrf(&token("csrg")));
    }
}
