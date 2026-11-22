use ddd_toolkit::DomainEvent;
use time::OffsetDateTime;

use crate::{AuthorizationRequestId, ClientId, GrantId, ScopeSet, Subject};

/// Events recorded by the `AuthorizationRequest` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum AuthorizationRequestEvent {
    Approved {
        request_id: AuthorizationRequestId,
        client_id: ClientId,
        subject: Subject,
        scope: ScopeSet,
        occurred_at: OffsetDateTime,
    },
    Denied {
        request_id: AuthorizationRequestId,
        client_id: ClientId,
        subject: Subject,
        scope: ScopeSet,
        occurred_at: OffsetDateTime,
    },
}

/// Events recorded by the `AuthorizationCode` aggregate. They never carry the
/// code or its hash.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum AuthorizationCodeEvent {
    Issued {
        client_id: ClientId,
        subject: Subject,
        occurred_at: OffsetDateTime,
    },
    Redeemed {
        client_id: ClientId,
        subject: Subject,
        grant_id: GrantId,
        occurred_at: OffsetDateTime,
    },
    ReplayDetected {
        client_id: ClientId,
        subject: Subject,
        grant_id: GrantId,
        occurred_at: OffsetDateTime,
    },
}

/// Events recorded by the `Consent` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum ConsentEvent {
    Granted {
        subject: Subject,
        client_id: ClientId,
        scope: ScopeSet,
        occurred_at: OffsetDateTime,
    },
}
