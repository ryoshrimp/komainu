use ddd_toolkit::DomainEvent;
use time::OffsetDateTime;

use super::grant::RevocationReason;
use crate::{ClientId, GrantId, ScopeSet, Subject};

/// Events recorded by the `Grant` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum GrantEvent {
    Created {
        grant_id: GrantId,
        client_id: ClientId,
        subject: Option<Subject>,
        scope: ScopeSet,
        /// `"authorization_code"` or `"client_credentials"`.
        origin: &'static str,
    },
    Revoked {
        grant_id: GrantId,
        reason: RevocationReason,
    },
}

/// Events recorded by the `AccessToken` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum AccessTokenEvent {
    Issued {
        grant_id: GrantId,
        client_id: ClientId,
        subject: Option<Subject>,
        scope: ScopeSet,
        expires_at: OffsetDateTime,
    },
}

/// Events recorded by the `RefreshToken` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum RefreshTokenEvent {
    Issued {
        grant_id: GrantId,
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    Rotated {
        grant_id: GrantId,
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    ReplayDetected {
        grant_id: GrantId,
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
}
