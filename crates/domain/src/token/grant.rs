use ddd_toolkit::{AggregateRoot, Entity};
use time::OffsetDateTime;

use super::event::GrantEvent;
use crate::{AuthorizationCode, ClientId, GrantId, ScopeSet, Subject, TokenHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOrigin {
    AuthorizationCode { code_hash: TokenHash },
    ClientCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    CodeReplay,
    RefreshTokenReplay,
    ClientDisabled,
    UserDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Active,
    Revoked {
        revoked_at: OffsetDateTime,
        reason: RevocationReason,
    },
}

/// The authority a client holds; tokens are valid only while their grant is active.
#[derive(Debug, Entity, AggregateRoot)]
pub struct Grant {
    #[entity(id)]
    id: GrantId,
    client_id: ClientId,
    subject: Option<Subject>,
    scope: ScopeSet,
    origin: GrantOrigin,
    status: GrantStatus,
    created_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<GrantEvent>,
}

/// Persistence form of [`Grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub id: GrantId,
    pub client_id: ClientId,
    pub subject: Option<Subject>,
    pub scope: ScopeSet,
    pub origin: GrantOrigin,
    pub status: GrantStatus,
    pub created_at: OffsetDateTime,
}

impl Grant {
    pub fn from_authorization_code(
        id: GrantId,
        code: &AuthorizationCode,
        now: OffsetDateTime,
    ) -> Grant {
        Self::create(
            id,
            code.client_id().clone(),
            Some(code.subject().clone()),
            code.scope().clone(),
            GrantOrigin::AuthorizationCode {
                code_hash: *code.id(),
            },
            now,
        )
    }

    pub fn for_client_credentials(
        id: GrantId,
        client_id: ClientId,
        scope: ScopeSet,
        now: OffsetDateTime,
    ) -> Grant {
        Self::create(
            id,
            client_id,
            None,
            scope,
            GrantOrigin::ClientCredentials,
            now,
        )
    }

    fn create(
        id: GrantId,
        client_id: ClientId,
        subject: Option<Subject>,
        scope: ScopeSet,
        origin: GrantOrigin,
        now: OffsetDateTime,
    ) -> Grant {
        let mut grant = Grant {
            id,
            client_id,
            subject,
            scope,
            origin,
            status: GrantStatus::Active,
            created_at: now,
            events: Vec::new(),
        };
        grant.record_event(GrantEvent::Created {
            grant_id: id,
            client_id: grant.client_id.clone(),
            subject: grant.subject.clone(),
            scope: grant.scope.clone(),
            origin: match origin {
                GrantOrigin::AuthorizationCode { .. } => "authorization_code",
                GrantOrigin::ClientCredentials => "client_credentials",
            },
        });
        grant
    }

    /// Idempotent: no-op (no event) when already revoked.
    pub fn revoke(&mut self, reason: RevocationReason, now: OffsetDateTime) {
        if !self.is_active() {
            return;
        }
        self.status = GrantStatus::Revoked {
            revoked_at: now,
            reason,
        };
        self.record_event(GrantEvent::Revoked {
            grant_id: self.id,
            reason,
        });
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// `None` for client_credentials grants.
    pub fn subject(&self) -> Option<&Subject> {
        self.subject.as_ref()
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn is_active(&self) -> bool {
        self.status == GrantStatus::Active
    }

    pub fn to_record(&self) -> GrantRecord {
        GrantRecord {
            id: self.id,
            client_id: self.client_id.clone(),
            subject: self.subject.clone(),
            scope: self.scope.clone(),
            origin: self.origin,
            status: self.status,
            created_at: self.created_at,
        }
    }

    /// Restores a grant from storage. Queues no events and does not validate.
    pub fn from_record(record: GrantRecord) -> Self {
        Grant {
            id: record.id,
            client_id: record.client_id,
            subject: record.subject,
            scope: record.scope,
            origin: record.origin,
            status: record.status,
            created_at: record.created_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;

    #[test]
    fn created_events_name_the_origin() {
        let mut grant = code_grant();
        assert!(matches!(
            grant.pull_events().as_slice(),
            [GrantEvent::Created {
                origin: "authorization_code",
                subject: Some(_),
                ..
            }]
        ));
        assert!(
            matches!(grant.origin, GrantOrigin::AuthorizationCode { code_hash } if code_hash == TokenHash::from_bytes([2; 32]))
        );

        let mut cc = Grant::for_client_credentials(gid(2), cid(), scopes("read"), t0());
        assert!(cc.subject().is_none());
        assert!(matches!(
            cc.pull_events().as_slice(),
            [GrantEvent::Created {
                origin: "client_credentials",
                subject: None,
                ..
            }]
        ));
    }

    #[test]
    fn revoke_twice_records_one_event() {
        let mut grant = code_grant();
        grant.pull_events();
        grant.revoke(RevocationReason::CodeReplay, t0());
        grant.revoke(RevocationReason::UserDisabled, t0());
        assert!(!grant.is_active());
        assert_eq!(
            grant.pull_events(),
            vec![GrantEvent::Revoked {
                grant_id: gid(1),
                reason: RevocationReason::CodeReplay
            }]
        );
        assert_eq!(
            Grant::from_record(grant.to_record()).to_record(),
            grant.to_record()
        );
    }
}
