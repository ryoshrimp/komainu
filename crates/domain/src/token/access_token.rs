use ddd_toolkit::{AggregateRoot, Entity};
use time::{Duration, OffsetDateTime};

use super::event::AccessTokenEvent;
use crate::error::DomainError;
use crate::{ClientId, Grant, GrantId, ScopeSet, Subject, TokenHash};

/// An access token. Its id is the SHA-256 of the token.
#[derive(Debug, Entity, AggregateRoot)]
pub struct AccessToken {
    #[entity(id)]
    id: TokenHash,
    grant_id: GrantId,
    client_id: ClientId,
    subject: Option<Subject>,
    scope: ScopeSet,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<AccessTokenEvent>,
}

/// Persistence form of [`AccessToken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub id: TokenHash,
    pub grant_id: GrantId,
    pub client_id: ClientId,
    pub subject: Option<Subject>,
    pub scope: ScopeSet,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl AccessToken {
    /// `scope` must be a subset of `grant.scope()` and the grant must be active;
    /// otherwise `InvalidState`.
    pub fn issue(
        token_hash: TokenHash,
        grant: &Grant,
        scope: ScopeSet,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> Result<AccessToken, DomainError> {
        if !grant.is_active() {
            return Err(DomainError::InvalidState("grant is revoked"));
        }
        if !scope.is_subset(grant.scope()) {
            return Err(DomainError::InvalidState("scope exceeds the grant"));
        }
        let mut token = AccessToken {
            id: token_hash,
            grant_id: *grant.id(),
            client_id: grant.client_id().clone(),
            subject: grant.subject().cloned(),
            scope,
            issued_at: now,
            expires_at: now + ttl,
            events: Vec::new(),
        };
        token.record_event(AccessTokenEvent::Issued {
            grant_id: token.grant_id,
            client_id: token.client_id.clone(),
            subject: token.subject.clone(),
            scope: token.scope.clone(),
            expires_at: token.expires_at,
        });
        Ok(token)
    }

    pub fn grant_id(&self) -> GrantId {
        self.grant_id
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn subject(&self) -> Option<&Subject> {
        self.subject.as_ref()
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// `now < expires_at`.
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }

    pub fn to_record(&self) -> AccessTokenRecord {
        AccessTokenRecord {
            id: self.id,
            grant_id: self.grant_id,
            client_id: self.client_id.clone(),
            subject: self.subject.clone(),
            scope: self.scope.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    /// Restores a token from storage. Queues no events and does not validate.
    pub fn from_record(record: AccessTokenRecord) -> Self {
        AccessToken {
            id: record.id,
            grant_id: record.grant_id,
            client_id: record.client_id,
            subject: record.subject,
            scope: record.scope,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::RevocationReason;

    const HASH: TokenHash = TokenHash::from_bytes([9; 32]);

    #[test]
    fn issue_and_validity_boundary() {
        let grant = code_grant();
        let mut token =
            AccessToken::issue(HASH, &grant, scopes("read"), t0(), Duration::seconds(3600))
                .unwrap();
        assert!(token.is_valid_at(t0() + Duration::seconds(3599)));
        assert!(!token.is_valid_at(t0() + Duration::seconds(3600)));
        assert_eq!(token.grant_id(), gid(1));
        assert_eq!(token.subject(), grant.subject());
        assert!(matches!(
            token.pull_events().as_slice(),
            [AccessTokenEvent::Issued { .. }]
        ));
        assert_eq!(
            AccessToken::from_record(token.to_record()).to_record(),
            token.to_record()
        );
    }

    #[test]
    fn revoked_grant_is_rejected() {
        let mut grant = code_grant();
        grant.revoke(RevocationReason::ClientDisabled, t0());
        let result = AccessToken::issue(HASH, &grant, scopes("read"), t0(), Duration::seconds(60));
        assert!(matches!(result, Err(DomainError::InvalidState(_))));
    }

    #[test]
    fn scope_must_be_subset_of_grant() {
        let grant = code_grant();
        let result = AccessToken::issue(HASH, &grant, scopes("admin"), t0(), Duration::seconds(60));
        assert!(matches!(result, Err(DomainError::InvalidState(_))));
    }
}
