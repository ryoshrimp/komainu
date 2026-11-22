use ddd_toolkit::{AggregateRoot, Entity};
use time::{Duration, OffsetDateTime};

use super::event::RefreshTokenEvent;
use crate::error::DomainError;
use crate::{ClientId, Grant, GrantId, TokenHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTokenStatus {
    Active,
    Rotated { rotated_at: OffsetDateTime },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateRefreshTokenError {
    /// Already rotated: the caller must revoke the grant.
    Replayed {
        grant_id: GrantId,
    },
    ClientMismatch,
    Expired,
}

/// A refresh token. Its id is the SHA-256 of the token.
/// Its scope is always the grant's, so it is not stored here.
#[derive(Debug, Entity, AggregateRoot)]
pub struct RefreshToken {
    #[entity(id)]
    id: TokenHash,
    grant_id: GrantId,
    client_id: ClientId,
    status: RefreshTokenStatus,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<RefreshTokenEvent>,
}

/// Persistence form of [`RefreshToken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub id: TokenHash,
    pub grant_id: GrantId,
    pub client_id: ClientId,
    pub status: RefreshTokenStatus,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl RefreshToken {
    /// The grant must be active; otherwise `InvalidState`.
    pub fn issue(
        token_hash: TokenHash,
        grant: &Grant,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> Result<RefreshToken, DomainError> {
        if !grant.is_active() {
            return Err(DomainError::InvalidState("grant is revoked"));
        }
        let mut token = RefreshToken {
            id: token_hash,
            grant_id: *grant.id(),
            client_id: grant.client_id().clone(),
            status: RefreshTokenStatus::Active,
            issued_at: now,
            expires_at: now + ttl,
            events: Vec::new(),
        };
        token.record_event(RefreshTokenEvent::Issued {
            grant_id: token.grant_id,
            client_id: token.client_id.clone(),
            occurred_at: now,
        });
        Ok(token)
    }

    pub fn grant_id(&self) -> GrantId {
        self.grant_id
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn rotate(
        &mut self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), RotateRefreshTokenError> {
        if matches!(self.status, RefreshTokenStatus::Rotated { .. }) {
            self.record_event(RefreshTokenEvent::ReplayDetected {
                grant_id: self.grant_id,
                client_id: self.client_id.clone(),
                occurred_at: now,
            });
            return Err(RotateRefreshTokenError::Replayed {
                grant_id: self.grant_id,
            });
        }
        if *client_id != self.client_id {
            return Err(RotateRefreshTokenError::ClientMismatch);
        }
        if now >= self.expires_at {
            return Err(RotateRefreshTokenError::Expired);
        }
        self.status = RefreshTokenStatus::Rotated { rotated_at: now };
        self.record_event(RefreshTokenEvent::Rotated {
            grant_id: self.grant_id,
            client_id: self.client_id.clone(),
            occurred_at: now,
        });
        Ok(())
    }

    pub fn to_record(&self) -> RefreshTokenRecord {
        RefreshTokenRecord {
            id: self.id,
            grant_id: self.grant_id,
            client_id: self.client_id.clone(),
            status: self.status,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    /// Restores a token from storage. Queues no events and does not validate.
    pub fn from_record(record: RefreshTokenRecord) -> Self {
        RefreshToken {
            id: record.id,
            grant_id: record.grant_id,
            client_id: record.client_id,
            status: record.status,
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

    const HASH: TokenHash = TokenHash::from_bytes([8; 32]);

    fn issued() -> RefreshToken {
        RefreshToken::issue(HASH, &code_grant(), t0(), Duration::seconds(100)).unwrap()
    }

    #[test]
    fn issue_requires_active_grant() {
        let mut grant = code_grant();
        grant.revoke(RevocationReason::UserDisabled, t0());
        let result = RefreshToken::issue(HASH, &grant, t0(), Duration::seconds(100));
        assert!(matches!(result, Err(DomainError::InvalidState(_))));
    }

    #[test]
    fn rotate_once_then_replay() {
        let mut token = issued();
        token.pull_events();
        token.rotate(&cid(), t0()).unwrap();
        assert_eq!(
            token.rotate(&cid(), t0()),
            Err(RotateRefreshTokenError::Replayed { grant_id: gid(1) })
        );
        assert!(matches!(
            token.pull_events().as_slice(),
            [
                RefreshTokenEvent::Rotated { .. },
                RefreshTokenEvent::ReplayDetected { .. }
            ]
        ));
        assert_eq!(
            RefreshToken::from_record(token.to_record()).to_record(),
            token.to_record()
        );
    }

    #[test]
    fn client_and_expiry_checks() {
        let other = ClientId::try_new("c2".to_owned()).unwrap();
        let mut token = issued();
        assert_eq!(
            token.rotate(&other, t0()),
            Err(RotateRefreshTokenError::ClientMismatch)
        );
        assert_eq!(
            token.rotate(&cid(), t0() + Duration::seconds(100)),
            Err(RotateRefreshTokenError::Expired)
        );
        // Client mismatch is checked before expiry.
        assert_eq!(
            token.rotate(&other, t0() + Duration::seconds(100)),
            Err(RotateRefreshTokenError::ClientMismatch)
        );
        assert_eq!(token.rotate(&cid(), t0() + Duration::seconds(99)), Ok(()));
    }
}
