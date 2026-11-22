use ddd_toolkit::Entity;
use time::{Duration, OffsetDateTime};

use crate::{Subject, TokenHash};

/// A login session of a resource owner. Its id is the hash of the cookie value.
#[derive(Debug, Entity)]
pub struct LoginSession {
    #[entity(id)]
    id: TokenHash,
    subject: Subject,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// Persistence form of [`LoginSession`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSessionRecord {
    pub id: TokenHash,
    pub subject: Subject,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl LoginSession {
    /// id is the hash of the session cookie value.
    pub fn start(
        id: TokenHash,
        subject: Subject,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> LoginSession {
        LoginSession {
            id,
            subject,
            created_at: now,
            expires_at: now + ttl,
        }
    }

    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// `now < expires_at`.
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }

    pub fn to_record(&self) -> LoginSessionRecord {
        LoginSessionRecord {
            id: self.id,
            subject: self.subject.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }

    pub fn from_record(record: LoginSessionRecord) -> Self {
        LoginSession {
            id: record.id,
            subject: record.subject,
            created_at: record.created_at,
            expires_at: record.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_until_expiry_boundary() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let session = LoginSession::start(
            TokenHash::from_bytes([0; 32]),
            Subject::try_new("u".to_owned()).unwrap(),
            t,
            Duration::seconds(60),
        );
        assert!(session.is_valid_at(t + Duration::seconds(59)));
        assert!(!session.is_valid_at(t + Duration::seconds(60)));
        assert_eq!(
            LoginSession::from_record(session.to_record()).to_record(),
            session.to_record()
        );
    }
}
