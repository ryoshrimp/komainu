use std::str::FromStr;

use ddd_toolkit::{AggregateRoot, Entity};
use time::OffsetDateTime;

use super::event::UserEvent;
use crate::error::DomainError;
use crate::{PasswordHash, Subject, UserId, Username};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    /// The string stored in databases and exchanged in wire formats.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl FromStr for UserStatus {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::invalid("user_status", "unknown value")),
        }
    }
}

/// A built-in resource owner.
#[derive(Debug, Entity, AggregateRoot)]
pub struct User {
    #[entity(id)]
    id: UserId,
    username: Username,
    password_hash: PasswordHash,
    status: UserStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<UserEvent>,
}

/// Persistence form of [`User`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: UserId,
    pub username: Username,
    pub password_hash: PasswordHash,
    pub status: UserStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl User {
    pub fn create(
        id: UserId,
        username: Username,
        password_hash: PasswordHash,
        now: OffsetDateTime,
    ) -> User {
        let mut user = User {
            id,
            username,
            password_hash,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
            events: Vec::new(),
        };
        user.record_event(UserEvent::Created {
            user_id: id,
            occurred_at: now,
        });
        user
    }

    pub fn change_password(&mut self, new_hash: PasswordHash, now: OffsetDateTime) {
        self.password_hash = new_hash;
        self.updated_at = now;
        self.record_event(UserEvent::PasswordChanged {
            user_id: self.id,
            occurred_at: now,
        });
    }

    /// Idempotent.
    pub fn disable(&mut self, now: OffsetDateTime) {
        if self.status == UserStatus::Disabled {
            return;
        }
        self.status = UserStatus::Disabled;
        self.updated_at = now;
        self.record_event(UserEvent::Disabled {
            user_id: self.id,
            occurred_at: now,
        });
    }

    /// Idempotent.
    pub fn enable(&mut self, now: OffsetDateTime) {
        if self.status == UserStatus::Active {
            return;
        }
        self.status = UserStatus::Active;
        self.updated_at = now;
        self.record_event(UserEvent::Enabled {
            user_id: self.id,
            occurred_at: now,
        });
    }

    pub fn username(&self) -> &Username {
        &self.username
    }

    pub fn password_hash(&self) -> &PasswordHash {
        &self.password_hash
    }

    pub fn subject(&self) -> Subject {
        Subject::from(self.id)
    }

    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn to_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            username: self.username.clone(),
            password_hash: self.password_hash.clone(),
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Restores a user from storage. Queues no events and does not validate.
    pub fn from_record(record: UserRecord) -> Self {
        User {
            id: record.id,
            username: record.username,
            password_hash: record.password_hash,
            status: record.status,
            created_at: record.created_at,
            updated_at: record.updated_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User::create(
            UserId::new(uuid::Uuid::from_u128(1)),
            Username::try_new("Alice".to_owned()).unwrap(),
            PasswordHash::try_new("$argon2id$x".to_owned()).unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn lifecycle_events() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut user = user();
        assert!(matches!(
            user.pull_events().as_slice(),
            [UserEvent::Created { .. }]
        ));
        user.change_password(
            PasswordHash::try_new("$argon2id$y".to_owned()).unwrap(),
            now,
        );
        assert_eq!(user.password_hash().as_inner(), "$argon2id$y");
        user.disable(now);
        user.disable(now);
        assert!(!user.is_active());
        user.enable(now);
        user.enable(now);
        assert!(user.is_active());
        let events = user.pull_events();
        assert!(matches!(
            events.as_slice(),
            [
                UserEvent::PasswordChanged { .. },
                UserEvent::Disabled { .. },
                UserEvent::Enabled { .. }
            ]
        ));
    }

    #[test]
    fn subject_and_record() {
        let user = user();
        assert_eq!(
            user.subject().as_inner(),
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(user.username().as_str(), "alice");
        let restored = User::from_record(user.to_record());
        assert_eq!(restored.to_record(), user.to_record());
    }
}
