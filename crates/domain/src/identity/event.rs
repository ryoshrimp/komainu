use ddd_toolkit::DomainEvent;
use time::OffsetDateTime;

use crate::UserId;

/// Events recorded by the `User` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum UserEvent {
    Created {
        user_id: UserId,
        occurred_at: OffsetDateTime,
    },
    PasswordChanged {
        user_id: UserId,
        occurred_at: OffsetDateTime,
    },
    Disabled {
        user_id: UserId,
        occurred_at: OffsetDateTime,
    },
    Enabled {
        user_id: UserId,
        occurred_at: OffsetDateTime,
    },
}
