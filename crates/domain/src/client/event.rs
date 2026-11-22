use ddd_toolkit::DomainEvent;
use time::OffsetDateTime;

use crate::ClientId;

/// Events recorded by the `Client` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum ClientEvent {
    Registered {
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    Updated {
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    SecretRotated {
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    Disabled {
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
    Enabled {
        client_id: ClientId,
        occurred_at: OffsetDateTime,
    },
}
