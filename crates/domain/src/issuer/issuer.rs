use std::collections::BTreeSet;

use ddd_toolkit::{AggregateRoot, DomainEvent, Entity, ValueObject};
use time::OffsetDateTime;

use crate::error::DomainError;
use crate::{ClientId, JwksDocument};

/// Identifier matched exactly against the assertion's `iss` (1-255 bytes of 0x21-0x7E).
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_issuer_id, error = DomainError)]
pub struct IssuerId(String);

fn validate_issuer_id(value: &IssuerId) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 255 {
        return Err(DomainError::invalid(
            "issuer_id",
            "length must be 1 to 255 bytes",
        ));
    }
    if !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(DomainError::invalid("issuer_id", "invalid character"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IssuerStatus {
    Active,
    Disabled,
}

impl IssuerStatus {
    /// The string stored in databases and exchanged in wire formats.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl std::str::FromStr for IssuerStatus {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::invalid("issuer_status", "unknown value")),
        }
    }
}

/// Input of [`TrustedIssuer::register`].
#[derive(Debug, Clone)]
pub struct NewTrustedIssuer {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
}

/// Input of [`TrustedIssuer::update`]. `None` means "leave unchanged".
#[derive(Debug, Clone, Default)]
pub struct TrustedIssuerUpdate {
    pub jwks: Option<JwksDocument>,
    /// `Some` replaces the whole set.
    pub allowed_clients: Option<BTreeSet<ClientId>>,
}

/// Events recorded by the `TrustedIssuer` aggregate.
#[derive(Debug, Clone, PartialEq, Eq, DomainEvent)]
pub enum IssuerEvent {
    Registered {
        issuer_id: IssuerId,
        occurred_at: OffsetDateTime,
    },
    Updated {
        issuer_id: IssuerId,
        occurred_at: OffsetDateTime,
    },
    Disabled {
        issuer_id: IssuerId,
        occurred_at: OffsetDateTime,
    },
    Enabled {
        issuer_id: IssuerId,
        occurred_at: OffsetDateTime,
    },
}

/// An external issuer whose assertions are accepted.
#[derive(Debug, Entity, AggregateRoot)]
pub struct TrustedIssuer {
    #[entity(id)]
    id: IssuerId,
    jwks: JwksDocument,
    allowed_clients: BTreeSet<ClientId>,
    status: IssuerStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<IssuerEvent>,
}

/// Persistence form of [`TrustedIssuer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerRecord {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
    pub status: IssuerStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn check_allowed_clients(clients: &BTreeSet<ClientId>) -> Result<(), DomainError> {
    if !(1..=100).contains(&clients.len()) {
        return Err(DomainError::invalid(
            "allowed_clients",
            "must contain 1 to 100 clients",
        ));
    }
    Ok(())
}

impl TrustedIssuer {
    pub fn register(new: NewTrustedIssuer, now: OffsetDateTime) -> Result<Self, DomainError> {
        check_allowed_clients(&new.allowed_clients)?;
        let mut issuer = TrustedIssuer {
            id: new.id,
            jwks: new.jwks,
            allowed_clients: new.allowed_clients,
            status: IssuerStatus::Active,
            created_at: now,
            updated_at: now,
            events: Vec::new(),
        };
        let issuer_id = issuer.id.clone();
        issuer.record_event(IssuerEvent::Registered {
            issuer_id,
            occurred_at: now,
        });
        Ok(issuer)
    }

    pub fn update(
        &mut self,
        update: TrustedIssuerUpdate,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if let Some(clients) = &update.allowed_clients {
            check_allowed_clients(clients)?;
        }
        if let Some(jwks) = update.jwks {
            self.jwks = jwks;
        }
        if let Some(clients) = update.allowed_clients {
            self.allowed_clients = clients;
        }
        self.updated_at = now;
        let issuer_id = self.id.clone();
        self.record_event(IssuerEvent::Updated {
            issuer_id,
            occurred_at: now,
        });
        Ok(())
    }

    pub fn disable(&mut self, now: OffsetDateTime) {
        if self.status == IssuerStatus::Disabled {
            return;
        }
        self.status = IssuerStatus::Disabled;
        self.updated_at = now;
        let issuer_id = self.id.clone();
        self.record_event(IssuerEvent::Disabled {
            issuer_id,
            occurred_at: now,
        });
    }

    pub fn enable(&mut self, now: OffsetDateTime) {
        if self.status == IssuerStatus::Active {
            return;
        }
        self.status = IssuerStatus::Active;
        self.updated_at = now;
        let issuer_id = self.id.clone();
        self.record_event(IssuerEvent::Enabled {
            issuer_id,
            occurred_at: now,
        });
    }

    pub fn jwks(&self) -> &JwksDocument {
        &self.jwks
    }

    pub fn allowed_clients(&self) -> &BTreeSet<ClientId> {
        &self.allowed_clients
    }

    pub fn allows_client(&self, client_id: &ClientId) -> bool {
        self.allowed_clients.contains(client_id)
    }

    pub fn is_active(&self) -> bool {
        self.status == IssuerStatus::Active
    }

    pub fn status(&self) -> IssuerStatus {
        self.status
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn to_record(&self) -> TrustedIssuerRecord {
        TrustedIssuerRecord {
            id: self.id.clone(),
            jwks: self.jwks.clone(),
            allowed_clients: self.allowed_clients.clone(),
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Restores an issuer from storage. Queues no events and does not validate.
    pub fn from_record(record: TrustedIssuerRecord) -> Self {
        TrustedIssuer {
            id: record.id,
            jwks: record.jwks,
            allowed_clients: record.allowed_clients,
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

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn cid(n: usize) -> ClientId {
        ClientId::try_new(format!("c{n}")).unwrap()
    }

    fn new_issuer(clients: usize) -> NewTrustedIssuer {
        NewTrustedIssuer {
            id: IssuerId::try_new("https://idp.example.com".to_owned()).unwrap(),
            jwks: JwksDocument::try_new("{\"keys\":[]}".to_owned()).unwrap(),
            allowed_clients: (0..clients).map(cid).collect(),
        }
    }

    #[test]
    fn issuer_id_rules() {
        assert!(IssuerId::try_new("https://idp.example.com/".to_owned()).is_ok());
        assert!(IssuerId::try_new(String::new()).is_err());
        assert!(IssuerId::try_new("a".repeat(255)).is_ok());
        assert!(IssuerId::try_new("a".repeat(256)).is_err());
        assert!(IssuerId::try_new("a b".to_owned()).is_err());
        assert!(IssuerId::try_new("a\tb".to_owned()).is_err());
        assert!(IssuerId::try_new("あ".to_owned()).is_err());
    }

    #[test]
    fn status_round_trips() {
        for s in [IssuerStatus::Active, IssuerStatus::Disabled] {
            assert_eq!(s.as_str().parse::<IssuerStatus>(), Ok(s));
        }
        assert!("x".parse::<IssuerStatus>().is_err());
    }

    #[test]
    fn register_checks_allowed_clients_count() {
        assert!(TrustedIssuer::register(new_issuer(0), now()).is_err());
        assert!(TrustedIssuer::register(new_issuer(101), now()).is_err());
        assert!(TrustedIssuer::register(new_issuer(1), now()).is_ok());
        assert!(TrustedIssuer::register(new_issuer(100), now()).is_ok());
    }

    #[test]
    fn register_records_event_and_allows_listed_clients() {
        let mut issuer = TrustedIssuer::register(new_issuer(2), now()).unwrap();
        assert!(matches!(
            issuer.pull_events().as_slice(),
            [IssuerEvent::Registered { .. }]
        ));
        assert!(issuer.is_active());
        assert!(issuer.allows_client(&cid(0)));
        assert!(issuer.allows_client(&cid(1)));
        assert!(!issuer.allows_client(&cid(2)));
    }

    #[test]
    fn update_replaces_fields_and_validates() {
        let mut issuer = TrustedIssuer::register(new_issuer(1), now()).unwrap();
        issuer.pull_events();
        let before = issuer.to_record();
        for n in [0, 101] {
            let bad = TrustedIssuerUpdate {
                allowed_clients: Some((0..n).map(cid).collect()),
                ..Default::default()
            };
            assert!(issuer.update(bad, now()).is_err());
        }
        assert_eq!(issuer.to_record(), before);
        assert!(issuer.pull_events().is_empty());

        let good = TrustedIssuerUpdate {
            jwks: Some(JwksDocument::try_new("{}".to_owned()).unwrap()),
            allowed_clients: Some([cid(5)].into()),
        };
        issuer.update(good, now()).unwrap();
        assert_eq!(issuer.jwks().as_str(), "{}");
        assert!(issuer.allows_client(&cid(5)));
        assert!(!issuer.allows_client(&cid(0)));
        assert!(matches!(
            issuer.pull_events().as_slice(),
            [IssuerEvent::Updated { .. }]
        ));
    }

    #[test]
    fn disable_and_enable_are_idempotent() {
        let mut issuer = TrustedIssuer::register(new_issuer(1), now()).unwrap();
        issuer.pull_events();
        issuer.enable(now());
        assert!(issuer.pull_events().is_empty());
        issuer.disable(now());
        issuer.disable(now());
        assert_eq!(issuer.status(), IssuerStatus::Disabled);
        assert!(!issuer.is_active());
        assert!(matches!(
            issuer.pull_events().as_slice(),
            [IssuerEvent::Disabled { .. }]
        ));
        issuer.enable(now());
        issuer.enable(now());
        assert!(issuer.is_active());
        assert!(matches!(
            issuer.pull_events().as_slice(),
            [IssuerEvent::Enabled { .. }]
        ));
    }

    #[test]
    fn record_round_trip() {
        let issuer = TrustedIssuer::register(new_issuer(3), now()).unwrap();
        let restored = TrustedIssuer::from_record(issuer.to_record());
        assert_eq!(restored.to_record(), issuer.to_record());
    }
}
