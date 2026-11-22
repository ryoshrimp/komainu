use ddd_toolkit::{AggregateRoot, Entity};
use time::OffsetDateTime;

use super::event::ConsentEvent;
use crate::{ClientId, ScopeSet, Subject};

/// Identifier of a [`Consent`]: one per (subject, client) pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConsentId {
    pub subject: Subject,
    pub client_id: ClientId,
}

/// The scopes a resource owner has granted to a client.
#[derive(Debug, Entity, AggregateRoot)]
pub struct Consent {
    #[entity(id)]
    id: ConsentId,
    scope: ScopeSet,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<ConsentEvent>,
}

/// Persistence form of [`Consent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRecord {
    pub id: ConsentId,
    pub scope: ScopeSet,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Consent {
    /// Records `ConsentEvent::Granted`.
    pub fn grant(
        subject: Subject,
        client_id: ClientId,
        scope: ScopeSet,
        now: OffsetDateTime,
    ) -> Consent {
        let mut consent = Consent {
            id: ConsentId { subject, client_id },
            scope,
            created_at: now,
            updated_at: now,
            events: Vec::new(),
        };
        consent.record_granted(now);
        consent
    }

    /// Adds scopes (union). Records `ConsentEvent::Granted` with the new full set.
    pub fn extend(&mut self, scope: &ScopeSet, now: OffsetDateTime) {
        self.scope = self.scope.union(scope);
        self.updated_at = now;
        self.record_granted(now);
    }

    /// `requested` is a subset of the granted scope.
    pub fn covers(&self, requested: &ScopeSet) -> bool {
        requested.is_subset(&self.scope)
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    fn record_granted(&mut self, now: OffsetDateTime) {
        self.record_event(ConsentEvent::Granted {
            subject: self.id.subject.clone(),
            client_id: self.id.client_id.clone(),
            scope: self.scope.clone(),
            occurred_at: now,
        });
    }

    pub fn to_record(&self) -> ConsentRecord {
        ConsentRecord {
            id: self.id.clone(),
            scope: self.scope.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Restores a consent from storage. Queues no events and does not validate.
    pub fn from_record(record: ConsentRecord) -> Self {
        Consent {
            id: record.id,
            scope: record.scope,
            created_at: record.created_at,
            updated_at: record.updated_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(s: &str) -> ScopeSet {
        ScopeSet::parse(s).unwrap()
    }

    #[test]
    fn covers_and_extend() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut consent = Consent::grant(
            Subject::try_new("u1".to_owned()).unwrap(),
            ClientId::try_new("c1".to_owned()).unwrap(),
            scopes("read"),
            now,
        );
        assert!(consent.covers(&scopes("read")));
        assert!(!consent.covers(&scopes("read write")));
        consent.extend(&scopes("write"), now);
        assert!(consent.covers(&scopes("read write")));
        let events = consent.pull_events();
        assert_eq!(events.len(), 2);
        let ConsentEvent::Granted { scope, .. } = &events[1];
        assert_eq!(scope.to_string(), "read write");
        assert_eq!(
            Consent::from_record(consent.to_record()).to_record(),
            consent.to_record()
        );
    }
}
