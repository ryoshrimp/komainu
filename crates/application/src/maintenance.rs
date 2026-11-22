//! Housekeeping: purging expired data and readiness checks.

use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::port::{PurgeCounts, StoreError};

/// Number of rows removed by [`MaintenanceService::purge_expired`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    pub counts: PurgeCounts,
    pub audit_events: u64,
}

#[derive(Clone)]
pub struct MaintenanceService {
    deps: Dependencies,
}

impl MaintenanceService {
    pub fn new(deps: Dependencies) -> Self {
        Self { deps }
    }

    /// One unit of work. Data older than `purge_grace` and audit events older than
    /// `audit_retention` are deleted. Writes no audit event.
    pub async fn purge_expired(&self, _ctx: &RequestContext) -> Result<PurgeReport, StoreError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let mut uow = deps.store.begin().await?;
        let counts = uow
            .purge()
            .purge_expired(now - deps.config.purge_grace)
            .await?;
        let audit_events = uow
            .purge()
            .purge_audit_events(now - deps.config.audit_retention)
            .await?;
        uow.commit().await?;
        Ok(PurgeReport {
            counts,
            audit_events,
        })
    }

    /// Readiness check (`UnitOfWorkFactory::ping`).
    pub async fn check_ready(&self) -> Result<(), StoreError> {
        self.deps.store.ping().await
    }
}
