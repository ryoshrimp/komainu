//! Periodic purge of expired data.

use std::time::Duration;

use komainu_application::{MaintenanceService, PurgeReport, StoreError};
use metrics::counter;

use crate::wiring::background_context;

/// Runs one purge and records logs/metrics. Never panics on store errors.
pub async fn run_once(service: &MaintenanceService) -> Result<PurgeReport, StoreError> {
    match service.purge_expired(&background_context()).await {
        Ok(report) => {
            let counts = report.counts;
            let kinds = [
                ("authorization_requests", counts.authorization_requests),
                ("authorization_codes", counts.authorization_codes),
                ("access_tokens", counts.access_tokens),
                ("refresh_tokens", counts.refresh_tokens),
                ("login_sessions", counts.login_sessions),
                ("grants", counts.grants),
                ("audit_events", report.audit_events),
            ];
            for (kind, deleted) in kinds {
                counter!("komainu_cleanup_deleted_total", "kind" => kind).increment(deleted);
            }
            counter!("komainu_cleanup_runs_total", "result" => "success").increment(1);
            tracing::info!(
                authorization_requests = counts.authorization_requests,
                authorization_codes = counts.authorization_codes,
                access_tokens = counts.access_tokens,
                refresh_tokens = counts.refresh_tokens,
                login_sessions = counts.login_sessions,
                grants = counts.grants,
                audit_events = report.audit_events,
                "cleanup finished"
            );
            Ok(report)
        }
        Err(error) => {
            counter!("komainu_cleanup_runs_total", "result" => "failure").increment(1);
            tracing::warn!(%error, "cleanup failed");
            Err(error)
        }
    }
}

/// Calls run_once every interval until `shutdown` resolves. The first run is one interval after start.
pub async fn run_periodic(
    service: MaintenanceService,
    interval: Duration,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(interval) => {
                // A failure is already logged and counted; try again next interval.
                let _ = run_once(&service).await;
            }
        }
    }
}
