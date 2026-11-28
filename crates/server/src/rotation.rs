//! Rotation of the AS signing keys at startup and periodically.

use std::sync::Arc;
use std::time::Duration;

use komainu::{RotationReport, SigningKeyError, SigningKeyService};
use metrics::counter;

use crate::wiring::background_context;

/// Runs one rotation and records logs/metrics. The error is returned to the caller.
pub async fn run_once(service: &SigningKeyService) -> Result<RotationReport, SigningKeyError> {
    let report = service.rotate_due(&background_context()).await?;
    let (created, activated, deleted) = (
        report.created.len(),
        report.activated.len(),
        report.deleted.len(),
    );
    for (kind, count) in [
        ("created", created),
        ("activated", activated),
        ("deleted", deleted),
    ] {
        counter!("komainu_signing_keys_rotated_total", "kind" => kind)
            .increment(u64::try_from(count).unwrap_or(u64::MAX));
    }
    if created + activated + deleted > 0 {
        tracing::info!(created, activated, deleted, "signing keys rotated");
    }
    Ok(report)
}

/// Calls `run_once` every interval until `shutdown` resolves. The first run is one interval
/// after start. A failure is logged and retried at the next interval.
pub async fn run_periodic(
    service: Arc<SigningKeyService>,
    interval: Duration,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(interval) => {
                if let Err(error) = run_once(&service).await {
                    tracing::error!(%error, "signing key rotation failed");
                }
            }
        }
    }
}
