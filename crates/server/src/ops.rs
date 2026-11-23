//! The ops listener: `/healthz`, `/readyz` and `/metrics`.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use komainu::application::MaintenanceService;
use metrics_exporter_prometheus::PrometheusHandle;

#[derive(Clone)]
struct OpsState {
    maintenance: MaintenanceService,
    metrics: PrometheusHandle,
}

/// Router of the ops listener.
pub fn router(maintenance: MaintenanceService, metrics: PrometheusHandle) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(render_metrics))
        .with_state(OpsState {
            maintenance,
            metrics,
        })
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<OpsState>) -> Response {
    match state.maintenance.check_ready().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(error) => {
            tracing::warn!(%error, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

async fn render_metrics(State(state): State<OpsState>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        state.metrics.render(),
    )
        .into_response()
}
