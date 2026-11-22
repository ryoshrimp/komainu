//! Logging and the Prometheus recorder.

use anyhow::anyhow;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;

use crate::config::{LogConfig, LogFormat};

/// Installs the tracing subscriber and registers the global Prometheus recorder.
///
/// `RUST_LOG` takes precedence over `log.filter`. Call at most once per process.
pub fn init(log: &LogConfig) -> anyhow::Result<PrometheusHandle> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.is_empty() => EnvFilter::try_new(value)?,
        _ => EnvFilter::try_new(&log.filter)?,
    };
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match log.format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.pretty().try_init(),
    }
    .map_err(|e| anyhow!("failed to install the log subscriber: {e}"))?;
    Ok(PrometheusBuilder::new().install_recorder()?)
}
