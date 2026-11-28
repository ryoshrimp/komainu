//! The `serve` and `migrate` commands: listeners, background jobs and graceful shutdown.

use std::net::SocketAddr;

use komainu::adapter_postgres::{PgUnitOfWorkFactory, connect, migrate};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::wiring::{Settings, services};
use crate::{Exit, cleanup, ops, rotation};

/// `komainu migrate`: applies the embedded migrations.
pub(crate) async fn run_migrate(settings: Settings) -> Result<(), Exit> {
    let pool = connect(&settings.pg).await.map_err(Exit::runtime)?;
    migrate(&pool).await.map_err(Exit::runtime)?;
    Ok(())
}

/// `komainu serve`. Returns when the servers have stopped; the error carries the exit code.
pub(crate) async fn run_serve(
    settings: Settings,
    migrate_first: bool,
    metrics: PrometheusHandle,
) -> Result<(), Exit> {
    // Handlers are installed before anything else so an early signal is not lost.
    let mut sigterm = signal(SignalKind::terminate()).map_err(Exit::runtime)?;
    let mut sigint = signal(SignalKind::interrupt()).map_err(Exit::runtime)?;

    let pool = match connect(&settings.pg).await {
        Ok(pool) => pool,
        Err(error) => {
            tracing::error!(%error, "cannot connect to the database");
            return Err(Exit::runtime(error));
        }
    };
    if migrate_first && let Err(error) = migrate(&pool).await {
        tracing::error!(%error, "migration failed");
        return Err(Exit::runtime(error));
    }

    let Settings {
        application,
        http,
        listen,
        ops_listen,
        shutdown_timeout,
        cleanup: cleanup_config,
        key_sealer,
        rotation_interval,
        ..
    } = settings;
    let services = services(
        PgUnitOfWorkFactory::new(pool),
        application,
        http,
        key_sealer,
    )
    .map_err(Exit::runtime)?;
    let signing_keys = services.komainu.signing_keys().cloned();
    if let Some(service) = &signing_keys
        && let Err(error) = rotation::run_once(service).await
    {
        tracing::error!(%error, "initial signing key rotation failed");
        return Err(Exit::runtime(error));
    }

    let main_listener = bind(listen).await?;
    let ops_listener = bind(ops_listen).await?;

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let app = services
        .komainu
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    let stop = stopped(stop_rx.clone());
    tasks.spawn(async move {
        axum::serve(main_listener, app)
            .with_graceful_shutdown(stop)
            .await
    });
    let ops_app = ops::router(services.komainu.maintenance().clone(), metrics);
    let stop = stopped(stop_rx.clone());
    tasks.spawn(async move {
        axum::serve(ops_listener, ops_app)
            .with_graceful_shutdown(stop)
            .await
    });
    if cleanup_config.enabled {
        let interval = std::time::Duration::from_secs(cleanup_config.interval_secs);
        let stop = stopped(stop_rx.clone());
        let maintenance = services.komainu.maintenance().clone();
        tasks.spawn(async move {
            cleanup::run_periodic(maintenance, interval, stop).await;
            Ok(())
        });
    }

    if let Some(service) = signing_keys {
        let stop = stopped(stop_rx.clone());
        tasks.spawn(async move {
            rotation::run_periodic(service, rotation_interval, stop).await;
            Ok(())
        });
    }

    tracing::info!(
        listen = %listen,
        ops_listen = %ops_listen,
        version = env!("CARGO_PKG_VERSION"),
        "komainu started"
    );

    let mut failed = false;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("shutdown requested"),
        _ = sigint.recv() => tracing::info!("shutdown requested"),
        finished = tasks.join_next() => {
            // A server or job ended before any signal: treat it as a failure and stop the rest.
            failed = true;
            tracing::error!(result = ?finished, "a server task ended unexpectedly");
        }
    }
    let _ = stop_tx.send(true);

    let drain = async {
        while let Some(finished) = tasks.join_next().await {
            if !matches!(finished, Ok(Ok(()))) {
                failed = true;
            }
        }
        failed
    };
    match tokio::time::timeout(shutdown_timeout, drain).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(Exit::runtime("a server task failed")),
        Err(_) => {
            tracing::warn!(
                timeout_secs = shutdown_timeout.as_secs(),
                "shutdown timed out with requests still in flight"
            );
            Err(Exit::runtime("shutdown timed out"))
        }
    }
}

async fn bind(addr: SocketAddr) -> Result<TcpListener, Exit> {
    TcpListener::bind(addr).await.map_err(|error| {
        tracing::error!(%error, %addr, "cannot bind the listener");
        Exit::runtime(format!("cannot bind {addr}: {error}"))
    })
}

/// Resolves once the shutdown flag is set.
async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}
