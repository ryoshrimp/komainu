#![cfg(feature = "pg-tests")]
//! Acceptance test of the purge job (server.md, cleanup).

mod common;

use komainu::adapter_postgres::PgUnitOfWorkFactory;
use komainu_server::{cleanup, config, wiring};

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_run_once_deletes_only_tokens_past_the_grace_period() {
    let db = common::start_db().await;
    let path = common::write_config(&db.url, common::free_addr(), common::free_addr());
    let mut cfg = config::load(Some(&path)).expect("load");
    config::validate(&mut cfg).expect("validate");
    let settings = wiring::Settings::from_config(cfg).expect("settings");
    let services = wiring::services(
        PgUnitOfWorkFactory::new(db.pool.clone()),
        settings.application,
        settings.http,
    )
    .expect("services");

    sqlx::query(
        "INSERT INTO clients (id, name, client_type, auth_method, secret_hash, redirect_uris, \
         grant_types, allowed_scopes, default_scopes, skip_consent, status, created_at, updated_at) \
         VALUES ('c', 'c', 'confidential', 'client_secret_basic', $1, '{}', '{client_credentials}', \
         '{}', '{}', false, 'active', now(), now())",
    )
    .bind(vec![1u8; 32])
    .execute(&db.pool)
    .await
    .expect("client");
    sqlx::query(
        "INSERT INTO grants (id, client_id, subject, scope, origin, status, created_at) \
         VALUES ('00000000-0000-7000-8000-000000000001', 'c', NULL, '{}', 'client_credentials', \
         'active', now())",
    )
    .execute(&db.pool)
    .await
    .expect("grant");
    // The purge cutoff is the host clock minus the 24 h grace period, so `expires_at` is computed
    // on the host as well and never depends on the database clock. The service clock is not
    // injectable here, so the tokens straddle the cutoff by one minute instead of sitting on it
    // (the exact `<` / `<=` boundary is covered at the application and adapter level).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs_f64();
    for (n, offset_secs) in [(1u8, 24 * 3600 + 60), (2, 24 * 3600 - 60), (3, 23 * 3600)] {
        sqlx::query(
            "INSERT INTO access_tokens (id, grant_id, client_id, subject, scope, issued_at, expires_at) \
             VALUES ($1, '00000000-0000-7000-8000-000000000001', 'c', NULL, '{}', \
             to_timestamp($2) - interval '30 hours', to_timestamp($2) - make_interval(secs => $3))",
        )
        .bind(vec![n; 32])
        .bind(now)
        .bind(f64::from(offset_secs))
        .execute(&db.pool)
        .await
        .expect("access token");
    }

    let report = cleanup::run_once(services.komainu.maintenance())
        .await
        .expect("purge");
    assert_eq!(report.counts.access_tokens, 1);
    let left: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT id FROM access_tokens ORDER BY id")
        .fetch_all(&db.pool)
        .await
        .expect("left");
    assert_eq!(left, vec![(vec![2u8; 32],), (vec![3u8; 32],)]);
}
