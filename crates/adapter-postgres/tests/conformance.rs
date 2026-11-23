#![cfg(feature = "pg-tests")]

mod common;

use std::sync::Arc;

use komainu_adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
use komainu_application::UnitOfWorkFactory;
use komainu_domain::Secret;
use komainu_testkit::conformance::run_store_conformance;

/// One container; every case gets its own empty database.
#[tokio::test]
async fn pg_store_passes_conformance() {
    let db = common::start_raw().await;
    let mut n = 0u32;
    run_store_conformance(|| {
        n += 1;
        let n = n;
        let pool = db.pool.clone();
        let url = db.url.clone();
        async move {
            let name = format!("conformance_{n}");
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&pool)
                .await
                .expect("create database");
            let base = url
                .strip_suffix("/postgres")
                .expect("url ends with /postgres");
            let url = format!("{base}/{name}");
            let pool = connect(&PgStoreConfig::new(Secret::new(url)))
                .await
                .expect("connect");
            migrate(&pool).await.expect("migrate");
            Arc::new(PgUnitOfWorkFactory::new(pool)) as Arc<dyn UnitOfWorkFactory>
        }
    })
    .await;
}
