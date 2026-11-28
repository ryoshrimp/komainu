#![cfg(feature = "pg-tests")]

mod common;

use std::sync::Arc;

use komainu_adapter_std::{OsSecureRandom, SystemClock};
use komainu_application::{RequestContext, SigningConfig, SigningKeyService};
use komainu_domain::{SigningAlgorithm, SigningPolicy};
use komainu_testkit::TestKeySealer;

/// N-2: two nodes rotating at once end up with one key per algorithm.
#[tokio::test]
async fn concurrent_rotate_due_creates_each_key_once() {
    let db = common::start().await;
    let algorithms = vec![SigningAlgorithm::Es256, SigningAlgorithm::Rs256];
    let service = || {
        SigningKeyService::new(
            Arc::new(db.factory.clone()),
            Arc::new(TestKeySealer),
            Arc::new(SystemClock),
            Arc::new(OsSecureRandom),
            SigningConfig::new(algorithms.clone(), SigningPolicy::default()).unwrap(),
        )
    };
    let (a, b) = (service(), service());
    let ctx = RequestContext {
        request_id: "req-1".to_owned(),
        client_ip: None,
    };
    let (ra, rb) = tokio::join!(a.rotate_due(&ctx), b.rotate_due(&ctx));
    let created = ra.unwrap().created.len() + rb.unwrap().created.len();
    assert_eq!(created, algorithms.len());
    assert_eq!(a.list().await.unwrap().len(), algorithms.len());
}

/// The node that waits for the rotation lock must read its clock after getting the lock.
///
/// Node A starts first (clock at T+1h) and queues behind a held lock. Then the clocks go back to
/// T and node B queues too. A wins the lock and creates a key at T+1h (when it reads the clock
/// before locking) and B, now at T, would then see that key as pending and move its activation
/// before its creation. Reading the clock after the lock avoids this.
#[tokio::test]
async fn concurrent_rotate_now_keeps_the_schedule_valid() {
    use std::time::Duration;

    use komainu_application::UnitOfWorkFactory;
    use komainu_testkit::FixedClock;
    use time::{Date, Month};

    let db = common::start().await;
    let t = Date::from_calendar_date(2026, Month::January, 1)
        .unwrap()
        .midnight()
        .assume_utc();
    let clock = FixedClock::new(t);
    let service = || {
        Arc::new(SigningKeyService::new(
            Arc::new(db.factory.clone()),
            Arc::new(TestKeySealer),
            Arc::new(clock.clone()),
            Arc::new(OsSecureRandom),
            SigningConfig::default(),
        ))
    };
    let (a, b) = (service(), service());
    let ctx = RequestContext {
        request_id: "req-1".to_owned(),
        client_ip: None,
    };
    a.rotate_due(&ctx).await.unwrap();

    let mut holder = db.factory.begin().await.unwrap();
    holder.signing_keys().lock_rotation().await.unwrap();

    clock.set(t + time::Duration::hours(1));
    let first = tokio::spawn({
        let (a, ctx) = (a.clone(), ctx.clone());
        async move { a.rotate_now(&ctx, SigningAlgorithm::Es256).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    clock.set(t);
    let second = tokio::spawn({
        let (b, ctx) = (b.clone(), ctx.clone());
        async move { b.rotate_now(&ctx, SigningAlgorithm::Es256).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(holder);

    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    let keys = a.list().await.unwrap();
    assert_eq!(keys.len(), 3);
}
