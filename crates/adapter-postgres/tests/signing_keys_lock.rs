#![cfg(feature = "pg-tests")]

mod common;

use std::time::Duration;

use komainu_application::UnitOfWorkFactory;
use tokio::time::timeout;

#[tokio::test]
async fn lock_rotation_waits_for_the_first_commit() {
    let db = common::start().await;
    let mut first = db.factory.begin().await.unwrap();
    first.signing_keys().lock_rotation().await.unwrap();

    let mut second = db.factory.begin().await.unwrap();
    let wait = second.signing_keys().lock_rotation();
    tokio::pin!(wait);
    assert!(
        timeout(Duration::from_millis(200), &mut wait)
            .await
            .is_err(),
        "the second lock was granted before the first unit of work ended"
    );

    first.commit().await.unwrap();
    timeout(Duration::from_secs(10), wait)
        .await
        .expect("the second lock was not granted after the commit")
        .unwrap();
}
