//! `used_assertions` table.

use komainu_application::{
    BoxFuture, RecordOutcome, StoreError, UsedAssertion, UsedAssertionRepository,
};

use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl UsedAssertionRepository for PgUnitOfWork {
    fn record(
        &mut self,
        assertion: &UsedAssertion,
    ) -> BoxFuture<'_, Result<RecordOutcome, StoreError>> {
        let a = assertion.clone();
        Box::pin(async move {
            // A concurrent insert of the same key blocks until its transaction ends, so
            // exactly one of two racing units of work records the assertion.
            let done = sqlx::query(
                "INSERT INTO used_assertions (kind, issuer, jti, expires_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (kind, issuer, jti) DO NOTHING",
            )
            .bind(a.kind.as_str())
            .bind(a.issuer)
            .bind(a.jti)
            .bind(a.expires_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            Ok(if done.rows_affected() == 0 {
                RecordOutcome::Replayed
            } else {
                RecordOutcome::Recorded
            })
        })
    }
}
