//! Deletion of expired data.

use komainu_application::{BoxFuture, PurgeCounts, PurgeRepository, StoreError};
use time::OffsetDateTime;

use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl PgUnitOfWork {
    async fn delete_before(
        &mut self,
        sql: &'static str,
        cutoff: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        sqlx::query(sql)
            .bind(cutoff)
            .execute(&mut *self.tx)
            .await
            .map(|done| done.rows_affected())
            .map_err(map_sqlx)
    }
}

impl PurgeRepository for PgUnitOfWork {
    fn purge_expired(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<PurgeCounts, StoreError>> {
        Box::pin(async move {
            // Children first: grants go last, once nothing references them.
            let authorization_codes = self
                .delete_before(
                    "DELETE FROM authorization_codes WHERE expires_at <= $1",
                    cutoff,
                )
                .await?;
            let access_tokens = self
                .delete_before("DELETE FROM access_tokens WHERE expires_at <= $1", cutoff)
                .await?;
            let refresh_tokens = self
                .delete_before("DELETE FROM refresh_tokens WHERE expires_at <= $1", cutoff)
                .await?;
            let authorization_requests = self
                .delete_before(
                    "DELETE FROM authorization_requests WHERE expires_at <= $1",
                    cutoff,
                )
                .await?;
            let login_sessions = self
                .delete_before("DELETE FROM login_sessions WHERE expires_at <= $1", cutoff)
                .await?;
            let grants = self
                .delete_before(
                    "DELETE FROM grants g WHERE g.created_at <= $1 \
                     AND NOT EXISTS (SELECT 1 FROM access_tokens t WHERE t.grant_id = g.id) \
                     AND NOT EXISTS (SELECT 1 FROM refresh_tokens t WHERE t.grant_id = g.id) \
                     AND NOT EXISTS (SELECT 1 FROM authorization_codes c WHERE c.grant_id = g.id)",
                    cutoff,
                )
                .await?;
            let used_assertions = self
                .delete_before("DELETE FROM used_assertions WHERE expires_at < $1", cutoff)
                .await?;
            Ok(PurgeCounts {
                authorization_requests,
                authorization_codes,
                access_tokens,
                refresh_tokens,
                login_sessions,
                grants,
                used_assertions,
            })
        })
    }

    fn purge_audit_events(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<u64, StoreError>> {
        Box::pin(self.delete_before("DELETE FROM audit_events WHERE occurred_at <= $1", cutoff))
    }
}
