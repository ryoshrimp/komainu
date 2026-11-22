//! `consents` table.

use komainu_application::{BoxFuture, ConsentRepository, StoreError};
use komainu_domain::*;

use crate::codec::{col, scope_from_db, scope_to_db};
use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl ConsentRepository for PgUnitOfWork {
    fn find(
        &mut self,
        subject: &Subject,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Consent>, StoreError>> {
        let subject = subject.clone();
        let client_id = client_id.clone();
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT scope, created_at, updated_at FROM consents \
                 WHERE subject = $1 AND client_id = $2",
            )
            .bind(subject.as_inner())
            .bind(client_id.as_inner())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.map(|row| {
                Ok(Consent::from_record(ConsentRecord {
                    id: ConsentId { subject, client_id },
                    scope: scope_from_db(col(&row, "scope")?, "consents.scope")?,
                    created_at: col(&row, "created_at")?,
                    updated_at: col(&row, "updated_at")?,
                }))
            })
            .transpose()
        })
    }

    fn upsert(&mut self, consent: &Consent) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = consent.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO consents (subject, client_id, scope, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (subject, client_id) DO UPDATE SET scope = EXCLUDED.scope, \
                 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at",
            )
            .bind(r.id.subject.as_inner())
            .bind(r.id.client_id.as_inner())
            .bind(scope_to_db(&r.scope))
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }
}
