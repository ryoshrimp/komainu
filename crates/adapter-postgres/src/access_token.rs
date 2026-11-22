//! `access_tokens` table.

use komainu_application::{AccessTokenRepository, BoxFuture, StoreError};
use komainu_domain::*;

use crate::codec::{col, hash_from_db, hash_to_db, scope_from_db, scope_to_db, valid};
use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl AccessTokenRepository for PgUnitOfWork {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<AccessToken>, StoreError>> {
        let id = *id;
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, grant_id, client_id, subject, scope, issued_at, expires_at \
                 FROM access_tokens WHERE id = $1",
            )
            .bind(hash_to_db(&id))
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.map(|row| {
                let subject = col::<Option<String>>(&row, "subject")?
                    .map(|s| valid(Subject::try_new(s), "access_tokens.subject"))
                    .transpose()?;
                Ok(AccessToken::from_record(AccessTokenRecord {
                    id: hash_from_db(col(&row, "id")?, "access_tokens.id")?,
                    grant_id: GrantId::new(col(&row, "grant_id")?),
                    client_id: valid(
                        ClientId::try_new(col(&row, "client_id")?),
                        "access_tokens.client_id",
                    )?,
                    subject,
                    scope: scope_from_db(col(&row, "scope")?, "access_tokens.scope")?,
                    issued_at: col(&row, "issued_at")?,
                    expires_at: col(&row, "expires_at")?,
                }))
            })
            .transpose()
        })
    }

    fn insert(&mut self, token: &AccessToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = token.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO access_tokens (id, grant_id, client_id, subject, scope, issued_at, \
                 expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.grant_id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(r.subject.as_ref().map(|s| s.as_inner()))
            .bind(scope_to_db(&r.scope))
            .bind(r.issued_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }
}
