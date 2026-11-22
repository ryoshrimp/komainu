//! `refresh_tokens` table.

use komainu_application::{BoxFuture, RefreshTokenRepository, StoreError};
use komainu_domain::*;

use crate::codec::{col, hash_from_db, hash_to_db, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

fn status_to_db(status: &RefreshTokenStatus) -> (&'static str, Option<time::OffsetDateTime>) {
    match status {
        RefreshTokenStatus::Active => ("active", None),
        RefreshTokenStatus::Rotated { rotated_at } => ("rotated", Some(*rotated_at)),
    }
}

impl RefreshTokenRepository for PgUnitOfWork {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<RefreshToken>, StoreError>> {
        let id = *id;
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, grant_id, client_id, status, rotated_at, issued_at, expires_at \
                 FROM refresh_tokens WHERE id = $1 FOR UPDATE",
            )
            .bind(hash_to_db(&id))
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.map(|row| {
                let rotated_at = col::<Option<time::OffsetDateTime>>(&row, "rotated_at")?;
                let status = match (col::<String>(&row, "status")?.as_str(), rotated_at) {
                    ("active", None) => RefreshTokenStatus::Active,
                    ("rotated", Some(rotated_at)) => RefreshTokenStatus::Rotated { rotated_at },
                    _ => return Err(corrupted("refresh_tokens.status")),
                };
                Ok(RefreshToken::from_record(RefreshTokenRecord {
                    id: hash_from_db(col(&row, "id")?, "refresh_tokens.id")?,
                    grant_id: GrantId::new(col(&row, "grant_id")?),
                    client_id: valid(
                        ClientId::try_new(col(&row, "client_id")?),
                        "refresh_tokens.client_id",
                    )?,
                    status,
                    issued_at: col(&row, "issued_at")?,
                    expires_at: col(&row, "expires_at")?,
                }))
            })
            .transpose()
        })
    }

    fn insert(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = token.to_record();
        Box::pin(async move {
            let (status, rotated_at) = status_to_db(&r.status);
            sqlx::query(
                "INSERT INTO refresh_tokens (id, grant_id, client_id, status, rotated_at, \
                 issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.grant_id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(status)
            .bind(rotated_at)
            .bind(r.issued_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = token.to_record();
        Box::pin(async move {
            let (status, rotated_at) = status_to_db(&r.status);
            let done = sqlx::query(
                "UPDATE refresh_tokens SET grant_id = $2, client_id = $3, status = $4, \
                 rotated_at = $5, issued_at = $6, expires_at = $7 WHERE id = $1",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.grant_id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(status)
            .bind(rotated_at)
            .bind(r.issued_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("refresh token"));
            }
            Ok(())
        })
    }
}
