//! `signing_keys` table.

use std::str::FromStr;

use komainu_application::{BoxFuture, SigningKeyRepository, StoreError};
use komainu_domain::*;
use sqlx::postgres::PgRow;

use crate::codec::{col, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

fn from_row(row: &PgRow) -> Result<ServerSigningKey, StoreError> {
    Ok(ServerSigningKey::from_record(ServerSigningKeyRecord {
        kid: valid(SigningKeyId::try_new(col(row, "kid")?), "signing_keys.kid")?,
        algorithm: SigningAlgorithm::from_str(&col::<String>(row, "alg")?)
            .map_err(|_| corrupted("signing_keys.alg"))?,
        sealed_private_key: valid(
            SealedPrivateKey::new(col(row, "sealed_private_key")?),
            "signing_keys.sealed_private_key",
        )?,
        public_jwk: valid(
            PublicJwk::try_new(col(row, "public_jwk")?),
            "signing_keys.public_jwk",
        )?,
        created_at: col(row, "created_at")?,
        activates_at: col(row, "activates_at")?,
        retires_at: col(row, "retires_at")?,
        deletes_at: col(row, "deletes_at")?,
    }))
}

impl SigningKeyRepository for PgUnitOfWork {
    fn lock_rotation(&mut self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('komainu:signing_keys', 0))")
                .execute(&mut *self.tx)
                .await
                .map(|_| ())
                .map_err(map_sqlx)
        })
    }

    fn list(&mut self) -> BoxFuture<'_, Result<Vec<ServerSigningKey>, StoreError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT kid, alg, sealed_private_key, public_jwk, created_at, activates_at, \
                 retires_at, deletes_at FROM signing_keys ORDER BY activates_at, kid COLLATE \"C\"",
            )
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            rows.iter().map(from_row).collect()
        })
    }

    fn insert(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = key.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO signing_keys (kid, alg, sealed_private_key, public_jwk, created_at, \
                 activates_at, retires_at, deletes_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(r.kid.as_inner())
            .bind(r.algorithm.as_str())
            .bind(r.sealed_private_key.as_bytes())
            .bind(r.public_jwk.as_inner())
            .bind(r.created_at)
            .bind(r.activates_at)
            .bind(r.retires_at)
            .bind(r.deletes_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update_schedule(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = key.to_record();
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE signing_keys SET activates_at = $2, retires_at = $3, deletes_at = $4 \
                 WHERE kid = $1",
            )
            .bind(r.kid.as_inner())
            .bind(r.activates_at)
            .bind(r.retires_at)
            .bind(r.deletes_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("signing key"));
            }
            Ok(())
        })
    }

    fn delete(&mut self, kid: &SigningKeyId) -> BoxFuture<'_, Result<bool, StoreError>> {
        let kid = kid.as_inner().clone();
        Box::pin(async move {
            let done = sqlx::query("DELETE FROM signing_keys WHERE kid = $1")
                .bind(kid)
                .execute(&mut *self.tx)
                .await
                .map_err(map_sqlx)?;
            Ok(done.rows_affected() > 0)
        })
    }
}
