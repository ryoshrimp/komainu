//! `trusted_issuers` and `trusted_issuer_clients` tables.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use komainu_application::{BoxFuture, ListPage, StoreError, TrustedIssuerRepository};
use komainu_domain::*;
use sqlx::postgres::PgRow;

use crate::codec::{col, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

macro_rules! columns {
    () => {
        "id, jwks, status, created_at, updated_at"
    };
}

fn from_row(row: &PgRow, allowed_clients: BTreeSet<ClientId>) -> Result<TrustedIssuer, StoreError> {
    Ok(TrustedIssuer::from_record(TrustedIssuerRecord {
        id: valid(IssuerId::try_new(col(row, "id")?), "trusted_issuers.id")?,
        jwks: valid(
            JwksDocument::try_new(col(row, "jwks")?),
            "trusted_issuers.jwks",
        )?,
        allowed_clients,
        status: IssuerStatus::from_str(&col::<String>(row, "status")?)
            .map_err(|_| corrupted("trusted_issuers.status"))?,
        created_at: col(row, "created_at")?,
        updated_at: col(row, "updated_at")?,
    }))
}

impl PgUnitOfWork {
    /// Loads the allowed clients of `ids`, grouped by issuer.
    async fn allowed_clients(
        &mut self,
        ids: Vec<String>,
    ) -> Result<BTreeMap<String, BTreeSet<ClientId>>, StoreError> {
        let rows = sqlx::query(
            "SELECT issuer_id, client_id FROM trusted_issuer_clients WHERE issuer_id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(map_sqlx)?;
        let mut grouped: BTreeMap<String, BTreeSet<ClientId>> = BTreeMap::new();
        for row in &rows {
            let client = valid(
                ClientId::try_new(col(row, "client_id")?),
                "trusted_issuer_clients.client_id",
            )?;
            grouped
                .entry(col(row, "issuer_id")?)
                .or_default()
                .insert(client);
        }
        Ok(grouped)
    }

    async fn select_issuers(&mut self, rows: Vec<PgRow>) -> Result<Vec<TrustedIssuer>, StoreError> {
        let ids = rows
            .iter()
            .map(|row| col::<String>(row, "id"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut grouped = self.allowed_clients(ids.clone()).await?;
        rows.iter()
            .zip(ids)
            .map(|(row, id)| from_row(row, grouped.remove(&id).unwrap_or_default()))
            .collect()
    }

    async fn select_issuer(
        &mut self,
        id: String,
        for_update: bool,
    ) -> Result<Option<TrustedIssuer>, StoreError> {
        let sql = if for_update {
            concat!(
                "SELECT ",
                columns!(),
                " FROM trusted_issuers WHERE id = $1 FOR UPDATE"
            )
        } else {
            concat!("SELECT ", columns!(), " FROM trusted_issuers WHERE id = $1")
        };
        let rows = sqlx::query(sql)
            .bind(id)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
        Ok(self.select_issuers(rows).await?.pop())
    }

    async fn replace_allowed_clients(
        &mut self,
        id: &IssuerId,
        clients: &BTreeSet<ClientId>,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM trusted_issuer_clients WHERE issuer_id = $1")
            .bind(id.as_inner())
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
        let clients: Vec<String> = clients.iter().map(|c| c.as_inner().clone()).collect();
        sqlx::query(
            "INSERT INTO trusted_issuer_clients (issuer_id, client_id) \
             SELECT $1, unnest($2::text[])",
        )
        .bind(id.as_inner())
        .bind(clients)
        .execute(&mut *self.tx)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}

impl TrustedIssuerRepository for PgUnitOfWork {
    fn find(&mut self, id: &IssuerId) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>> {
        let id = id.as_inner().clone();
        Box::pin(self.select_issuer(id, false))
    }

    fn find_for_update(
        &mut self,
        id: &IssuerId,
    ) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>> {
        let id = id.as_inner().clone();
        Box::pin(self.select_issuer(id, true))
    }

    fn insert(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = issuer.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO trusted_issuers (id, jwks, status, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(r.id.as_inner())
            .bind(r.jwks.as_str())
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            self.replace_allowed_clients(&r.id, &r.allowed_clients)
                .await
        })
    }

    fn update(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = issuer.to_record();
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE trusted_issuers SET jwks = $2, status = $3, created_at = $4, \
                 updated_at = $5 WHERE id = $1",
            )
            .bind(r.id.as_inner())
            .bind(r.jwks.as_str())
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("trusted issuer"));
            }
            self.replace_allowed_clients(&r.id, &r.allowed_clients)
                .await
        })
    }

    fn list(
        &mut self,
        page: &ListPage<IssuerId>,
    ) -> BoxFuture<'_, Result<Vec<TrustedIssuer>, StoreError>> {
        let after = page.after.as_ref().map(|id| id.as_inner().clone());
        let limit = i64::from(page.limit);
        Box::pin(async move {
            // COLLATE "C" gives byte order, the same as the in-memory store's `Ord`.
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM trusted_issuers WHERE ($1::text IS NULL OR id COLLATE \"C\" > $1::text COLLATE \"C\") \
                 ORDER BY id COLLATE \"C\" LIMIT $2"
            ))
            .bind(after)
            .bind(limit)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            self.select_issuers(rows).await
        })
    }
}
