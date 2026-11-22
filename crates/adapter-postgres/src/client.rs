//! `clients` table.

use std::str::FromStr;

use komainu_application::{BoxFuture, ClientRepository, ListPage, StoreError};
use komainu_domain::*;
use sqlx::postgres::PgRow;

use crate::codec::{col, hash_from_db, hash_to_db, scope_from_db, scope_to_db, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

macro_rules! columns {
    () => {
        "id, name, client_type, auth_method, secret_hash, redirect_uris, grant_types, \
         allowed_scopes, default_scopes, skip_consent, status, created_at, updated_at"
    };
}

fn from_row(row: &PgRow) -> Result<Client, StoreError> {
    let secret_hash = col::<Option<Vec<u8>>>(row, "secret_hash")?
        .map(|b| hash_from_db(b, "clients.secret_hash"))
        .transpose()?;
    let redirect_uris = col::<Vec<String>>(row, "redirect_uris")?
        .into_iter()
        .map(|u| valid(RedirectUri::try_new(u), "clients.redirect_uris"))
        .collect::<Result<_, _>>()?;
    let grant_types = col::<Vec<String>>(row, "grant_types")?
        .iter()
        .map(|g| GrantType::from_str(g).map_err(|_| corrupted("clients.grant_types")))
        .collect::<Result<_, _>>()?;
    Ok(Client::from_record(ClientRecord {
        id: valid(ClientId::try_new(col(row, "id")?), "clients.id")?,
        name: valid(ClientName::try_new(col(row, "name")?), "clients.name")?,
        client_type: ClientType::from_str(&col::<String>(row, "client_type")?)
            .map_err(|_| corrupted("clients.client_type"))?,
        auth_method: TokenEndpointAuthMethod::from_str(&col::<String>(row, "auth_method")?)
            .map_err(|_| corrupted("clients.auth_method"))?,
        secret_hash,
        redirect_uris,
        grant_types,
        allowed_scopes: scope_from_db(col(row, "allowed_scopes")?, "clients.allowed_scopes")?,
        default_scopes: scope_from_db(col(row, "default_scopes")?, "clients.default_scopes")?,
        skip_consent: col(row, "skip_consent")?,
        status: ClientStatus::from_str(&col::<String>(row, "status")?)
            .map_err(|_| corrupted("clients.status"))?,
        created_at: col(row, "created_at")?,
        updated_at: col(row, "updated_at")?,
    }))
}

impl PgUnitOfWork {
    async fn select_client(
        &mut self,
        id: String,
        for_update: bool,
    ) -> Result<Option<Client>, StoreError> {
        let sql = if for_update {
            concat!(
                "SELECT ",
                columns!(),
                " FROM clients WHERE id = $1 FOR UPDATE"
            )
        } else {
            concat!("SELECT ", columns!(), " FROM clients WHERE id = $1")
        };
        let row = sqlx::query(sql)
            .bind(id)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
        row.as_ref().map(from_row).transpose()
    }
}

impl ClientRepository for PgUnitOfWork {
    fn find(&mut self, id: &ClientId) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        let id = id.as_inner().clone();
        Box::pin(self.select_client(id, false))
    }

    fn find_for_update(
        &mut self,
        id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        let id = id.as_inner().clone();
        Box::pin(self.select_client(id, true))
    }

    fn insert(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = client.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO clients (id, name, client_type, auth_method, secret_hash, \
                 redirect_uris, grant_types, allowed_scopes, default_scopes, skip_consent, \
                 status, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .bind(r.id.as_inner())
            .bind(r.name.as_inner())
            .bind(r.client_type.as_str())
            .bind(r.auth_method.as_str())
            .bind(r.secret_hash.as_ref().map(hash_to_db))
            .bind(redirect_uris_to_db(&r))
            .bind(grant_types_to_db(&r))
            .bind(scope_to_db(&r.allowed_scopes))
            .bind(scope_to_db(&r.default_scopes))
            .bind(r.skip_consent)
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = client.to_record();
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE clients SET name = $2, client_type = $3, auth_method = $4, \
                 secret_hash = $5, redirect_uris = $6, grant_types = $7, allowed_scopes = $8, \
                 default_scopes = $9, skip_consent = $10, status = $11, created_at = $12, \
                 updated_at = $13 WHERE id = $1",
            )
            .bind(r.id.as_inner())
            .bind(r.name.as_inner())
            .bind(r.client_type.as_str())
            .bind(r.auth_method.as_str())
            .bind(r.secret_hash.as_ref().map(hash_to_db))
            .bind(redirect_uris_to_db(&r))
            .bind(grant_types_to_db(&r))
            .bind(scope_to_db(&r.allowed_scopes))
            .bind(scope_to_db(&r.default_scopes))
            .bind(r.skip_consent)
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("client"));
            }
            Ok(())
        })
    }

    fn list(
        &mut self,
        page: &ListPage<ClientId>,
    ) -> BoxFuture<'_, Result<Vec<Client>, StoreError>> {
        let after = page.after.as_ref().map(|id| id.as_inner().clone());
        let limit = i64::from(page.limit);
        Box::pin(async move {
            // COLLATE "C" gives byte order, the same as the in-memory store's `Ord`.
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM clients WHERE ($1::text IS NULL OR id COLLATE \"C\" > $1::text COLLATE \"C\") \
                 ORDER BY id COLLATE \"C\" LIMIT $2"
            ))
            .bind(after)
            .bind(limit)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            rows.iter().map(from_row).collect()
        })
    }
}

fn redirect_uris_to_db(r: &ClientRecord) -> Vec<String> {
    r.redirect_uris
        .iter()
        .map(|u| u.as_str().to_owned())
        .collect()
}

fn grant_types_to_db(r: &ClientRecord) -> Vec<String> {
    r.grant_types
        .iter()
        .map(|g| g.as_str().to_owned())
        .collect()
}
