//! `grants` table. `origin` and `status` are split over several columns.

use komainu_application::{BoxFuture, GrantRepository, StoreError};
use komainu_domain::*;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;

use crate::codec::{col, hash_from_db, hash_to_db, scope_from_db, scope_to_db, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

macro_rules! columns {
    () => {
        "id, client_id, subject, scope, origin, origin_code_hash, status, revoked_at, \
         revocation_reason, created_at"
    };
}

fn reason_to_db(reason: RevocationReason) -> &'static str {
    match reason {
        RevocationReason::CodeReplay => "code_replay",
        RevocationReason::RefreshTokenReplay => "refresh_token_replay",
        RevocationReason::ClientDisabled => "client_disabled",
        RevocationReason::UserDisabled => "user_disabled",
    }
}

fn reason_from_db(value: &str) -> Result<RevocationReason, StoreError> {
    match value {
        "code_replay" => Ok(RevocationReason::CodeReplay),
        "refresh_token_replay" => Ok(RevocationReason::RefreshTokenReplay),
        "client_disabled" => Ok(RevocationReason::ClientDisabled),
        "user_disabled" => Ok(RevocationReason::UserDisabled),
        _ => Err(corrupted("grants.revocation_reason")),
    }
}

/// Column values of a grant that do not map one to one.
struct Split<'a> {
    origin: &'static str,
    origin_code_hash: Option<&'a [u8]>,
    status: &'static str,
    revoked_at: Option<OffsetDateTime>,
    reason: Option<&'static str>,
}

fn split(r: &GrantRecord) -> Split<'_> {
    let (origin, origin_code_hash) = match &r.origin {
        GrantOrigin::AuthorizationCode { code_hash } => {
            ("authorization_code", Some(hash_to_db(code_hash)))
        }
        GrantOrigin::ClientCredentials => ("client_credentials", None),
    };
    let (status, revoked_at, reason) = match r.status {
        GrantStatus::Active => ("active", None, None),
        GrantStatus::Revoked { revoked_at, reason } => {
            ("revoked", Some(revoked_at), Some(reason_to_db(reason)))
        }
    };
    Split {
        origin,
        origin_code_hash,
        status,
        revoked_at,
        reason,
    }
}

fn from_row(row: &PgRow) -> Result<Grant, StoreError> {
    let origin = match (
        col::<String>(row, "origin")?.as_str(),
        col::<Option<Vec<u8>>>(row, "origin_code_hash")?,
    ) {
        ("authorization_code", Some(hash)) => GrantOrigin::AuthorizationCode {
            code_hash: hash_from_db(hash, "grants.origin_code_hash")?,
        },
        ("client_credentials", None) => GrantOrigin::ClientCredentials,
        _ => return Err(corrupted("grants.origin")),
    };
    let status = match (
        col::<String>(row, "status")?.as_str(),
        col::<Option<OffsetDateTime>>(row, "revoked_at")?,
        col::<Option<String>>(row, "revocation_reason")?,
    ) {
        ("active", None, None) => GrantStatus::Active,
        ("revoked", Some(revoked_at), Some(reason)) => GrantStatus::Revoked {
            revoked_at,
            reason: reason_from_db(&reason)?,
        },
        _ => return Err(corrupted("grants.status")),
    };
    let subject = col::<Option<String>>(row, "subject")?
        .map(|s| valid(Subject::try_new(s), "grants.subject"))
        .transpose()?;
    Ok(Grant::from_record(GrantRecord {
        id: GrantId::new(col(row, "id")?),
        client_id: valid(
            ClientId::try_new(col(row, "client_id")?),
            "grants.client_id",
        )?,
        subject,
        scope: scope_from_db(col(row, "scope")?, "grants.scope")?,
        origin,
        status,
        created_at: col(row, "created_at")?,
    }))
}

impl PgUnitOfWork {
    async fn select_grant(
        &mut self,
        id: GrantId,
        for_update: bool,
    ) -> Result<Option<Grant>, StoreError> {
        let sql = if for_update {
            concat!(
                "SELECT ",
                columns!(),
                " FROM grants WHERE id = $1 FOR UPDATE"
            )
        } else {
            concat!("SELECT ", columns!(), " FROM grants WHERE id = $1")
        };
        let row = sqlx::query(sql)
            .bind(id.as_inner())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
        row.as_ref().map(from_row).transpose()
    }
}

impl GrantRepository for PgUnitOfWork {
    fn find(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>> {
        Box::pin(self.select_grant(id, false))
    }

    fn find_for_update(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>> {
        Box::pin(self.select_grant(id, true))
    }

    fn insert(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = grant.to_record();
        Box::pin(async move {
            let s = split(&r);
            sqlx::query(
                "INSERT INTO grants (id, client_id, subject, scope, origin, origin_code_hash, \
                 status, revoked_at, revocation_reason, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(r.id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(r.subject.as_ref().map(|x| x.as_inner()))
            .bind(scope_to_db(&r.scope))
            .bind(s.origin)
            .bind(s.origin_code_hash)
            .bind(s.status)
            .bind(s.revoked_at)
            .bind(s.reason)
            .bind(r.created_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = grant.to_record();
        Box::pin(async move {
            let s = split(&r);
            let done = sqlx::query(
                "UPDATE grants SET client_id = $2, subject = $3, scope = $4, origin = $5, \
                 origin_code_hash = $6, status = $7, revoked_at = $8, revocation_reason = $9, \
                 created_at = $10 WHERE id = $1",
            )
            .bind(r.id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(r.subject.as_ref().map(|x| x.as_inner()))
            .bind(scope_to_db(&r.scope))
            .bind(s.origin)
            .bind(s.origin_code_hash)
            .bind(s.status)
            .bind(s.revoked_at)
            .bind(s.reason)
            .bind(r.created_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("grant"));
            }
            Ok(())
        })
    }

    fn list_active_by_client(
        &mut self,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>> {
        let client_id = client_id.as_inner().clone();
        Box::pin(async move {
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM grants WHERE client_id = $1 AND status = 'active' ORDER BY id FOR UPDATE"
            ))
            .bind(client_id)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            rows.iter().map(from_row).collect()
        })
    }

    fn list_active_by_subject(
        &mut self,
        subject: &Subject,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>> {
        let subject = subject.as_inner().clone();
        Box::pin(async move {
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM grants WHERE subject = $1 AND status = 'active' ORDER BY id FOR UPDATE"
            ))
            .bind(subject)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            rows.iter().map(from_row).collect()
        })
    }
}
