//! `authorization_codes` table. `Redeemed { grant_id, redeemed_at }` is split over two columns.

use komainu_application::{AuthorizationCodeRepository, BoxFuture, StoreError};
use komainu_domain::*;
use sqlx::postgres::PgRow;

use crate::codec::{col, hash_from_db, hash_to_db, scope_from_db, scope_to_db, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

/// Returns `(status, grant_id, redeemed_at)` column values.
fn status_to_db(
    status: &AuthorizationCodeStatus,
) -> (
    &'static str,
    Option<uuid::Uuid>,
    Option<time::OffsetDateTime>,
) {
    match status {
        AuthorizationCodeStatus::Issued => ("issued", None, None),
        AuthorizationCodeStatus::Redeemed {
            grant_id,
            redeemed_at,
        } => ("redeemed", Some(*grant_id.as_inner()), Some(*redeemed_at)),
    }
}

fn from_row(row: &PgRow) -> Result<AuthorizationCode, StoreError> {
    let grant_id = col::<Option<uuid::Uuid>>(row, "grant_id")?;
    let redeemed_at = col::<Option<time::OffsetDateTime>>(row, "redeemed_at")?;
    let status = match (
        col::<String>(row, "status")?.as_str(),
        grant_id,
        redeemed_at,
    ) {
        ("issued", None, None) => AuthorizationCodeStatus::Issued,
        ("redeemed", Some(grant_id), Some(redeemed_at)) => AuthorizationCodeStatus::Redeemed {
            grant_id: GrantId::new(grant_id),
            redeemed_at,
        },
        _ => return Err(corrupted("authorization_codes.status")),
    };
    Ok(AuthorizationCode::from_record(AuthorizationCodeRecord {
        id: hash_from_db(col(row, "id")?, "authorization_codes.id")?,
        client_id: valid(
            ClientId::try_new(col(row, "client_id")?),
            "authorization_codes.client_id",
        )?,
        subject: valid(
            Subject::try_new(col(row, "subject")?),
            "authorization_codes.subject",
        )?,
        redirect_uri: valid(
            RedirectUri::try_new(col(row, "redirect_uri")?),
            "authorization_codes.redirect_uri",
        )?,
        redirect_uri_provided: col(row, "redirect_uri_provided")?,
        scope: scope_from_db(col(row, "scope")?, "authorization_codes.scope")?,
        pkce: PkceChallenge::new(
            valid(
                CodeChallenge::try_new(col(row, "code_challenge")?),
                "authorization_codes.code_challenge",
            )?,
            valid(
                col::<String>(row, "code_challenge_method")?.parse(),
                "authorization_codes.code_challenge_method",
            )?,
        ),
        status,
        issued_at: col(row, "issued_at")?,
        expires_at: col(row, "expires_at")?,
    }))
}

impl AuthorizationCodeRepository for PgUnitOfWork {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<AuthorizationCode>, StoreError>> {
        let id = *id;
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, client_id, subject, redirect_uri, redirect_uri_provided, scope, \
                 code_challenge, code_challenge_method, status, grant_id, redeemed_at, issued_at, expires_at \
                 FROM authorization_codes WHERE id = $1 FOR UPDATE",
            )
            .bind(hash_to_db(&id))
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.as_ref().map(from_row).transpose()
        })
    }

    fn insert(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = code.to_record();
        Box::pin(async move {
            let (status, grant_id, redeemed_at) = status_to_db(&r.status);
            sqlx::query(
                "INSERT INTO authorization_codes (id, client_id, subject, redirect_uri, \
                 redirect_uri_provided, scope, code_challenge, code_challenge_method, status, \
                 grant_id, redeemed_at, issued_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.client_id.as_inner())
            .bind(r.subject.as_inner())
            .bind(r.redirect_uri.as_str())
            .bind(r.redirect_uri_provided)
            .bind(scope_to_db(&r.scope))
            .bind(r.pkce.challenge().as_inner())
            .bind(r.pkce.method().as_str())
            .bind(status)
            .bind(grant_id)
            .bind(redeemed_at)
            .bind(r.issued_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = code.to_record();
        Box::pin(async move {
            let (status, grant_id, redeemed_at) = status_to_db(&r.status);
            let done = sqlx::query(
                "UPDATE authorization_codes SET client_id = $2, subject = $3, redirect_uri = $4, \
                 redirect_uri_provided = $5, scope = $6, \
                 code_challenge = $7, code_challenge_method = $8, status = $9, grant_id = $10, \
                 redeemed_at = $11, issued_at = $12, expires_at = $13 WHERE id = $1",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.client_id.as_inner())
            .bind(r.subject.as_inner())
            .bind(r.redirect_uri.as_str())
            .bind(r.redirect_uri_provided)
            .bind(scope_to_db(&r.scope))
            .bind(r.pkce.challenge().as_inner())
            .bind(r.pkce.method().as_str())
            .bind(status)
            .bind(grant_id)
            .bind(redeemed_at)
            .bind(r.issued_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("authorization code"));
            }
            Ok(())
        })
    }
}
