//! `authorization_requests` table.

use komainu_application::{AuthorizationRequestRepository, BoxFuture, StoreError};
use komainu_domain::*;
use sqlx::postgres::PgRow;
use std::str::FromStr;

use crate::codec::{col, hash_from_db, hash_to_db, scope_from_db, scope_to_db, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

fn from_row(row: &PgRow) -> Result<AuthorizationRequest, StoreError> {
    let state = col::<Option<String>>(row, "state")?
        .map(|s| valid(State::try_new(s), "authorization_requests.state"))
        .transpose()?;
    let subject = col::<Option<String>>(row, "subject")?
        .map(|s| valid(Subject::try_new(s), "authorization_requests.subject"))
        .transpose()?;
    Ok(AuthorizationRequest::from_record(
        AuthorizationRequestRecord {
            id: AuthorizationRequestId::new(col(row, "id")?),
            client_id: valid(
                ClientId::try_new(col(row, "client_id")?),
                "authorization_requests.client_id",
            )?,
            redirect_uri: valid(
                RedirectUri::try_new(col(row, "redirect_uri")?),
                "authorization_requests.redirect_uri",
            )?,
            redirect_uri_provided: col(row, "redirect_uri_provided")?,
            scope: scope_from_db(col(row, "scope")?, "authorization_requests.scope")?,
            state,
            csrf_token_hash: hash_from_db(
                col(row, "csrf_token_hash")?,
                "authorization_requests.csrf_token_hash",
            )?,
            pkce: PkceChallenge::new(
                valid(
                    CodeChallenge::try_new(col(row, "code_challenge")?),
                    "authorization_requests.code_challenge",
                )?,
                valid(
                    col::<String>(row, "code_challenge_method")?.parse(),
                    "authorization_requests.code_challenge_method",
                )?,
            ),
            status: AuthorizationRequestStatus::from_str(&col::<String>(row, "status")?)
                .map_err(|_| corrupted("authorization_requests.status"))?,
            subject,
            created_at: col(row, "created_at")?,
            updated_at: col(row, "updated_at")?,
            expires_at: col(row, "expires_at")?,
        },
    ))
}

impl AuthorizationRequestRepository for PgUnitOfWork {
    fn find_for_update(
        &mut self,
        id: AuthorizationRequestId,
    ) -> BoxFuture<'_, Result<Option<AuthorizationRequest>, StoreError>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, client_id, redirect_uri, redirect_uri_provided, scope, state, \
                 csrf_token_hash, code_challenge, code_challenge_method, status, subject, \
                 created_at, updated_at, expires_at \
                 FROM authorization_requests WHERE id = $1 FOR UPDATE",
            )
            .bind(id.as_inner())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.as_ref().map(from_row).transpose()
        })
    }

    fn insert(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = request.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO authorization_requests (id, client_id, redirect_uri, \
                 redirect_uri_provided, scope, state, csrf_token_hash, code_challenge, \
                 code_challenge_method, status, subject, created_at, updated_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(r.id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(r.redirect_uri.as_str())
            .bind(r.redirect_uri_provided)
            .bind(scope_to_db(&r.scope))
            .bind(r.state.as_ref().map(|s| s.as_inner()))
            .bind(hash_to_db(&r.csrf_token_hash))
            .bind(r.pkce.challenge().as_inner())
            .bind(r.pkce.method().as_str())
            .bind(r.status.as_str())
            .bind(r.subject.as_ref().map(|s| s.as_inner()))
            .bind(r.created_at)
            .bind(r.updated_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = request.to_record();
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE authorization_requests SET client_id = $2, redirect_uri = $3, \
                 redirect_uri_provided = $4, scope = $5, state = $6, csrf_token_hash = $7, \
                 code_challenge = $8, code_challenge_method = $9, status = $10, subject = $11, \
                 created_at = $12, updated_at = $13, expires_at = $14 \
                 WHERE id = $1",
            )
            .bind(r.id.as_inner())
            .bind(r.client_id.as_inner())
            .bind(r.redirect_uri.as_str())
            .bind(r.redirect_uri_provided)
            .bind(scope_to_db(&r.scope))
            .bind(r.state.as_ref().map(|s| s.as_inner()))
            .bind(hash_to_db(&r.csrf_token_hash))
            .bind(r.pkce.challenge().as_inner())
            .bind(r.pkce.method().as_str())
            .bind(r.status.as_str())
            .bind(r.subject.as_ref().map(|s| s.as_inner()))
            .bind(r.created_at)
            .bind(r.updated_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("authorization request"));
            }
            Ok(())
        })
    }
}
