//! `login_sessions` table.

use komainu_application::{BoxFuture, LoginSessionRepository, StoreError};
use komainu_domain::*;

use crate::codec::{col, hash_from_db, hash_to_db, valid};
use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl LoginSessionRepository for PgUnitOfWork {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<LoginSession>, StoreError>> {
        let id = *id;
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, subject, created_at, expires_at FROM login_sessions WHERE id = $1",
            )
            .bind(hash_to_db(&id))
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.map(|row| {
                Ok(LoginSession::from_record(LoginSessionRecord {
                    id: hash_from_db(col(&row, "id")?, "login_sessions.id")?,
                    subject: valid(
                        Subject::try_new(col(&row, "subject")?),
                        "login_sessions.subject",
                    )?,
                    created_at: col(&row, "created_at")?,
                    expires_at: col(&row, "expires_at")?,
                }))
            })
            .transpose()
        })
    }

    fn insert(&mut self, session: &LoginSession) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = session.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO login_sessions (id, subject, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(hash_to_db(&r.id))
            .bind(r.subject.as_inner())
            .bind(r.created_at)
            .bind(r.expires_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn delete(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<(), StoreError>> {
        let id = *id;
        Box::pin(async move {
            sqlx::query("DELETE FROM login_sessions WHERE id = $1")
                .bind(hash_to_db(&id))
                .execute(&mut *self.tx)
                .await
                .map(|_| ())
                .map_err(map_sqlx)
        })
    }

    fn delete_by_subject(&mut self, subject: &Subject) -> BoxFuture<'_, Result<u64, StoreError>> {
        let subject = subject.as_inner().clone();
        Box::pin(async move {
            sqlx::query("DELETE FROM login_sessions WHERE subject = $1")
                .bind(subject)
                .execute(&mut *self.tx)
                .await
                .map(|done| done.rows_affected())
                .map_err(map_sqlx)
        })
    }
}
