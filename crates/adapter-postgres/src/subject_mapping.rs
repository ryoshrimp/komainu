//! `issuer_subjects` table.

use komainu_application::{BoxFuture, ListPage, StoreError, SubjectMappingRepository};
use komainu_domain::*;
use sqlx::postgres::PgRow;

use crate::codec::{col, valid};
use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

macro_rules! columns {
    () => {
        "issuer_id, subject, user_id, updated_at"
    };
}

fn from_row(row: &PgRow) -> Result<SubjectMapping, StoreError> {
    Ok(SubjectMapping {
        issuer_id: valid(
            IssuerId::try_new(col(row, "issuer_id")?),
            "issuer_subjects.issuer_id",
        )?,
        subject: valid(
            ExternalSubject::try_new(col(row, "subject")?),
            "issuer_subjects.subject",
        )?,
        user_id: UserId::new(col(row, "user_id")?),
        updated_at: col(row, "updated_at")?,
    })
}

impl SubjectMappingRepository for PgUnitOfWork {
    fn find(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<Option<SubjectMapping>, StoreError>> {
        let issuer_id = issuer_id.as_inner().clone();
        let subject = subject.as_inner().clone();
        Box::pin(async move {
            let row = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM issuer_subjects WHERE issuer_id = $1 AND subject = $2"
            ))
            .bind(issuer_id)
            .bind(subject)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.as_ref().map(from_row).transpose()
        })
    }

    fn upsert(&mut self, mapping: &SubjectMapping) -> BoxFuture<'_, Result<(), StoreError>> {
        let m = mapping.clone();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO issuer_subjects (issuer_id, subject, user_id, updated_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (issuer_id, subject) \
                 DO UPDATE SET user_id = EXCLUDED.user_id, updated_at = EXCLUDED.updated_at",
            )
            .bind(m.issuer_id.as_inner())
            .bind(m.subject.as_inner())
            .bind(m.user_id.as_inner())
            .bind(m.updated_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn delete(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<bool, StoreError>> {
        let issuer_id = issuer_id.as_inner().clone();
        let subject = subject.as_inner().clone();
        Box::pin(async move {
            sqlx::query("DELETE FROM issuer_subjects WHERE issuer_id = $1 AND subject = $2")
                .bind(issuer_id)
                .bind(subject)
                .execute(&mut *self.tx)
                .await
                .map(|done| done.rows_affected() > 0)
                .map_err(map_sqlx)
        })
    }

    fn list_by_issuer(
        &mut self,
        issuer_id: &IssuerId,
        page: &ListPage<ExternalSubject>,
    ) -> BoxFuture<'_, Result<Vec<SubjectMapping>, StoreError>> {
        let issuer_id = issuer_id.as_inner().clone();
        let after = page.after.as_ref().map(|s| s.as_inner().clone());
        let limit = i64::from(page.limit);
        Box::pin(async move {
            // COLLATE "C" gives byte order, the same as the in-memory store's `Ord`.
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM issuer_subjects WHERE issuer_id = $1 \
                 AND ($2::text IS NULL OR subject COLLATE \"C\" > $2::text COLLATE \"C\") \
                 ORDER BY subject COLLATE \"C\" LIMIT $3"
            ))
            .bind(issuer_id)
            .bind(after)
            .bind(limit)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            rows.iter().map(from_row).collect()
        })
    }
}
