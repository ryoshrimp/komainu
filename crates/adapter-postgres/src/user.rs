//! `users` table.

use komainu_application::{BoxFuture, ListPage, StoreError, UserRepository};
use komainu_domain::*;
use sqlx::postgres::PgRow;
use std::str::FromStr;

use crate::codec::{col, valid};
use crate::error::{corrupted, map_sqlx, not_found};
use crate::uow::PgUnitOfWork;

macro_rules! columns {
    () => {
        "id, username, password_hash, status, created_at, updated_at"
    };
}

fn from_row(row: &PgRow) -> Result<User, StoreError> {
    Ok(User::from_record(UserRecord {
        id: UserId::new(col(row, "id")?),
        username: valid(Username::try_new(col(row, "username")?), "users.username")?,
        password_hash: valid(
            PasswordHash::try_new(col(row, "password_hash")?),
            "users.password_hash",
        )?,
        status: UserStatus::from_str(&col::<String>(row, "status")?)
            .map_err(|_| corrupted("users.status"))?,
        created_at: col(row, "created_at")?,
        updated_at: col(row, "updated_at")?,
    }))
}

impl PgUnitOfWork {
    async fn select_user(
        &mut self,
        id: UserId,
        for_update: bool,
    ) -> Result<Option<User>, StoreError> {
        let sql = if for_update {
            concat!(
                "SELECT ",
                columns!(),
                " FROM users WHERE id = $1 FOR UPDATE"
            )
        } else {
            concat!("SELECT ", columns!(), " FROM users WHERE id = $1")
        };
        let row = sqlx::query(sql)
            .bind(id.as_inner())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
        row.as_ref().map(from_row).transpose()
    }
}

impl UserRepository for PgUnitOfWork {
    fn find(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        Box::pin(self.select_user(id, false))
    }

    fn find_for_update(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        Box::pin(self.select_user(id, true))
    }

    fn find_by_username(
        &mut self,
        username: &Username,
    ) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        let username = username.as_str().to_owned();
        Box::pin(async move {
            let row = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM users WHERE username = $1"
            ))
            .bind(username)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            row.as_ref().map(from_row).transpose()
        })
    }

    fn insert(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = user.to_record();
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, status, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(r.id.as_inner())
            .bind(r.username.as_str())
            .bind(r.password_hash.as_inner())
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }

    fn update(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>> {
        let r = user.to_record();
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE users SET username = $2, password_hash = $3, status = $4, \
                 created_at = $5, updated_at = $6 WHERE id = $1",
            )
            .bind(r.id.as_inner())
            .bind(r.username.as_str())
            .bind(r.password_hash.as_inner())
            .bind(r.status.as_str())
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut *self.tx)
            .await
            .map_err(map_sqlx)?;
            if done.rows_affected() == 0 {
                return Err(not_found("user"));
            }
            Ok(())
        })
    }

    fn list(&mut self, page: &ListPage<Username>) -> BoxFuture<'_, Result<Vec<User>, StoreError>> {
        let after = page.after.as_ref().map(|u| u.as_str().to_owned());
        let limit = i64::from(page.limit);
        Box::pin(async move {
            // COLLATE "C" gives byte order, the same as the in-memory store's `Ord`.
            let rows = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM users WHERE ($1::text IS NULL OR username COLLATE \"C\" > $1::text COLLATE \"C\") \
                 ORDER BY username COLLATE \"C\" LIMIT $2"
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
