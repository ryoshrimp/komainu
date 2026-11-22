//! The PostgreSQL unit of work: one transaction behind all repositories.

use komainu_application::{
    AccessTokenRepository, AuditLogRepository, AuthorizationCodeRepository,
    AuthorizationRequestRepository, BoxFuture, ClientRepository, ConsentRepository,
    GrantRepository, LoginSessionRepository, PurgeRepository, RefreshTokenRepository, StoreError,
    UnitOfWork, UnitOfWorkFactory, UserRepository,
};
use sqlx::{PgPool, Postgres, Transaction};

use crate::error::map_sqlx;

/// Starts transactions on a shared connection pool.
#[derive(Clone, Debug)]
pub struct PgUnitOfWorkFactory {
    pool: PgPool,
}

impl PgUnitOfWorkFactory {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl UnitOfWorkFactory for PgUnitOfWorkFactory {
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn UnitOfWork>, StoreError>> {
        Box::pin(async move {
            let tx = self.pool.begin().await.map_err(map_sqlx)?;
            Ok(Box::new(PgUnitOfWork { tx }) as Box<dyn UnitOfWork>)
        })
    }

    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move {
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(map_sqlx)
        })
    }
}

/// A transaction. Dropping it without `commit` rolls back.
pub(crate) struct PgUnitOfWork {
    pub(crate) tx: Transaction<'static, Postgres>,
}

impl UnitOfWork for PgUnitOfWork {
    fn clients(&mut self) -> &mut dyn ClientRepository {
        self
    }
    fn users(&mut self) -> &mut dyn UserRepository {
        self
    }
    fn login_sessions(&mut self) -> &mut dyn LoginSessionRepository {
        self
    }
    fn authorization_requests(&mut self) -> &mut dyn AuthorizationRequestRepository {
        self
    }
    fn authorization_codes(&mut self) -> &mut dyn AuthorizationCodeRepository {
        self
    }
    fn consents(&mut self) -> &mut dyn ConsentRepository {
        self
    }
    fn grants(&mut self) -> &mut dyn GrantRepository {
        self
    }
    fn access_tokens(&mut self) -> &mut dyn AccessTokenRepository {
        self
    }
    fn refresh_tokens(&mut self) -> &mut dyn RefreshTokenRepository {
        self
    }
    fn audit_log(&mut self) -> &mut dyn AuditLogRepository {
        self
    }
    fn purge(&mut self) -> &mut dyn PurgeRepository {
        self
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), StoreError>> {
        Box::pin(async move { self.tx.commit().await.map_err(map_sqlx) })
    }
}
