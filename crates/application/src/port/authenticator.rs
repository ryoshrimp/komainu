use komainu_domain::{Secret, Subject};

use super::{BoxFuture, StoreError, UnitOfWork};

#[derive(Debug)]
pub struct LoginCredentials {
    /// Raw input; the built-in authenticator normalizes it with Username::try_new.
    pub username: String,
    /// Raw input. The built-in authenticator converts it with Password::try_new;
    /// on failure it returns InvalidCredentials (still audited as login.failed).
    pub password: Secret<String>,
}

#[derive(Debug)]
pub enum AuthenticationOutcome {
    Authenticated(Subject),
    InvalidCredentials,
    Disabled,
}

pub trait ResourceOwnerAuthenticator: Send + Sync + 'static {
    /// The uow is the caller's transaction. Implementations that do not use the store may ignore it.
    fn authenticate<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        credentials: &'a LoginCredentials,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, StoreError>>;
    /// Whether the subject may still use the server (checked on every session use).
    fn is_active<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        subject: &'a Subject,
    ) -> BoxFuture<'a, Result<bool, StoreError>>;
}
