use std::sync::Arc;

use komainu_domain::{Password, Secret, Subject, UserId, Username};

use crate::port::{
    AuthenticationOutcome, BoxFuture, LoginCredentials, PasswordHasher, ResourceOwnerAuthenticator,
    StoreError, UnitOfWork,
};

/// Authenticates against the built-in user store.
pub struct BuiltinAuthenticator {
    hasher: Arc<dyn PasswordHasher>,
}

impl BuiltinAuthenticator {
    pub fn new(hasher: Arc<dyn PasswordHasher>) -> Self {
        Self { hasher }
    }
}

impl ResourceOwnerAuthenticator for BuiltinAuthenticator {
    fn authenticate<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        credentials: &'a LoginCredentials,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, StoreError>> {
        Box::pin(async move {
            // The length rule does not depend on whether the user exists, so
            // returning early leaks nothing through timing.
            let Ok(password) = Password::try_new(Secret::new(
                credentials.password.expose_secret_ref().clone(),
            )) else {
                return Ok(AuthenticationOutcome::InvalidCredentials);
            };
            let user = match Username::try_new(credentials.username.clone()) {
                Ok(username) => uow.users().find_by_username(&username).await?,
                Err(_) => None,
            };
            let Some(user) = user else {
                self.hasher.verify_dummy(&password).await;
                return Ok(AuthenticationOutcome::InvalidCredentials);
            };
            if !self.hasher.verify(&password, user.password_hash()).await {
                return Ok(AuthenticationOutcome::InvalidCredentials);
            }
            if !user.is_active() {
                return Ok(AuthenticationOutcome::Disabled);
            }
            Ok(AuthenticationOutcome::Authenticated(user.subject()))
        })
    }

    fn is_active<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        subject: &'a Subject,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let Ok(id) = uuid::Uuid::parse_str(subject.as_inner()) else {
                return Ok(false);
            };
            let user = uow.users().find(UserId::new(id)).await?;
            Ok(user.is_some_and(|u| u.is_active()))
        })
    }
}
