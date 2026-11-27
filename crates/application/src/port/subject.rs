use komainu_domain::{ExternalSubject, TrustedIssuer, UserId};

use super::{BoxFuture, StoreError, UnitOfWork};

/// Maps the `sub` of an assertion to a komainu user.
pub trait AssertionSubjectResolver: Send + Sync + 'static {
    /// Returns `Ok(None)` if no user corresponds. Does not look at the user's state (the caller does).
    fn resolve<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        issuer: &'a TrustedIssuer,
        subject: &'a ExternalSubject,
    ) -> BoxFuture<'a, Result<Option<UserId>, StoreError>>;
}

/// The default resolver: the `user_id` of the `(issuer, subject)` row of the mapping table.
#[derive(Debug, Default, Clone, Copy)]
pub struct MappingTableSubjectResolver;

impl AssertionSubjectResolver for MappingTableSubjectResolver {
    fn resolve<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        issuer: &'a TrustedIssuer,
        subject: &'a ExternalSubject,
    ) -> BoxFuture<'a, Result<Option<UserId>, StoreError>> {
        Box::pin(async move {
            let mapping = uow.subject_mappings().find(issuer.id(), subject).await?;
            Ok(mapping.map(|m| m.user_id))
        })
    }
}
