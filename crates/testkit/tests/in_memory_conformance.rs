//! The in-memory store passes the conformance cases, and a deliberately broken store does not.

use std::sync::Arc;

use komainu_application::*;
use komainu_domain::*;
use komainu_testkit::InMemoryUnitOfWorkFactory;
use komainu_testkit::conformance::{run_store_conformance, store_cases};

fn in_memory() -> Arc<dyn UnitOfWorkFactory> {
    Arc::new(InMemoryUnitOfWorkFactory::new())
}

#[tokio::test]
async fn in_memory_store_passes() {
    run_store_conformance(|| async { in_memory() }).await;
}

#[test]
fn fourteen_cases_with_the_documented_names() {
    let names: Vec<_> = store_cases().iter().map(|case| case.name).collect();
    assert_eq!(
        names,
        [
            "client_user_session_roundtrip",
            "authorization_flow_records_roundtrip",
            "grant_revoked_by_client_request_roundtrip",
            "audit_append_commits",
            "dropped_uow_is_rolled_back",
            "unique_violation_is_conflict",
            "client_duplicate_id_is_conflict",
            "purge_expired_deletes_only_expired_rows",
            "purge_audit_events_deletes_old_events",
            "concurrent_code_redemption_has_one_winner",
            "private_key_jwt_client_and_jwt_bearer_grant_roundtrip",
            "trusted_issuer_roundtrip",
            "subject_mapping_roundtrip",
            "used_assertion_replay",
        ]
    );
}

#[tokio::test]
async fn cases_can_run_one_by_one() {
    for case in store_cases() {
        (case.run)(in_memory())
            .await
            .unwrap_or_else(|failure| panic!("{}: {failure}", case.name));
    }
}

#[tokio::test]
async fn a_broken_store_is_reported_by_name() {
    let result = tokio::spawn(run_store_conformance(|| async {
        Arc::new(BrokenFactory(InMemoryUnitOfWorkFactory::new())) as Arc<dyn UnitOfWorkFactory>
    }))
    .await;
    let error = result.expect_err("the broken store must fail the conformance run");
    let message = error
        .into_panic()
        .downcast::<String>()
        .map(|message| *message)
        .unwrap_or_default();
    assert!(
        message.contains("client_duplicate_id_is_conflict"),
        "{message}"
    );
}

/// Wraps the in-memory store; `clients().insert` swallows `Conflict`.
struct BrokenFactory(InMemoryUnitOfWorkFactory);

impl UnitOfWorkFactory for BrokenFactory {
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn UnitOfWork>, StoreError>> {
        Box::pin(async move {
            let inner = self.0.begin().await?;
            Ok(Box::new(BrokenUow { inner }) as Box<dyn UnitOfWork>)
        })
    }

    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        self.0.ping()
    }
}

struct BrokenUow {
    inner: Box<dyn UnitOfWork>,
}

impl UnitOfWork for BrokenUow {
    fn clients(&mut self) -> &mut dyn ClientRepository {
        self
    }
    fn users(&mut self) -> &mut dyn UserRepository {
        self.inner.users()
    }
    fn login_sessions(&mut self) -> &mut dyn LoginSessionRepository {
        self.inner.login_sessions()
    }
    fn authorization_requests(&mut self) -> &mut dyn AuthorizationRequestRepository {
        self.inner.authorization_requests()
    }
    fn authorization_codes(&mut self) -> &mut dyn AuthorizationCodeRepository {
        self.inner.authorization_codes()
    }
    fn consents(&mut self) -> &mut dyn ConsentRepository {
        self.inner.consents()
    }
    fn grants(&mut self) -> &mut dyn GrantRepository {
        self.inner.grants()
    }
    fn access_tokens(&mut self) -> &mut dyn AccessTokenRepository {
        self.inner.access_tokens()
    }
    fn refresh_tokens(&mut self) -> &mut dyn RefreshTokenRepository {
        self.inner.refresh_tokens()
    }
    fn audit_log(&mut self) -> &mut dyn AuditLogRepository {
        self.inner.audit_log()
    }
    fn trusted_issuers(&mut self) -> &mut dyn TrustedIssuerRepository {
        self.inner.trusted_issuers()
    }
    fn subject_mappings(&mut self) -> &mut dyn SubjectMappingRepository {
        self.inner.subject_mappings()
    }
    fn used_assertions(&mut self) -> &mut dyn UsedAssertionRepository {
        self.inner.used_assertions()
    }
    fn purge(&mut self) -> &mut dyn PurgeRepository {
        self.inner.purge()
    }
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), StoreError>> {
        self.inner.commit()
    }
}

impl ClientRepository for BrokenUow {
    fn find(&mut self, id: &ClientId) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        self.inner.clients().find(id)
    }
    fn find_for_update(
        &mut self,
        id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        self.inner.clients().find_for_update(id)
    }
    fn insert(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        let result = self.inner.clients().insert(client);
        Box::pin(async move {
            match result.await {
                Err(StoreError::Conflict) => Ok(()),
                other => other,
            }
        })
    }
    fn update(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        self.inner.clients().update(client)
    }
    fn list(
        &mut self,
        page: &ListPage<ClientId>,
    ) -> BoxFuture<'_, Result<Vec<Client>, StoreError>> {
        self.inner.clients().list(page)
    }
}
