use super::BoxFuture;
use super::repository::*;

#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    /// Unique constraint violation (e.g. duplicate username).
    #[error("conflict")]
    Conflict,
    /// Connection failure, pool timeout, serialization failure.
    #[error("store unavailable: {0}")]
    Unavailable(String),
    #[error("store error: {0}")]
    Other(String),
}

pub trait UnitOfWorkFactory: Send + Sync + 'static {
    /// Begins a transaction (READ COMMITTED).
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn UnitOfWork>, StoreError>>;
    /// Readiness check. Ok when the store accepts queries.
    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>>;
}

/// Dropping without commit rolls back.
pub trait UnitOfWork: Send {
    fn clients(&mut self) -> &mut dyn ClientRepository;
    fn users(&mut self) -> &mut dyn UserRepository;
    fn login_sessions(&mut self) -> &mut dyn LoginSessionRepository;
    fn authorization_requests(&mut self) -> &mut dyn AuthorizationRequestRepository;
    fn authorization_codes(&mut self) -> &mut dyn AuthorizationCodeRepository;
    fn consents(&mut self) -> &mut dyn ConsentRepository;
    fn grants(&mut self) -> &mut dyn GrantRepository;
    fn access_tokens(&mut self) -> &mut dyn AccessTokenRepository;
    fn refresh_tokens(&mut self) -> &mut dyn RefreshTokenRepository;
    fn audit_log(&mut self) -> &mut dyn AuditLogRepository;
    fn trusted_issuers(&mut self) -> &mut dyn TrustedIssuerRepository;
    fn subject_mappings(&mut self) -> &mut dyn SubjectMappingRepository;
    fn used_assertions(&mut self) -> &mut dyn UsedAssertionRepository;
    fn signing_keys(&mut self) -> &mut dyn SigningKeyRepository;
    fn purge(&mut self) -> &mut dyn PurgeRepository;
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), StoreError>>;
}

#[derive(Debug, Clone)]
pub struct ListPage<K> {
    /// Returns items whose key is strictly greater than this.
    pub after: Option<K>,
    /// 1..=1000. Callers clamp.
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeCounts {
    pub authorization_requests: u64,
    pub authorization_codes: u64,
    pub access_tokens: u64,
    pub refresh_tokens: u64,
    pub login_sessions: u64,
    pub grants: u64,
    pub used_assertions: u64,
}
