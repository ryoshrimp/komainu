use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use komainu_application::*;
use komainu_domain::*;
use time::OffsetDateTime;

/// Everything the in-memory store holds. Cloned on `begin`, replaced on `commit`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryState {
    pub clients: BTreeMap<ClientId, ClientRecord>,
    pub users: BTreeMap<UserId, UserRecord>,
    pub login_sessions: BTreeMap<TokenHash, LoginSessionRecord>,
    pub authorization_requests: BTreeMap<AuthorizationRequestId, AuthorizationRequestRecord>,
    pub authorization_codes: BTreeMap<TokenHash, AuthorizationCodeRecord>,
    pub consents: BTreeMap<ConsentId, ConsentRecord>,
    pub grants: BTreeMap<GrantId, GrantRecord>,
    pub access_tokens: BTreeMap<TokenHash, AccessTokenRecord>,
    pub refresh_tokens: BTreeMap<TokenHash, RefreshTokenRecord>,
    pub trusted_issuers: BTreeMap<IssuerId, TrustedIssuerRecord>,
    pub subject_mappings: BTreeMap<(IssuerId, ExternalSubject), SubjectMapping>,
    /// Keyed by `(kind, issuer, jti)`; the value is `expires_at`.
    pub used_assertions: BTreeMap<(AssertionKind, String, String), OffsetDateTime>,
    /// Keyed by `kid`.
    pub signing_keys: BTreeMap<String, ServerSigningKey>,
    pub audit_events: Vec<AuditEvent>,
}

/// Snapshot-and-replace store. Not safe for concurrent writers (tests are sequential).
#[derive(Clone, Default)]
pub struct InMemoryUnitOfWorkFactory {
    committed: Arc<Mutex<InMemoryState>>,
    fail_next: Arc<AtomicBool>,
}

impl InMemoryUnitOfWorkFactory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Committed audit events in append order.
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.committed.lock().unwrap().audit_events.clone()
    }

    /// Committed state, for assertions.
    pub fn state(&self) -> InMemoryState {
        self.committed.lock().unwrap().clone()
    }

    /// The next begin()/ping() returns StoreError::Unavailable.
    pub fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    fn check_failure(&self) -> Result<(), StoreError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            Err(StoreError::Unavailable("injected failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

impl UnitOfWorkFactory for InMemoryUnitOfWorkFactory {
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn UnitOfWork>, StoreError>> {
        let result = self.check_failure().map(|()| {
            Box::new(InMemoryUnitOfWork {
                committed: Arc::clone(&self.committed),
                working: self.state(),
            }) as Box<dyn UnitOfWork>
        });
        ready(result)
    }

    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        ready(self.check_failure())
    }
}

/// A transaction: a copy of the committed state that `commit` swaps back in.
struct InMemoryUnitOfWork {
    committed: Arc<Mutex<InMemoryState>>,
    working: InMemoryState,
}

fn ready<'a, T: Send + 'a>(value: T) -> BoxFuture<'a, T> {
    Box::pin(std::future::ready(value))
}

fn insert_unique<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<(), StoreError> {
    if map.contains_key(&key) {
        return Err(StoreError::Conflict);
    }
    map.insert(key, value);
    Ok(())
}

fn replace_existing<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    what: &str,
) -> Result<(), StoreError> {
    match map.get_mut(&key) {
        Some(slot) => {
            *slot = value;
            Ok(())
        }
        None => Err(StoreError::Other(format!("{what} not found"))),
    }
}

fn delete_where<K: Ord, V>(map: &mut BTreeMap<K, V>, pred: impl Fn(&V) -> bool) -> u64 {
    let before = map.len();
    map.retain(|_, v| !pred(v));
    (before - map.len()) as u64
}

impl UnitOfWork for InMemoryUnitOfWork {
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
    fn trusted_issuers(&mut self) -> &mut dyn TrustedIssuerRepository {
        self
    }
    fn subject_mappings(&mut self) -> &mut dyn SubjectMappingRepository {
        self
    }
    fn used_assertions(&mut self) -> &mut dyn UsedAssertionRepository {
        self
    }
    fn signing_keys(&mut self) -> &mut dyn SigningKeyRepository {
        self
    }
    fn purge(&mut self) -> &mut dyn PurgeRepository {
        self
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), StoreError>> {
        let this = *self;
        *this.committed.lock().unwrap() = this.working;
        ready(Ok(()))
    }
}

impl ClientRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: &ClientId) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        let found = self
            .working
            .clients
            .get(id)
            .cloned()
            .map(Client::from_record);
        ready(Ok(found))
    }

    fn find_for_update(
        &mut self,
        id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Client>, StoreError>> {
        ClientRepository::find(self, id)
    }

    fn insert(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = client.to_record();
        ready(insert_unique(
            &mut self.working.clients,
            record.id.clone(),
            record,
        ))
    }

    fn update(&mut self, client: &Client) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = client.to_record();
        ready(replace_existing(
            &mut self.working.clients,
            record.id.clone(),
            record,
            "client",
        ))
    }

    fn list(
        &mut self,
        page: &ListPage<ClientId>,
    ) -> BoxFuture<'_, Result<Vec<Client>, StoreError>> {
        let items = self
            .working
            .clients
            .iter()
            .filter(|(id, _)| page.after.as_ref().is_none_or(|after| *id > after))
            .take(page.limit as usize)
            .map(|(_, r)| Client::from_record(r.clone()))
            .collect();
        ready(Ok(items))
    }
}

impl UserRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        let found = self.working.users.get(&id).cloned().map(User::from_record);
        ready(Ok(found))
    }

    fn find_for_update(&mut self, id: UserId) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        UserRepository::find(self, id)
    }

    fn find_by_username(
        &mut self,
        username: &Username,
    ) -> BoxFuture<'_, Result<Option<User>, StoreError>> {
        let found = self
            .working
            .users
            .values()
            .find(|r| r.username == *username)
            .cloned()
            .map(User::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = user.to_record();
        let duplicate_name = self
            .working
            .users
            .values()
            .any(|r| r.username == record.username);
        let result = if duplicate_name {
            Err(StoreError::Conflict)
        } else {
            insert_unique(&mut self.working.users, record.id, record)
        };
        ready(result)
    }

    fn update(&mut self, user: &User) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = user.to_record();
        let taken = self
            .working
            .users
            .values()
            .any(|r| r.id != record.id && r.username == record.username);
        let result = if taken {
            Err(StoreError::Conflict)
        } else {
            replace_existing(&mut self.working.users, record.id, record, "user")
        };
        ready(result)
    }

    fn list(&mut self, page: &ListPage<Username>) -> BoxFuture<'_, Result<Vec<User>, StoreError>> {
        let mut records: Vec<&UserRecord> = self
            .working
            .users
            .values()
            .filter(|r| page.after.as_ref().is_none_or(|after| r.username > *after))
            .collect();
        records.sort_by(|a, b| a.username.cmp(&b.username));
        let items = records
            .into_iter()
            .take(page.limit as usize)
            .map(|r| User::from_record(r.clone()))
            .collect();
        ready(Ok(items))
    }
}

impl LoginSessionRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<LoginSession>, StoreError>> {
        let found = self
            .working
            .login_sessions
            .get(id)
            .cloned()
            .map(LoginSession::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, session: &LoginSession) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = session.to_record();
        ready(insert_unique(
            &mut self.working.login_sessions,
            record.id,
            record,
        ))
    }

    fn delete(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<(), StoreError>> {
        self.working.login_sessions.remove(id);
        ready(Ok(()))
    }

    fn delete_by_subject(&mut self, subject: &Subject) -> BoxFuture<'_, Result<u64, StoreError>> {
        let deleted = delete_where(&mut self.working.login_sessions, |r| r.subject == *subject);
        ready(Ok(deleted))
    }
}

impl AuthorizationRequestRepository for InMemoryUnitOfWork {
    fn find_for_update(
        &mut self,
        id: AuthorizationRequestId,
    ) -> BoxFuture<'_, Result<Option<AuthorizationRequest>, StoreError>> {
        let found = self
            .working
            .authorization_requests
            .get(&id)
            .cloned()
            .map(AuthorizationRequest::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = request.to_record();
        ready(insert_unique(
            &mut self.working.authorization_requests,
            record.id,
            record,
        ))
    }

    fn update(&mut self, request: &AuthorizationRequest) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = request.to_record();
        ready(replace_existing(
            &mut self.working.authorization_requests,
            record.id,
            record,
            "authorization request",
        ))
    }
}

impl AuthorizationCodeRepository for InMemoryUnitOfWork {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<AuthorizationCode>, StoreError>> {
        let found = self
            .working
            .authorization_codes
            .get(id)
            .cloned()
            .map(AuthorizationCode::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = code.to_record();
        ready(insert_unique(
            &mut self.working.authorization_codes,
            record.id,
            record,
        ))
    }

    fn update(&mut self, code: &AuthorizationCode) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = code.to_record();
        ready(replace_existing(
            &mut self.working.authorization_codes,
            record.id,
            record,
            "authorization code",
        ))
    }
}

impl ConsentRepository for InMemoryUnitOfWork {
    fn find(
        &mut self,
        subject: &Subject,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Option<Consent>, StoreError>> {
        let id = ConsentId {
            subject: subject.clone(),
            client_id: client_id.clone(),
        };
        let found = self
            .working
            .consents
            .get(&id)
            .cloned()
            .map(Consent::from_record);
        ready(Ok(found))
    }

    fn upsert(&mut self, consent: &Consent) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = consent.to_record();
        self.working.consents.insert(record.id.clone(), record);
        ready(Ok(()))
    }
}

impl GrantRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>> {
        let found = self
            .working
            .grants
            .get(&id)
            .cloned()
            .map(Grant::from_record);
        ready(Ok(found))
    }

    fn find_for_update(&mut self, id: GrantId) -> BoxFuture<'_, Result<Option<Grant>, StoreError>> {
        GrantRepository::find(self, id)
    }

    fn insert(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = grant.to_record();
        ready(insert_unique(&mut self.working.grants, record.id, record))
    }

    fn update(&mut self, grant: &Grant) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = grant.to_record();
        ready(replace_existing(
            &mut self.working.grants,
            record.id,
            record,
            "grant",
        ))
    }

    fn list_active_by_client(
        &mut self,
        client_id: &ClientId,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>> {
        let items = active_grants(&self.working, |r| r.client_id == *client_id);
        ready(Ok(items))
    }

    fn list_active_by_subject(
        &mut self,
        subject: &Subject,
    ) -> BoxFuture<'_, Result<Vec<Grant>, StoreError>> {
        let items = active_grants(&self.working, |r| r.subject.as_ref() == Some(subject));
        ready(Ok(items))
    }
}

fn active_grants(state: &InMemoryState, pred: impl Fn(&GrantRecord) -> bool) -> Vec<Grant> {
    state
        .grants
        .values()
        .filter(|r| matches!(r.status, GrantStatus::Active) && pred(r))
        .cloned()
        .map(Grant::from_record)
        .collect()
}

impl AccessTokenRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: &TokenHash) -> BoxFuture<'_, Result<Option<AccessToken>, StoreError>> {
        let found = self
            .working
            .access_tokens
            .get(id)
            .cloned()
            .map(AccessToken::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, token: &AccessToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = token.to_record();
        ready(insert_unique(
            &mut self.working.access_tokens,
            record.id,
            record,
        ))
    }
}

impl RefreshTokenRepository for InMemoryUnitOfWork {
    fn find_for_update(
        &mut self,
        id: &TokenHash,
    ) -> BoxFuture<'_, Result<Option<RefreshToken>, StoreError>> {
        let found = self
            .working
            .refresh_tokens
            .get(id)
            .cloned()
            .map(RefreshToken::from_record);
        ready(Ok(found))
    }

    fn insert(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = token.to_record();
        ready(insert_unique(
            &mut self.working.refresh_tokens,
            record.id,
            record,
        ))
    }

    fn update(&mut self, token: &RefreshToken) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = token.to_record();
        ready(replace_existing(
            &mut self.working.refresh_tokens,
            record.id,
            record,
            "refresh token",
        ))
    }
}

impl AuditLogRepository for InMemoryUnitOfWork {
    fn append(&mut self, event: &AuditEvent) -> BoxFuture<'_, Result<(), StoreError>> {
        self.working.audit_events.push(event.clone());
        ready(Ok(()))
    }
}

impl TrustedIssuerRepository for InMemoryUnitOfWork {
    fn find(&mut self, id: &IssuerId) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>> {
        let found = self
            .working
            .trusted_issuers
            .get(id)
            .cloned()
            .map(TrustedIssuer::from_record);
        ready(Ok(found))
    }

    fn find_for_update(
        &mut self,
        id: &IssuerId,
    ) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>> {
        TrustedIssuerRepository::find(self, id)
    }

    fn insert(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = issuer.to_record();
        ready(insert_unique(
            &mut self.working.trusted_issuers,
            record.id.clone(),
            record,
        ))
    }

    fn update(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>> {
        let record = issuer.to_record();
        ready(replace_existing(
            &mut self.working.trusted_issuers,
            record.id.clone(),
            record,
            "trusted issuer",
        ))
    }

    fn list(
        &mut self,
        page: &ListPage<IssuerId>,
    ) -> BoxFuture<'_, Result<Vec<TrustedIssuer>, StoreError>> {
        let items = self
            .working
            .trusted_issuers
            .iter()
            .filter(|(id, _)| page.after.as_ref().is_none_or(|after| *id > after))
            .take(page.limit as usize)
            .map(|(_, r)| TrustedIssuer::from_record(r.clone()))
            .collect();
        ready(Ok(items))
    }
}

impl SubjectMappingRepository for InMemoryUnitOfWork {
    fn find(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<Option<SubjectMapping>, StoreError>> {
        let key = (issuer_id.clone(), subject.clone());
        ready(Ok(self.working.subject_mappings.get(&key).cloned()))
    }

    fn upsert(&mut self, mapping: &SubjectMapping) -> BoxFuture<'_, Result<(), StoreError>> {
        let key = (mapping.issuer_id.clone(), mapping.subject.clone());
        self.working.subject_mappings.insert(key, mapping.clone());
        ready(Ok(()))
    }

    fn delete(
        &mut self,
        issuer_id: &IssuerId,
        subject: &ExternalSubject,
    ) -> BoxFuture<'_, Result<bool, StoreError>> {
        let key = (issuer_id.clone(), subject.clone());
        ready(Ok(self.working.subject_mappings.remove(&key).is_some()))
    }

    fn list_by_issuer(
        &mut self,
        issuer_id: &IssuerId,
        page: &ListPage<ExternalSubject>,
    ) -> BoxFuture<'_, Result<Vec<SubjectMapping>, StoreError>> {
        let items = self
            .working
            .subject_mappings
            .values()
            .filter(|m| m.issuer_id == *issuer_id)
            .filter(|m| page.after.as_ref().is_none_or(|after| m.subject > *after))
            .take(page.limit as usize)
            .cloned()
            .collect();
        ready(Ok(items))
    }
}

impl UsedAssertionRepository for InMemoryUnitOfWork {
    fn record(
        &mut self,
        assertion: &UsedAssertion,
    ) -> BoxFuture<'_, Result<RecordOutcome, StoreError>> {
        let key = (
            assertion.kind,
            assertion.issuer.clone(),
            assertion.jti.clone(),
        );
        let outcome = match self.working.used_assertions.entry(key) {
            Entry::Occupied(_) => RecordOutcome::Replayed,
            Entry::Vacant(slot) => {
                slot.insert(assertion.expires_at);
                RecordOutcome::Recorded
            }
        };
        ready(Ok(outcome))
    }
}

impl SigningKeyRepository for InMemoryUnitOfWork {
    /// Does nothing: the in-memory store replaces its whole state on commit, so it cannot
    /// serialize writers.
    fn lock_rotation(&mut self) -> BoxFuture<'_, Result<(), StoreError>> {
        ready(Ok(()))
    }

    fn list(&mut self) -> BoxFuture<'_, Result<Vec<ServerSigningKey>, StoreError>> {
        let mut keys: Vec<_> = self.working.signing_keys.values().cloned().collect();
        keys.sort_by(|a, b| {
            (a.activates_at(), a.kid().as_inner()).cmp(&(b.activates_at(), b.kid().as_inner()))
        });
        ready(Ok(keys))
    }

    fn insert(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>> {
        ready(insert_unique(
            &mut self.working.signing_keys,
            key.kid().as_inner().clone(),
            key.clone(),
        ))
    }

    fn update_schedule(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>> {
        let result = match self.working.signing_keys.get_mut(key.kid().as_inner()) {
            Some(stored) => {
                let mut record = stored.to_record();
                record.activates_at = key.activates_at();
                record.retires_at = key.retires_at();
                record.deletes_at = key.deletes_at();
                *stored = ServerSigningKey::from_record(record);
                Ok(())
            }
            None => Err(StoreError::Other("signing key not found".to_owned())),
        };
        ready(result)
    }

    fn delete(&mut self, kid: &SigningKeyId) -> BoxFuture<'_, Result<bool, StoreError>> {
        ready(Ok(self
            .working
            .signing_keys
            .remove(kid.as_inner())
            .is_some()))
    }
}

impl PurgeRepository for InMemoryUnitOfWork {
    fn purge_expired(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<PurgeCounts, StoreError>> {
        let s = &mut self.working;
        let authorization_codes =
            delete_where(&mut s.authorization_codes, |r| r.expires_at <= cutoff);
        let access_tokens = delete_where(&mut s.access_tokens, |r| r.expires_at <= cutoff);
        let refresh_tokens = delete_where(&mut s.refresh_tokens, |r| r.expires_at <= cutoff);
        let authorization_requests =
            delete_where(&mut s.authorization_requests, |r| r.expires_at <= cutoff);
        let login_sessions = delete_where(&mut s.login_sessions, |r| r.expires_at <= cutoff);

        let mut referenced: BTreeSet<GrantId> = BTreeSet::new();
        referenced.extend(s.access_tokens.values().map(|r| r.grant_id));
        referenced.extend(s.refresh_tokens.values().map(|r| r.grant_id));
        referenced.extend(
            s.authorization_codes
                .values()
                .filter_map(|r| match r.status {
                    AuthorizationCodeStatus::Redeemed { grant_id, .. } => Some(grant_id),
                    AuthorizationCodeStatus::Issued => None,
                }),
        );
        let grants = delete_where(&mut s.grants, |r| {
            r.created_at <= cutoff && !referenced.contains(&r.id)
        });

        let used_assertions =
            delete_where(&mut s.used_assertions, |expires_at| *expires_at < cutoff);

        ready(Ok(PurgeCounts {
            authorization_requests,
            authorization_codes,
            access_tokens,
            refresh_tokens,
            login_sessions,
            grants,
            used_assertions,
        }))
    }

    fn purge_audit_events(
        &mut self,
        cutoff: OffsetDateTime,
    ) -> BoxFuture<'_, Result<u64, StoreError>> {
        let before = self.working.audit_events.len();
        self.working.audit_events.retain(|e| e.occurred_at > cutoff);
        ready(Ok((before - self.working.audit_events.len()) as u64))
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_util::block_on;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(1000)
    }

    fn user(n: u128, name: &str) -> User {
        User::create(
            UserId::new(uuid::Uuid::from_u128(n)),
            Username::try_new(name.to_owned()).unwrap(),
            PasswordHash::try_new("plain$pw".to_owned()).unwrap(),
            t0(),
        )
    }

    fn client(id: &str) -> Client {
        Client::register(
            NewClient {
                id: ClientId::try_new(id.to_owned()).unwrap(),
                name: ClientName::try_new("App".to_owned()).unwrap(),
                client_type: ClientType::Public,
                auth_method: TokenEndpointAuthMethod::None,
                redirect_uris: vec![
                    RedirectUri::try_new("https://a.example/cb".to_owned()).unwrap(),
                ],
                grant_types: [GrantType::AuthorizationCode].into(),
                allowed_scopes: ScopeSet::empty(),
                default_scopes: ScopeSet::empty(),
                skip_consent: false,
                keys: None,
            },
            None,
            t0(),
        )
        .unwrap()
    }

    fn hash(n: u8) -> TokenHash {
        TokenHash::from_bytes([n; 32])
    }

    fn audit(at: OffsetDateTime) -> AuditEvent {
        AuditEvent {
            id: uuid::Uuid::nil(),
            occurred_at: at,
            kind: AuditKind::Logout,
            outcome: AuditOutcome::Success,
            actor: AuditActor::User,
            request_id: "r".to_owned(),
            client_ip: None,
            client_id: None,
            subject: None,
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn saved_and_committed_is_visible_to_another_uow() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let u = user(1, "alice");
            let c = client("c1");
            let mut uow = store.begin().await.unwrap();
            uow.users().insert(&u).await.unwrap();
            uow.clients().insert(&c).await.unwrap();
            uow.audit_log().append(&audit(t0())).await.unwrap();
            // Visible inside the transaction, invisible outside until commit.
            assert!(uow.users().find(*u.id()).await.unwrap().is_some());
            assert!(store.state().users.is_empty());
            uow.commit().await.unwrap();

            let mut other = store.begin().await.unwrap();
            let found = other.users().find(*u.id()).await.unwrap().unwrap();
            assert_eq!(found.to_record(), u.to_record());
            let found = other.clients().find(c.id()).await.unwrap().unwrap();
            assert_eq!(found.to_record(), c.to_record());
            assert_eq!(store.audit_events().len(), 1);
        });
    }

    #[test]
    fn dropped_without_commit_is_invisible() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let u = user(1, "alice");
            let mut uow = store.begin().await.unwrap();
            uow.users().insert(&u).await.unwrap();
            uow.audit_log().append(&audit(t0())).await.unwrap();
            drop(uow);

            let mut other = store.begin().await.unwrap();
            assert!(other.users().find(*u.id()).await.unwrap().is_none());
            assert!(store.audit_events().is_empty());
        });
    }

    #[test]
    fn duplicates_conflict() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let mut uow = store.begin().await.unwrap();
            uow.users().insert(&user(1, "alice")).await.unwrap();
            // Same user name, different ID: the name is case-insensitive.
            let err = uow.users().insert(&user(2, "ALICE")).await.unwrap_err();
            assert!(matches!(err, StoreError::Conflict));
            let err = uow.users().insert(&user(1, "bob")).await.unwrap_err();
            assert!(matches!(err, StoreError::Conflict));
            uow.clients().insert(&client("c1")).await.unwrap();
            let err = uow.clients().insert(&client("c1")).await.unwrap_err();
            assert!(matches!(err, StoreError::Conflict));
            // Updating a missing row is an error.
            let err = uow.clients().update(&client("c2")).await.unwrap_err();
            assert!(matches!(err, StoreError::Other(_)));
        });
    }

    #[test]
    fn fail_next_fails_once() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            store.fail_next();
            assert!(matches!(
                store.begin().await.err(),
                Some(StoreError::Unavailable(_))
            ));
            assert!(store.begin().await.is_ok());
            store.fail_next();
            assert!(matches!(
                store.ping().await,
                Err(StoreError::Unavailable(_))
            ));
            assert!(store.ping().await.is_ok());
        });
    }

    #[test]
    fn list_is_ordered_and_paged() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let mut uow = store.begin().await.unwrap();
            for (n, name) in [(1, "carol"), (2, "alice"), (3, "bob")] {
                uow.users().insert(&user(n, name)).await.unwrap();
            }
            let page = ListPage {
                after: None,
                limit: 2,
            };
            let names: Vec<_> = uow
                .users()
                .list(&page)
                .await
                .unwrap()
                .iter()
                .map(|u| u.username().as_str().to_owned())
                .collect();
            assert_eq!(names, ["alice", "bob"]);
            let page = ListPage {
                after: Some(Username::try_new("bob".to_owned()).unwrap()),
                limit: 10,
            };
            let rest = uow.users().list(&page).await.unwrap();
            assert_eq!(rest.len(), 1);
            assert_eq!(rest[0].username().as_str(), "carol");
        });
    }

    #[test]
    fn sessions_delete_by_subject() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let s1 = Subject::try_new("u1".to_owned()).unwrap();
            let s2 = Subject::try_new("u2".to_owned()).unwrap();
            let ttl = Duration::hours(1);
            let mut uow = store.begin().await.unwrap();
            for (n, s) in [(1, &s1), (2, &s1), (3, &s2)] {
                let session = LoginSession::start(hash(n), s.clone(), t0(), ttl);
                uow.login_sessions().insert(&session).await.unwrap();
            }
            assert_eq!(
                uow.login_sessions().delete_by_subject(&s1).await.unwrap(),
                2
            );
            uow.login_sessions().delete(&hash(9)).await.unwrap();
            assert!(uow.login_sessions().find(&hash(3)).await.unwrap().is_some());
            assert!(uow.login_sessions().find(&hash(1)).await.unwrap().is_none());
        });
    }

    #[test]
    fn purge_removes_only_old_rows() {
        block_on(async {
            let store = InMemoryUnitOfWorkFactory::new();
            let cutoff = t0();
            let ttl = Duration::hours(1);
            let mut uow = store.begin().await.unwrap();
            let subject = Subject::try_new("u1".to_owned()).unwrap();
            // Sessions expiring exactly at the cutoff (purged) and one second later (kept).
            let old = LoginSession::start(hash(1), subject.clone(), cutoff - ttl, ttl);
            let fresh = LoginSession::start(hash(2), subject, cutoff - ttl + Duration::SECOND, ttl);
            uow.login_sessions().insert(&old).await.unwrap();
            uow.login_sessions().insert(&fresh).await.unwrap();

            // An old grant with a token that is still stored survives; an unreferenced one goes.
            let cid = ClientId::try_new("c1".to_owned()).unwrap();
            let long_ago = cutoff - Duration::days(10);
            let gid = |n| GrantId::new(uuid::Uuid::from_u128(n));
            let kept =
                Grant::for_client_credentials(gid(1), cid.clone(), ScopeSet::empty(), long_ago);
            let gone = Grant::for_client_credentials(gid(2), cid, ScopeSet::empty(), long_ago);
            uow.grants().insert(&kept).await.unwrap();
            uow.grants().insert(&gone).await.unwrap();
            let token = AccessToken::issue(
                hash(3),
                &kept,
                ScopeSet::empty(),
                cutoff + Duration::days(1),
                Duration::hours(1),
            )
            .unwrap();
            uow.access_tokens().insert(&token).await.unwrap();

            let counts = uow.purge().purge_expired(cutoff).await.unwrap();
            assert_eq!(
                counts,
                PurgeCounts {
                    login_sessions: 1,
                    grants: 1,
                    ..PurgeCounts::default()
                }
            );
            assert!(uow.grants().find(gid(1)).await.unwrap().is_some());
            assert!(uow.grants().find(gid(2)).await.unwrap().is_none());

            uow.audit_log().append(&audit(cutoff)).await.unwrap();
            uow.audit_log()
                .append(&audit(cutoff + Duration::SECOND))
                .await
                .unwrap();
            assert_eq!(uow.purge().purge_audit_events(cutoff).await.unwrap(), 1);
        });
    }
}
