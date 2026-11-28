//! Server signing keys: rotation, revocation, the JWKS and signing.

mod cache;
mod config;
mod error;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use komainu_domain::{
    KeyStatus, KeyToCreate, PublicJwk, ServerSigningKey, ServerSigningKeyRecord, SigningAlgorithm,
    SigningKeyId, current_key, immediate_key, plan_rotation,
};
use komainu_jose::jws::{self, SignOptions};
use komainu_jose::jwt::{self, Claims};
use komainu_jose::{JwkSet, RsaKeySize, SigningKey, VerifyingKey};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use self::cache::{Cached, KeyCache};
pub use self::config::{SigningConfig, SigningConfigError};
pub use self::error::SigningKeyError;
use crate::audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::ids::new_uuid_v7;
use crate::port::{Clock, KeySealer, SecureRandom, UnitOfWorkFactory};
use crate::support::{AuditEventExt, append_all};

const AAD_PREFIX: &[u8] = b"komainu:signing-key:";

/// A key as shown to operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeySummary {
    pub kid: SigningKeyId,
    pub algorithm: SigningAlgorithm,
    /// Judged at the time of the call.
    pub status: KeyStatus,
    pub created_at: OffsetDateTime,
    pub activates_at: OffsetDateTime,
    pub retires_at: OffsetDateTime,
    pub deletes_at: OffsetDateTime,
}

impl SigningKeySummary {
    fn of(key: &ServerSigningKey, now: OffsetDateTime) -> Self {
        Self {
            kid: key.kid().clone(),
            algorithm: key.algorithm(),
            status: key.status_at(now),
            created_at: key.created_at(),
            activates_at: key.activates_at(),
            retires_at: key.retires_at(),
            deletes_at: key.deletes_at(),
        }
    }
}

/// What [`SigningKeyService::rotate_due`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationReport {
    pub created: Vec<SigningKeySummary>,
    pub activated: Vec<SigningKeyId>,
    pub deleted: Vec<SigningKeyId>,
}

/// What [`SigningKeyService::revoke`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub revoked: SigningKeyId,
    /// The key made active in its place (newly created or a pending one), if any.
    pub replacement: Option<SigningKeySummary>,
}

/// Manages the AS signing keys and signs with them.
pub struct SigningKeyService {
    store: Arc<dyn UnitOfWorkFactory>,
    sealer: Arc<dyn KeySealer>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn SecureRandom>,
    config: SigningConfig,
    cache: KeyCache,
}

fn aad(kid: &str) -> Vec<u8> {
    [AAD_PREFIX, kid.as_bytes()].concat()
}

impl SigningKeyService {
    pub fn new(
        store: Arc<dyn UnitOfWorkFactory>,
        sealer: Arc<dyn KeySealer>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn SecureRandom>,
        config: SigningConfig,
    ) -> Self {
        Self {
            store,
            sealer,
            clock,
            random,
            config,
            cache: KeyCache::default(),
        }
    }

    pub fn config(&self) -> &SigningConfig {
        &self.config
    }

    /// Periodic rotation: activates, creates and deletes keys as the policy says.
    pub async fn rotate_due(
        &self,
        ctx: &RequestContext,
    ) -> Result<RotationReport, SigningKeyError> {
        let mut uow = self.store.begin().await?;
        uow.signing_keys().lock_rotation().await?;
        // Read the clock only once the lock is held: a node that waited must not act on a time
        // earlier than the `created_at` of a key the other node has just committed.
        let now = self.clock.now();
        let mut keys = uow.signing_keys().list().await?;
        let plan = plan_rotation(&keys, self.config.algorithms(), now, self.config.policy());

        let mut report = RotationReport::default();
        let mut events = Vec::new();
        for kid in &plan.activate {
            let Some(key) = keys.iter_mut().find(|k| k.kid() == kid) else {
                continue;
            };
            if key.activate_now(now) {
                uow.signing_keys().update_schedule(key).await?;
                events.push(self.activated_event(ctx, key, AuditActor::System));
                report.activated.push(kid.clone());
            }
        }
        for plan_key in &plan.create {
            let key = self.create_key(plan_key, now)?;
            uow.signing_keys().insert(&key).await?;
            events.push(self.created_event(ctx, &key, AuditActor::System));
            report.created.push(SigningKeySummary::of(&key, now));
        }
        for kid in &plan.delete {
            let Some(algorithm) = keys.iter().find(|k| k.kid() == kid).map(|k| k.algorithm())
            else {
                continue;
            };
            if uow.signing_keys().delete(kid).await? {
                events.push(
                    self.event(ctx, AuditKind::SigningKeyDeleted, AuditActor::System)
                        .detail("kid", kid.as_inner().clone())
                        .detail("alg", algorithm.as_str()),
                );
                report.deleted.push(kid.clone());
            }
        }
        append_all(uow.as_mut(), events).await?;
        let changed = report_has_changes(&report);
        uow.commit().await?;
        if changed {
            self.cache.clear();
        }
        Ok(report)
    }

    /// Immediate rotation of one algorithm (F-5).
    pub async fn rotate_now(
        &self,
        ctx: &RequestContext,
        algorithm: SigningAlgorithm,
    ) -> Result<SigningKeySummary, SigningKeyError> {
        if !self.config.algorithms().contains(&algorithm) {
            return Err(SigningKeyError::AlgorithmNotEnabled(algorithm));
        }
        let overlap = self.config.policy().retire_overlap();
        let mut uow = self.store.begin().await?;
        uow.signing_keys().lock_rotation().await?;
        // Read the clock only once the lock is held: a node that waited must not act on a time
        // earlier than the `created_at` of a key the other node has just committed.
        let now = self.clock.now();
        let mut keys = uow.signing_keys().list().await?;
        let mut events = Vec::new();
        for key in keys.iter_mut().filter(|k| {
            k.algorithm() == algorithm
                && matches!(k.status_at(now), KeyStatus::Pending | KeyStatus::Active)
        }) {
            if key.retire(now, overlap) {
                uow.signing_keys().update_schedule(key).await?;
                events.push(
                    self.event(ctx, AuditKind::SigningKeyRetired, AuditActor::Admin)
                        .detail("kid", key.kid().as_inner().clone())
                        .detail("alg", algorithm.as_str())
                        .detail("deletes_at", rfc3339(key.deletes_at())),
                );
            }
        }
        let key = self.create_key(&immediate_key(algorithm, now, self.config.policy()), now)?;
        uow.signing_keys().insert(&key).await?;
        events.push(self.created_event(ctx, &key, AuditActor::Admin));
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        self.cache.clear();
        Ok(SigningKeySummary::of(&key, now))
    }

    /// Deletes a key (F-6), making sure its algorithm still has an active key.
    pub async fn revoke(
        &self,
        ctx: &RequestContext,
        kid: &SigningKeyId,
    ) -> Result<RevokeOutcome, SigningKeyError> {
        let mut uow = self.store.begin().await?;
        uow.signing_keys().lock_rotation().await?;
        // Read the clock only once the lock is held: a node that waited must not act on a time
        // earlier than the `created_at` of a key the other node has just committed.
        let now = self.clock.now();
        let keys = uow.signing_keys().list().await?;
        let Some(revoked) = keys.iter().find(|k| k.kid() == kid) else {
            return Err(SigningKeyError::NotFound);
        };
        let algorithm = revoked.algorithm();
        if !uow.signing_keys().delete(kid).await? {
            return Err(SigningKeyError::NotFound);
        }
        let mut events = vec![
            self.event(ctx, AuditKind::SigningKeyRevoked, AuditActor::Admin)
                .detail("kid", kid.as_inner().clone())
                .detail("alg", algorithm.as_str()),
        ];
        let mut remaining: Vec<ServerSigningKey> =
            keys.into_iter().filter(|k| k.kid() != kid).collect();

        let mut replacement = None;
        if self.config.algorithms().contains(&algorithm)
            && current_key(&remaining, algorithm, now).is_none()
        {
            let pending = remaining
                .iter_mut()
                .filter(|k| k.algorithm() == algorithm && k.status_at(now) == KeyStatus::Pending)
                .min_by(|a, b| {
                    a.activates_at()
                        .cmp(&b.activates_at())
                        .then_with(|| a.kid().cmp(b.kid()))
                });
            if let Some(key) = pending {
                key.activate_now(now);
                uow.signing_keys().update_schedule(key).await?;
                events.push(self.activated_event(ctx, key, AuditActor::Admin));
                replacement = Some(SigningKeySummary::of(key, now));
            } else {
                let key =
                    self.create_key(&immediate_key(algorithm, now, self.config.policy()), now)?;
                uow.signing_keys().insert(&key).await?;
                events.push(self.created_event(ctx, &key, AuditActor::Admin));
                replacement = Some(SigningKeySummary::of(&key, now));
            }
        }
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        self.cache.clear();
        Ok(RevokeOutcome {
            revoked: kid.clone(),
            replacement,
        })
    }

    /// Every key, expired ones included. Reads the store directly.
    pub async fn list(&self) -> Result<Vec<SigningKeySummary>, SigningKeyError> {
        let now = self.clock.now();
        let mut uow = self.store.begin().await?;
        let keys = uow.signing_keys().list().await?;
        Ok(keys.iter().map(|k| SigningKeySummary::of(k, now)).collect())
    }

    /// The JWKS document (cached).
    pub async fn jwks_json(&self) -> Result<Arc<str>, SigningKeyError> {
        Ok(self.load().await?.jwks.clone())
    }

    /// Signs `payload` as a compact JWS with the active key of `algorithm`.
    pub async fn sign_jws(
        &self,
        algorithm: SigningAlgorithm,
        payload: &[u8],
        typ: Option<&str>,
    ) -> Result<String, SigningKeyError> {
        let key = self.signer(algorithm).await?;
        Ok(jws::sign(payload, &key, &options(typ))?)
    }

    /// Signs `claims` as a JWT with the active key of `algorithm`.
    pub async fn sign_jwt<T: Serialize>(
        &self,
        algorithm: SigningAlgorithm,
        claims: &Claims<T>,
        typ: Option<&str>,
    ) -> Result<String, SigningKeyError> {
        let key = self.signer(algorithm).await?;
        Ok(jwt::encode(claims, &key, &options(typ))?)
    }

    async fn signer(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<Arc<SigningKey>, SigningKeyError> {
        if !self.config.algorithms().contains(&algorithm) {
            return Err(SigningKeyError::AlgorithmNotEnabled(algorithm));
        }
        let cached = self.load().await?;
        let now = self.clock.now();
        current_key(&cached.keys, algorithm, now)
            .and_then(|k| cached.signers.get(k.kid()))
            .cloned()
            .ok_or(SigningKeyError::NoActiveKey(algorithm))
    }

    async fn load(&self) -> Result<Arc<Cached>, SigningKeyError> {
        let now = self.clock.now();
        if let Some(cached) = self.cache.fresh(now) {
            return Ok(cached);
        }
        let keys = {
            let mut uow = self.store.begin().await?;
            uow.signing_keys().list().await?
        };
        let mut published = Vec::new();
        let mut signers = HashMap::new();
        for key in &keys {
            if !key.is_published_at(now) {
                continue;
            }
            published.push(VerifyingKey::from_jwk(key.public_jwk().as_inner())?);
            if matches!(key.status_at(now), KeyStatus::Pending | KeyStatus::Active) {
                let kid = key.kid().as_inner();
                let der = self.sealer.open(key.sealed_private_key(), &aad(kid))?;
                let signer = SigningKey::from_pkcs8_der(&der)?.with_thumbprint_kid();
                signers.insert(key.kid().clone(), Arc::new(signer));
            }
        }
        let jwks: Arc<str> = JwkSet::new(published)?.to_json().into();
        let cached = Arc::new(Cached {
            loaded_at: now,
            keys,
            signers,
            jwks,
        });
        self.cache.store(cached.clone());
        Ok(cached)
    }

    fn create_key(
        &self,
        plan: &KeyToCreate,
        now: OffsetDateTime,
    ) -> Result<ServerSigningKey, SigningKeyError> {
        let generated = match plan.algorithm {
            SigningAlgorithm::Es256 => SigningKey::generate_es256()?,
            SigningAlgorithm::Rs256 => SigningKey::generate_rsa(RsaKeySize::Bits2048)?,
        }
        .with_thumbprint_kid();
        let kid = generated
            .kid()
            .map(|k| k.as_inner().to_owned())
            .ok_or_else(|| SigningKeyError::Crypto("generated key has no kid".to_owned()))?;
        let sealed = self.sealer.seal(&generated.to_pkcs8_der()?, &aad(&kid))?;
        Ok(ServerSigningKey::new(ServerSigningKeyRecord {
            kid: SigningKeyId::try_new(kid)?,
            algorithm: plan.algorithm,
            sealed_private_key: sealed,
            public_jwk: PublicJwk::try_new(generated.verifying_key().to_jwk())?,
            created_at: now,
            activates_at: plan.activates_at,
            retires_at: plan.retires_at,
            deletes_at: plan.deletes_at,
        })?)
    }

    fn event(&self, ctx: &RequestContext, kind: AuditKind, actor: AuditActor) -> AuditEvent {
        AuditEvent {
            id: new_uuid_v7(self.clock.as_ref(), self.random.as_ref()),
            occurred_at: self.clock.now(),
            kind,
            outcome: AuditOutcome::Success,
            actor,
            request_id: ctx.request_id.clone(),
            client_ip: ctx.client_ip,
            client_id: None,
            subject: None,
            details: BTreeMap::new(),
        }
    }

    fn created_event(
        &self,
        ctx: &RequestContext,
        key: &ServerSigningKey,
        actor: AuditActor,
    ) -> AuditEvent {
        self.event(ctx, AuditKind::SigningKeyCreated, actor)
            .detail("kid", key.kid().as_inner().clone())
            .detail("alg", key.algorithm().as_str())
            .detail("activates_at", rfc3339(key.activates_at()))
    }

    fn activated_event(
        &self,
        ctx: &RequestContext,
        key: &ServerSigningKey,
        actor: AuditActor,
    ) -> AuditEvent {
        self.event(ctx, AuditKind::SigningKeyActivated, actor)
            .detail("kid", key.kid().as_inner().clone())
            .detail("alg", key.algorithm().as_str())
    }
}

fn report_has_changes(report: &RotationReport) -> bool {
    !(report.created.is_empty() && report.activated.is_empty() && report.deleted.is_empty())
}

fn options(typ: Option<&str>) -> SignOptions {
    match typ {
        Some(t) => SignOptions::new().typ(t),
        None => SignOptions::new(),
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}
