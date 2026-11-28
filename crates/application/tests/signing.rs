//! SigningKeyService acceptance tests (signing-keys.md).

mod common;

use std::sync::Arc;

use common::*;
use komainu_application::{
    ApplicationConfig, ApplicationConfigError, AuditActor, AuditKind, KeySealer, SigningConfig,
    SigningKeyError, SigningKeyService,
};
use komainu_domain::{KeyStatus, SigningAlgorithm, SigningKeyId, SigningPolicy};
use komainu_jose::JwkSet;
use komainu_jose::jws::{self, VerifyOptions};
use komainu_jose::jwt::{self, Audience, Claims, NoCustomClaims, Validation};
use komainu_testkit::{TestEnv, TestKeySealer};
use time::Duration;

fn env(algorithms: Vec<SigningAlgorithm>) -> (TestEnv, Arc<SigningKeyService>) {
    let config = SigningConfig::new(algorithms, SigningPolicy::default()).unwrap();
    let env = TestEnv::new(ApplicationConfig::default()).with_signing(config);
    let service = env.deps.signing_keys.clone().unwrap();
    (env, service)
}

fn es_env() -> (TestEnv, Arc<SigningKeyService>) {
    env(vec![SigningAlgorithm::Es256])
}

fn claims(env: &TestEnv) -> Claims<NoCustomClaims> {
    let now = komainu_application::Clock::now(&env.clock);
    let mut c = Claims::<NoCustomClaims>::default();
    c.registered.iss = Some("https://as.example".to_owned());
    c.registered.aud = Some(Audience::One("rs".to_owned()));
    c.registered.exp = Some(now + Duration::hours(1));
    c.registered.iat = Some(now);
    c
}

fn kid_of(token: &str) -> String {
    let header = token.split('.').next().unwrap();
    let json = base64_url_decode(header);
    let text = String::from_utf8(json).unwrap();
    let rest = text.split("\"kid\":\"").nth(1).unwrap();
    rest.split('"').next().unwrap().to_owned()
}

fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn kinds(env: &TestEnv) -> Vec<&'static str> {
    env.store
        .audit_events()
        .iter()
        .map(|e| e.kind.as_str())
        .collect()
}

#[test]
fn rotate_due_creates_one_active_key_per_algorithm_once() {
    let (_env, service) = env(vec![SigningAlgorithm::Es256, SigningAlgorithm::Rs256]);
    assert_send(&service.rotate_due(&ctx()));
    let report = block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(report.created.len(), 2);
    assert!(report.created.iter().all(|k| k.status == KeyStatus::Active));
    let again = block_on(service.rotate_due(&ctx())).unwrap();
    assert!(again.created.is_empty() && again.activated.is_empty() && again.deleted.is_empty());
    assert_eq!(block_on(service.list()).unwrap().len(), 2);
}

#[test]
fn key_lifecycle_prepublish_activate_delete() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    let first = block_on(service.list()).unwrap()[0].kid.clone();

    env.clock.advance(Duration::days(83));
    // Load the cache at the same instant as the rotation, so only invalidation can refresh it.
    let jwks = JwkSet::from_json(&block_on(service.jwks_json()).unwrap()).unwrap();
    assert_eq!(jwks.keys().len(), 1);
    block_on(service.sign_jws(SigningAlgorithm::Es256, b"x", None)).unwrap();
    let report = block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(report.created.len(), 1);
    assert_eq!(report.created[0].status, KeyStatus::Pending);
    let second = report.created[0].kid.clone();

    let jwks = JwkSet::from_json(&block_on(service.jwks_json()).unwrap()).unwrap();
    assert_eq!(jwks.keys().len(), 2);
    let token = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&token), first.as_inner());

    env.clock.advance(Duration::days(7));
    let token = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&token), second.as_inner());

    env.clock.advance(Duration::days(7));
    let report = block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(report.deleted, vec![first]);
    let jwks = JwkSet::from_json(&block_on(service.jwks_json()).unwrap()).unwrap();
    assert_eq!(jwks.keys().len(), 1);
}

#[test]
fn signs_and_verifies_against_the_published_jwks() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    let jwks = JwkSet::from_json(&block_on(service.jwks_json()).unwrap()).unwrap();

    let token =
        block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), Some("at+jwt"))).unwrap();
    let now = komainu_application::Clock::now(&env.clock);
    let validation = Validation::new("https://as.example", "rs").require_typ("at+jwt");
    let decoded: jwt::Decoded<NoCustomClaims> =
        jwt::decode(&token, jwks.keys(), &validation, now).unwrap();
    assert_eq!(decoded.header.typ(), Some("at+jwt"));
    assert_eq!(decoded.header.algorithm().as_str(), "ES256");

    let jws_token = block_on(service.sign_jws(SigningAlgorithm::Es256, b"payload", None)).unwrap();
    let verified = jws::verify(&jws_token, jwks.keys(), &VerifyOptions::new()).unwrap();
    assert_eq!(verified.payload, b"payload");
}

#[test]
fn algorithm_not_enabled_and_no_active_key() {
    let (env, service) = es_env();
    let rs = SigningAlgorithm::Rs256;
    assert!(matches!(
        block_on(service.sign_jwt(rs, &claims(&env), None)),
        Err(SigningKeyError::AlgorithmNotEnabled(
            SigningAlgorithm::Rs256
        ))
    ));
    assert!(matches!(
        block_on(service.rotate_now(&ctx(), rs)),
        Err(SigningKeyError::AlgorithmNotEnabled(_))
    ));
    assert!(matches!(
        block_on(service.sign_jws(SigningAlgorithm::Es256, b"x", None)),
        Err(SigningKeyError::NoActiveKey(SigningAlgorithm::Es256))
    ));
    assert!(matches!(
        block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)),
        Err(SigningKeyError::NoActiveKey(SigningAlgorithm::Es256))
    ));
}

#[test]
fn rotate_now_retires_previous_keys_and_signs_with_the_new_one() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    env.clock.advance(Duration::days(83));
    block_on(service.rotate_due(&ctx())).unwrap(); // active + pending
    env.clock.advance(Duration::days(1));
    let old = block_on(service.list()).unwrap();
    let before = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&before), old[0].kid.as_inner());

    let now = komainu_application::Clock::now(&env.clock);
    let new = block_on(service.rotate_now(&ctx(), SigningAlgorithm::Es256)).unwrap();
    assert_eq!(new.status, KeyStatus::Active);
    for key in block_on(service.list()).unwrap() {
        if key.kid != new.kid {
            assert_eq!(key.status, KeyStatus::Retired);
            assert_eq!(key.deletes_at, now + Duration::days(7));
        }
    }
    let after = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&after), new.kid.as_inner());

    let events = env.store.audit_events();
    let retired = events
        .iter()
        .filter(|e| e.kind == AuditKind::SigningKeyRetired)
        .count();
    assert_eq!(retired, 2);
    assert!(
        events
            .iter()
            .rev()
            .take(3)
            .all(|e| e.actor == AuditActor::Admin)
    );
}

#[test]
fn revoke_activates_a_pending_key() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    env.clock.advance(Duration::days(83));
    let pending = block_on(service.rotate_due(&ctx())).unwrap().created[0]
        .kid
        .clone();
    let active = block_on(service.list()).unwrap()[0].kid.clone();
    let count_before = block_on(service.list()).unwrap().len();
    let events_before = env.store.audit_events().len();

    let outcome = block_on(service.revoke(&ctx(), &active)).unwrap();
    // Nothing new is created: one key removed, the pending one is reused.
    assert_eq!(block_on(service.list()).unwrap().len(), count_before - 1);
    let new_kinds: Vec<_> = kinds(&env)[events_before..].to_vec();
    assert_eq!(
        new_kinds,
        vec!["signing_key.revoked", "signing_key.activated"]
    );
    assert_eq!(outcome.revoked, active);
    assert_eq!(outcome.replacement.as_ref().unwrap().kid, pending);
    assert_eq!(outcome.replacement.unwrap().status, KeyStatus::Active);
    let token = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&token), pending.as_inner());
}

#[test]
fn revoke_the_only_active_key_creates_a_replacement() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    let old = block_on(service.list()).unwrap()[0].kid.clone();
    // Load the cache first so we see it being dropped.
    block_on(service.jwks_json()).unwrap();

    let outcome = block_on(service.revoke(&ctx(), &old)).unwrap();
    let replacement = outcome.replacement.unwrap();
    assert_ne!(replacement.kid, old);
    assert!(!env.store.state().signing_keys.contains_key(old.as_inner()));
    let jwks = block_on(service.jwks_json()).unwrap();
    assert!(!jwks.contains(old.as_inner()));
    assert!(jwks.contains(replacement.kid.as_inner()));
    assert!(kinds(&env).ends_with(&["signing_key.revoked", "signing_key.created"]));
}

#[test]
fn revoke_a_retired_key_needs_no_replacement_and_unknown_is_not_found() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    let old = block_on(service.list()).unwrap()[0].kid.clone();
    block_on(service.rotate_now(&ctx(), SigningAlgorithm::Es256)).unwrap();

    let outcome = block_on(service.revoke(&ctx(), &old)).unwrap();
    assert!(outcome.replacement.is_none());

    let unknown = SigningKeyId::try_new("nope".to_owned()).unwrap();
    let before = env.store.audit_events().len();
    assert!(matches!(
        block_on(service.revoke(&ctx(), &unknown)),
        Err(SigningKeyError::NotFound)
    ));
    assert_eq!(env.store.audit_events().len(), before);
}

#[test]
fn pending_key_is_activated_by_rotate_due_when_nothing_is_active() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    env.clock.advance(Duration::days(83));
    let pending = block_on(service.rotate_due(&ctx())).unwrap().created[0]
        .kid
        .clone();
    // Retire the active key by hand: revoke it directly in the store is not possible
    // through the service without activating the pending one, so remove it from the state.
    let active = block_on(service.list()).unwrap()[0].kid.clone();
    {
        // Delete through a unit of work, bypassing the service.
        use komainu_application::UnitOfWorkFactory;
        let mut uow = block_on(env.store.begin()).unwrap();
        block_on(uow.signing_keys().delete(&active)).unwrap();
        block_on(uow.commit()).unwrap();
    }
    // Load the cache: no active key yet.
    assert!(matches!(
        block_on(service.sign_jws(SigningAlgorithm::Es256, b"x", None)),
        Err(SigningKeyError::NoActiveKey(_))
    ));
    let report = block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(report.activated, vec![pending.clone()]);
    let token = block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    assert_eq!(&kid_of(&token), pending.as_inner());
}

fn is_kid(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `YYYY-MM-DDTHH:MM:SSZ`, optionally with fractional seconds.
fn is_rfc3339_utc(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() >= 20
        && b.ends_with(b"Z")
        && b[..19].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
}

/// (kind, actor, detail keys) of the events appended after the first `from`.
fn shapes(env: &TestEnv, from: usize) -> Vec<(&'static str, AuditActor, Vec<&'static str>)> {
    env.store.audit_events()[from..]
        .iter()
        .map(|e| {
            (
                e.kind.as_str(),
                e.actor,
                e.details.keys().copied().collect(),
            )
        })
        .collect()
}

#[test]
fn audit_events_have_the_designed_shape_and_no_secrets() {
    use AuditActor::{Admin, System};
    let (env, service) = es_env();
    let mut seen = 0;
    let mut step = |env: &TestEnv| {
        let s = shapes(env, seen);
        seen += s.len();
        s
    };

    // created (system) and, with the key gone, deleted (system).
    block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(
        step(&env),
        vec![(
            "signing_key.created",
            System,
            vec!["activates_at", "alg", "kid"]
        )]
    );
    env.clock.advance(Duration::days(83));
    block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(step(&env).len(), 1);
    env.clock.advance(Duration::days(14));
    block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(
        step(&env),
        vec![("signing_key.deleted", System, vec!["alg", "kid"])]
    );

    // retired + created (admin).
    block_on(service.rotate_now(&ctx(), SigningAlgorithm::Es256)).unwrap();
    assert_eq!(
        step(&env),
        vec![
            (
                "signing_key.retired",
                Admin,
                vec!["alg", "deletes_at", "kid"]
            ),
            (
                "signing_key.created",
                Admin,
                vec!["activates_at", "alg", "kid"]
            ),
        ]
    );

    // revoked + created (admin): the only active key is revoked, no pending exists.
    let active = block_on(service.list())
        .unwrap()
        .into_iter()
        .find(|k| k.status == KeyStatus::Active)
        .unwrap();
    block_on(service.revoke(&ctx(), &active.kid)).unwrap();
    assert_eq!(
        step(&env),
        vec![
            ("signing_key.revoked", Admin, vec!["alg", "kid"]),
            (
                "signing_key.created",
                Admin,
                vec!["activates_at", "alg", "kid"]
            ),
        ]
    );

    // activated (admin, by revoke).
    env.clock.advance(Duration::days(83));
    block_on(service.rotate_due(&ctx())).unwrap();
    step(&env);
    let active = block_on(service.list())
        .unwrap()
        .into_iter()
        .find(|k| k.status == KeyStatus::Active)
        .unwrap();
    block_on(service.revoke(&ctx(), &active.kid)).unwrap();
    assert_eq!(
        step(&env),
        vec![
            ("signing_key.revoked", Admin, vec!["alg", "kid"]),
            ("signing_key.activated", Admin, vec!["alg", "kid"]),
        ]
    );

    // No secret material anywhere in the events.
    let state = env.store.state();
    for e in env.store.audit_events() {
        assert_eq!(e.outcome.as_str(), "success");
        assert!(e.client_id.is_none() && e.subject.is_none());
        let text = format!("{e:?}");
        assert!(!text.contains("\"d\""), "JWK private member leaked: {text}");
        for (k, v) in &e.details {
            let allowed = match *k {
                "kid" => is_kid(v),
                "alg" => v == "ES256" || v == "RS256",
                "activates_at" | "deletes_at" => is_rfc3339_utc(v),
                other => panic!("unexpected detail key {other}"),
            };
            assert!(allowed, "{k}={v}");
            for key in state.signing_keys.values() {
                // TestKeySealer output is TEST + len + aad ("komainu:signing-key:" + kid) + key.
                let skip = 8 + 20 + key.kid().as_inner().len();
                let sealed = &key.sealed_private_key().as_bytes()[skip..];
                assert!(
                    !v.as_bytes()
                        .windows(8)
                        .any(|w| sealed.windows(8).any(|s| s == w))
                );
            }
        }
    }
}

#[test]
fn activated_by_rotate_due_is_audited_as_system() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    env.clock.advance(Duration::days(83));
    block_on(service.rotate_due(&ctx())).unwrap();
    let active = block_on(service.list()).unwrap()[0].kid.clone();
    {
        use komainu_application::UnitOfWorkFactory;
        let mut uow = block_on(env.store.begin()).unwrap();
        block_on(uow.signing_keys().delete(&active)).unwrap();
        block_on(uow.commit()).unwrap();
    }
    let from = env.store.audit_events().len();
    block_on(service.rotate_due(&ctx())).unwrap();
    assert_eq!(
        shapes(&env, from),
        vec![(
            "signing_key.activated",
            AuditActor::System,
            vec!["alg", "kid"]
        )]
    );
}

#[test]
fn deleting_expired_keys_is_audited() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    env.clock.advance(Duration::days(97));
    block_on(service.rotate_due(&ctx())).unwrap();
    assert!(kinds(&env).contains(&"signing_key.deleted"));
}

#[test]
fn validate_checks_retire_overlap_against_the_access_token_ttl() {
    let policy = |overlap| {
        SigningConfig::new(
            vec![SigningAlgorithm::Es256],
            SigningPolicy::new(Duration::days(90), Duration::days(7), overlap).unwrap(),
        )
        .unwrap()
    };
    let base = ApplicationConfig::default().with_access_token_ttl(Duration::hours(1));
    assert_eq!(base.validate(), Ok(()));
    assert_eq!(
        base.clone()
            .with_signing(policy(Duration::minutes(59)))
            .validate(),
        Err(ApplicationConfigError::RetireOverlapTooShort)
    );
    assert_eq!(
        base.with_signing(policy(Duration::hours(1))).validate(),
        Ok(())
    );
}

#[test]
fn signing_within_the_cache_ttl_does_not_touch_the_store() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    block_on(service.sign_jws(SigningAlgorithm::Es256, b"x", None)).unwrap();
    let begins = env.store.begin_count();
    for _ in 0..10 {
        block_on(service.sign_jwt(SigningAlgorithm::Es256, &claims(&env), None)).unwrap();
    }
    assert_eq!(env.store.begin_count(), begins);
    env.clock.advance(Duration::seconds(60));
    block_on(service.sign_jws(SigningAlgorithm::Es256, b"x", None)).unwrap();
    assert_eq!(env.store.begin_count(), begins + 1);
}

#[test]
fn sealed_key_is_bound_to_its_kid() {
    let (env, service) = es_env();
    block_on(service.rotate_due(&ctx())).unwrap();
    let state = env.store.state();
    let (kid, key) = state.signing_keys.iter().next().unwrap();
    let aad = [b"komainu:signing-key:".as_slice(), kid.as_bytes()].concat();
    assert!(TestKeySealer.open(key.sealed_private_key(), &aad).is_ok());
    let other = [aad.as_slice(), b":other"].concat();
    assert!(
        TestKeySealer
            .open(key.sealed_private_key(), &other)
            .is_err()
    );
}
