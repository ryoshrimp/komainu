//! AdminService acceptance tests (application.md).

mod common;

use common::*;
use komainu_application::{
    AdminError, AuditActor, AuditKind, ClientAuthentication, ListPage, TokenError,
};
use komainu_domain::{
    ClientType, GrantType, NewPassword, ScopeSet, Secret, TokenEndpointAuthMethod, Username,
};

fn user(name: &str) -> Username {
    Username::try_new(name.to_owned()).unwrap()
}

#[test]
fn register_confidential_client_returns_a_working_secret() {
    let fx = Fixture::new();
    let registered = block_on(fx.admin.register_client(&ctx(), confidential(&ALL_GRANTS))).unwrap();
    let secret = registered.secret.expect("secret is returned once");
    let auth = ClientAuthentication::Basic {
        client_id: registered.client.id.as_inner().to_string(),
        secret: Secret::new(secret.expose().to_owned()),
    };
    assert!(exchange(&fx, auth, grant_request("client_credentials", None)).is_ok());
    // The stored record holds a hash, never the plaintext.
    let dump = format!("{:?}", fx.env.store.state().clients);
    assert!(!dump.contains(secret.expose()));
    let event = &fx.env.store.audit_events()[0];
    assert_eq!(event.kind, AuditKind::ClientRegistered);
    assert_eq!(event.actor, AuditActor::Admin);
    assert_eq!(event.details["client_type"], "confidential");
}

#[test]
fn unknown_scope_is_rejected() {
    let mut cfg = config();
    cfg.scopes.clear();
    let fx = Fixture::with_config(cfg);
    let mut input = confidential(&ALL_GRANTS);
    input.allowed_scopes = ScopeSet::parse("read").unwrap();
    let err = block_on(fx.admin.register_client(&ctx(), input)).unwrap_err();
    assert!(matches!(err, AdminError::UnknownScope(s) if s == "read"));
    assert!(fx.env.store.state().clients.is_empty());
}

#[test]
fn public_client_is_rejected_when_disabled() {
    let fx = Fixture::new();
    let mut input = confidential(&[GrantType::AuthorizationCode]);
    input.client_type = ClientType::Public;
    input.auth_method = TokenEndpointAuthMethod::None;
    let err = block_on(fx.admin.register_client(&ctx(), input)).unwrap_err();
    assert!(matches!(err, AdminError::PublicClientsDisabled));
}

#[test]
fn rotate_secret_invalidates_the_old_one() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let new = block_on(fx.admin.rotate_client_secret(&ctx(), &client.id)).unwrap();
    let request = || grant_request("client_credentials", None);
    assert!(matches!(
        exchange(&fx, client.basic(), request()),
        Err(TokenError::InvalidClient { .. })
    ));
    let auth = ClientAuthentication::Basic {
        client_id: client.id.as_inner().to_string(),
        secret: Secret::new(new.expose().to_owned()),
    };
    assert!(exchange(&fx, auth, request()).is_ok());
    let kinds: Vec<_> = fx.env.store.audit_events().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&AuditKind::ClientSecretRotated));
}

#[test]
fn disable_client_revokes_issued_access_tokens() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let res = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap();
    let token = res.access_token.expose().to_owned();
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_some()
    );
    let view = block_on(fx.admin.disable_client(&ctx(), &client.id)).unwrap();
    assert!(!view.active);
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_none()
    );
    let revoked = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .find(|e| e.kind == AuditKind::GrantRevoked)
        .unwrap();
    assert_eq!(revoked.actor, AuditActor::Admin);
    assert_eq!(revoked.details["reason"], "client_disabled");
    // Disabling again is idempotent and enabling restores authentication.
    let before = fx.env.store.audit_events().len();
    block_on(fx.admin.disable_client(&ctx(), &client.id)).unwrap();
    let after = fx.env.store.audit_events().len();
    assert!(after <= before + 1);
    let view = block_on(fx.admin.enable_client(&ctx(), &client.id)).unwrap();
    assert!(view.active);
}

#[test]
fn duplicate_username_is_a_conflict() {
    let fx = Fixture::new();
    create_user(&fx, "alice");
    let err = block_on(fx.admin.create_user(
        &ctx(),
        user("ALICE"),
        NewPassword::try_new(Secret::new(PASSWORD.to_owned())).unwrap(),
    ))
    .unwrap_err();
    assert!(matches!(err, AdminError::Conflict));
}

#[test]
fn disable_user_deletes_sessions_and_invalidates_tokens() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    create_user(&fx, "alice");
    let code = obtain_code(&fx, &client.id, "alice", &[]);
    let res = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let token = res.access_token.expose().to_owned();
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_some()
    );
    assert_eq!(fx.env.store.state().login_sessions.len(), 1);
    let view = block_on(fx.admin.disable_user(&ctx(), &user("alice"))).unwrap();
    assert!(!view.active);
    assert!(fx.env.store.state().login_sessions.is_empty());
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_none()
    );
    let revoked = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .find(|e| e.kind == AuditKind::GrantRevoked)
        .unwrap();
    assert_eq!(revoked.details["reason"], "user_disabled");
}

#[test]
fn user_and_client_crud_and_listing() {
    let fx = Fixture::new();
    create_user(&fx, "alice");
    create_user(&fx, "bob");
    let got = block_on(fx.admin.get_user(&ctx(), &user("alice"))).unwrap();
    assert!(got.active);
    assert!(matches!(
        block_on(fx.admin.get_user(&ctx(), &user("carol"))),
        Err(AdminError::NotFound)
    ));
    block_on(fx.admin.set_user_password(
        &ctx(),
        &user("alice"),
        NewPassword::try_new(Secret::new("another password".to_owned())).unwrap(),
    ))
    .unwrap();
    block_on(fx.admin.disable_user(&ctx(), &user("bob"))).unwrap();
    assert!(
        block_on(fx.admin.enable_user(&ctx(), &user("bob")))
            .unwrap()
            .active
    );
    let page = ListPage {
        after: None,
        limit: 0,
    };
    // A limit of 0 is clamped to 1.
    let users = block_on(fx.admin.list_users(&ctx(), page)).unwrap();
    assert_eq!(users.len(), 1);
    let client = register(&fx, confidential(&ALL_GRANTS));
    let clients = block_on(fx.admin.list_clients(
        &ctx(),
        ListPage {
            after: None,
            limit: 10,
        },
    ))
    .unwrap();
    assert_eq!(clients.len(), 1);
    let view = block_on(fx.admin.update_client(
        &ctx(),
        &client.id,
        komainu_domain::ClientUpdate {
            skip_consent: Some(true),
            ..Default::default()
        },
    ))
    .unwrap();
    assert!(view.skip_consent);
    assert!(
        block_on(fx.admin.get_client(&ctx(), &client.id))
            .unwrap()
            .skip_consent
    );
    // Reads write no audit events; the audit log is empty of get/list kinds and secrets.
    let dump = format!("{:?}", fx.env.store.audit_events());
    assert!(!dump.contains(PASSWORD) && !dump.contains("another password"));
}

// ---- private_key_jwt keys (F-1) ----

mod keys {
    use super::*;
    use komainu_application::{AdminError, RegisterClient};
    use komainu_domain::{ClientKeys, ClientUpdate, JwksDocument, TokenEndpointAuthMethod};

    #[test]
    fn private_key_jwt_client_has_no_secret_and_keeps_keys() {
        let fx = Fixture::new();
        let key = key_with_kid("k1");
        let registered = block_on(
            fx.admin
                .register_client(&ctx(), private_key_jwt(jwks_keys(&[&key]))),
        )
        .unwrap();
        assert!(registered.secret.is_none());
        assert_eq!(
            registered.client.auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(matches!(registered.client.keys, Some(ClientKeys::Jwks(_))));
        // The uri form is accepted without fetching.
        let (fx, fetcher) = assertion_fixture();
        let by_uri = block_on(
            fx.admin
                .register_client(&ctx(), private_key_jwt(ClientKeys::JwksUri(jwks_uri()))),
        )
        .unwrap();
        assert!(matches!(by_uri.client.keys, Some(ClientKeys::JwksUri(_))));
        assert_eq!(fetcher.calls(&jwks_uri()), 0);
    }

    #[test]
    fn jwks_uri_is_rejected_without_a_fetcher() {
        let fx = Fixture::new();
        let err = block_on(
            fx.admin
                .register_client(&ctx(), private_key_jwt(ClientKeys::JwksUri(jwks_uri()))),
        )
        .unwrap_err();
        assert!(matches!(err, AdminError::InvalidJwks(_)), "{err:?}");
    }

    #[test]
    fn secret_clients_still_get_a_secret() {
        let fx = Fixture::new();
        let r = block_on(fx.admin.register_client(&ctx(), confidential(&ALL_GRANTS))).unwrap();
        assert!(r.secret.is_some());
    }

    fn invalid(doc: String) -> RegisterClient {
        private_key_jwt(ClientKeys::Jwks(JwksDocument::try_new(doc).unwrap()))
    }

    #[test]
    fn unusable_jwks_is_rejected() {
        let fx = Fixture::new();
        let empty = r#"{"keys":[]}"#.to_owned();
        let err = block_on(fx.admin.register_client(&ctx(), invalid(empty))).unwrap_err();
        assert!(matches!(err, AdminError::InvalidJwks(_)), "{err:?}");
        let many: Vec<_> = (0..11).map(|i| key_with_kid(&format!("k{i}"))).collect();
        let refs: Vec<_> = many.iter().collect();
        let err =
            block_on(fx.admin.register_client(&ctx(), invalid(jwks_json(&refs)))).unwrap_err();
        assert!(matches!(err, AdminError::InvalidJwks(_)), "{err:?}");
        let ten = &refs[..10];
        block_on(fx.admin.register_client(&ctx(), invalid(jwks_json(ten)))).unwrap();
    }

    #[test]
    fn update_replaces_and_validates_keys() {
        let fx = Fixture::new();
        let key = key_with_kid("k1");
        let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
        let next = key_with_kid("k2");
        let update = |keys| ClientUpdate {
            keys: Some(keys),
            ..ClientUpdate::default()
        };
        let view = block_on(
            fx.admin
                .update_client(&ctx(), &id, update(jwks_keys(&[&next]))),
        )
        .unwrap();
        assert!(matches!(view.keys, Some(ClientKeys::Jwks(_))));
        let bad = ClientKeys::Jwks(JwksDocument::try_new(r#"{"keys":[]}"#.to_owned()).unwrap());
        let err = block_on(fx.admin.update_client(&ctx(), &id, update(bad))).unwrap_err();
        assert!(matches!(err, AdminError::InvalidJwks(_)));
    }
}

// ---- trusted issuers (F-8, F-9) ----

mod issuers {
    use super::*;
    use komainu_application::RegisterIssuer;
    use komainu_domain::{ExternalSubject, IssuerId, IssuerStatus, TrustedIssuerUpdate};
    use std::collections::BTreeSet;

    const IDP: &str = "https://idp.example.com";

    fn issuer_id(id: &str) -> IssuerId {
        IssuerId::try_new(id.to_owned()).unwrap()
    }

    fn register_input(fx: &Fixture, id: &str) -> RegisterIssuer {
        let client = register(
            fx,
            confidential(&[GrantType::AuthorizationCode, GrantType::JwtBearer]),
        );
        let key = key_with_kid("k");
        RegisterIssuer {
            id: issuer_id(id),
            jwks: komainu_domain::JwksDocument::try_new(jwks_json(&[&key])).unwrap(),
            allowed_clients: [client.id].into(),
        }
    }

    fn page(limit: u32) -> ListPage<IssuerId> {
        ListPage { after: None, limit }
    }

    fn kinds(fx: &Fixture) -> Vec<&'static str> {
        fx.env
            .store
            .audit_events()
            .iter()
            .map(|e| e.kind.as_str())
            .filter(|k| k.starts_with("issuer."))
            .collect()
    }

    #[test]
    fn register_update_disable_enable_and_audit() {
        let fx = Fixture::new();
        let input = register_input(&fx, IDP);
        let view = block_on(fx.admin.register_issuer(&ctx(), input.clone())).unwrap();
        assert_eq!(view.status, IssuerStatus::Active);
        assert_eq!(view.allowed_clients, input.allowed_clients);
        let id = issuer_id(IDP);
        let other = register(
            &fx,
            confidential(&[GrantType::AuthorizationCode, GrantType::JwtBearer]),
        );
        let updated = block_on(fx.admin.update_issuer(
            &ctx(),
            &id,
            TrustedIssuerUpdate {
                allowed_clients: Some([other.id.clone()].into()),
                ..Default::default()
            },
        ))
        .unwrap();
        assert_eq!(updated.allowed_clients, BTreeSet::from([other.id]));
        assert_eq!(
            block_on(fx.admin.disable_issuer(&ctx(), &id))
                .unwrap()
                .status,
            IssuerStatus::Disabled
        );
        assert_eq!(
            block_on(fx.admin.enable_issuer(&ctx(), &id))
                .unwrap()
                .status,
            IssuerStatus::Active
        );
        assert_eq!(
            kinds(&fx),
            [
                "issuer.registered",
                "issuer.updated",
                "issuer.disabled",
                "issuer.enabled"
            ]
        );
        let event = fx
            .env
            .store
            .audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::IssuerRegistered)
            .unwrap();
        assert_eq!(event.actor, AuditActor::Admin);
        assert_eq!(event.details["issuer"], IDP);
        assert!(block_on(fx.admin.get_issuer(&ctx(), &id)).is_ok());
        assert!(matches!(
            block_on(
                fx.admin
                    .get_issuer(&ctx(), &issuer_id("https://nope.example.com"))
            ),
            Err(AdminError::NotFound)
        ));
    }

    #[test]
    fn unknown_client_invalid_jwks_and_duplicates_are_rejected() {
        let fx = Fixture::new();
        let mut input = register_input(&fx, IDP);
        let missing = komainu_domain::ClientId::try_new("ghost".to_owned()).unwrap();
        let mut unknown = input.clone();
        unknown.allowed_clients.insert(missing.clone());
        assert!(matches!(
            block_on(fx.admin.register_issuer(&ctx(), unknown)),
            Err(AdminError::UnknownClient(id)) if id == missing
        ));
        let update_unknown = block_on(fx.admin.update_issuer(
            &ctx(),
            &issuer_id(IDP),
            TrustedIssuerUpdate::default(),
        ));
        assert!(matches!(update_unknown, Err(AdminError::NotFound)));
        let bad = input.clone();
        let mut bad_jwks = bad;
        bad_jwks.jwks = komainu_domain::JwksDocument::try_new(r#"{"keys":[]}"#.to_owned()).unwrap();
        assert!(matches!(
            block_on(fx.admin.register_issuer(&ctx(), bad_jwks)),
            Err(AdminError::InvalidJwks(_))
        ));
        assert!(kinds(&fx).is_empty());
        block_on(fx.admin.register_issuer(&ctx(), input.clone())).unwrap();
        assert!(matches!(
            block_on(fx.admin.register_issuer(&ctx(), input.clone())),
            Err(AdminError::Conflict)
        ));
        // Update checks client existence too.
        input.allowed_clients.insert(missing.clone());
        let err = block_on(fx.admin.update_issuer(
            &ctx(),
            &issuer_id(IDP),
            TrustedIssuerUpdate {
                allowed_clients: Some(input.allowed_clients),
                ..Default::default()
            },
        ));
        assert!(matches!(err, Err(AdminError::UnknownClient(_))));
        // No allowed clients is a domain error.
        let none = block_on(fx.admin.update_issuer(
            &ctx(),
            &issuer_id(IDP),
            TrustedIssuerUpdate {
                allowed_clients: Some(BTreeSet::new()),
                ..Default::default()
            },
        ));
        assert!(matches!(none, Err(AdminError::Invalid(_))));
    }

    #[test]
    fn list_issuers_clamps_the_limit() {
        let fx = Fixture::new();
        for id in ["https://a.example.com", "https://b.example.com"] {
            block_on(fx.admin.register_issuer(&ctx(), register_input(&fx, id))).unwrap();
        }
        assert_eq!(
            block_on(fx.admin.list_issuers(&ctx(), page(0)))
                .unwrap()
                .len(),
            1
        );
        let all = block_on(fx.admin.list_issuers(&ctx(), page(100))).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, issuer_id("https://a.example.com"));
        let after = ListPage {
            after: Some(issuer_id("https://a.example.com")),
            limit: 100,
        };
        assert_eq!(
            block_on(fx.admin.list_issuers(&ctx(), after))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn subject_mappings_are_upserted_listed_and_removed() {
        let fx = Fixture::new();
        block_on(fx.admin.register_issuer(&ctx(), register_input(&fx, IDP))).unwrap();
        create_user(&fx, "alice");
        create_user(&fx, "bob");
        let id = issuer_id(IDP);
        let sub = |s: &str| ExternalSubject::try_new(s.to_owned()).unwrap();
        let first = block_on(
            fx.admin
                .map_subject(&ctx(), &id, sub("u-1"), &user("alice")),
        )
        .unwrap();
        assert_eq!(first.username, user("alice"));
        // Re-mapping overwrites.
        let second = block_on(fx.admin.map_subject(&ctx(), &id, sub("u-1"), &user("bob"))).unwrap();
        assert_ne!(first.user_id, second.user_id);
        let page = ListPage {
            after: None,
            limit: 100,
        };
        let list = block_on(fx.admin.list_subject_mappings(&ctx(), &id, page)).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].username, user("bob"));
        // Unknown issuer / user.
        assert!(matches!(
            block_on(fx.admin.map_subject(
                &ctx(),
                &issuer_id("https://x.example.com"),
                sub("u"),
                &user("bob")
            )),
            Err(AdminError::NotFound)
        ));
        assert!(matches!(
            block_on(
                fx.admin
                    .map_subject(&ctx(), &id, sub("u-2"), &user("ghost"))
            ),
            Err(AdminError::NotFound)
        ));
        block_on(fx.admin.unmap_subject(&ctx(), &id, &sub("u-1"))).unwrap();
        assert!(matches!(
            block_on(fx.admin.unmap_subject(&ctx(), &id, &sub("u-1"))),
            Err(AdminError::NotFound)
        ));
        let events = fx.env.store.audit_events();
        let mapped = events
            .iter()
            .filter(|e| e.kind == AuditKind::SubjectMapped)
            .count();
        let unmapped = events
            .iter()
            .filter(|e| e.kind == AuditKind::SubjectUnmapped)
            .count();
        assert_eq!((mapped, unmapped), (2, 1));
        let ev = events
            .iter()
            .find(|e| e.kind == AuditKind::SubjectUnmapped)
            .unwrap();
        assert_eq!(ev.details["issuer"], IDP);
        assert_eq!(ev.details["subject"], "u-1");
    }
}
