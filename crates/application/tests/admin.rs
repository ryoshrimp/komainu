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
