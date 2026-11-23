//! Acceptance tests of `AuthorizationService` (application.md).
mod common;

use common::*;
use komainu_application::{
    AuthorizeError, AuthorizeOutcome, AuthorizeParams, LoginError, NonRedirectableError,
};
use komainu_domain::Username;

fn setup(skip_consent: bool) -> (Fixture, Registered) {
    let fx = Fixture::new();
    let mut input = confidential(&ALL_GRANTS);
    input.skip_consent = skip_consent;
    let client = register(&fx, input);
    create_user(&fx, "alice");
    (fx, client)
}

fn count_events(fx: &Fixture, kind: &str) -> usize {
    fx.env
        .store
        .audit_events()
        .iter()
        .filter(|e| e.kind.as_str() == kind)
        .count()
}

fn start(
    fx: &Fixture,
    p: AuthorizeParams,
) -> Result<komainu_application::StartResult, AuthorizeError> {
    block_on(fx.authz.start(&ctx(), p, None))
}

fn non_redirectable(
    r: Result<komainu_application::StartResult, AuthorizeError>,
) -> NonRedirectableError {
    match r {
        Err(AuthorizeError::NonRedirectable(e)) => e,
        other => panic!("expected non-redirectable error, got {other:?}"),
    }
}

fn redirect_location(r: Result<komainu_application::StartResult, AuthorizeError>) -> String {
    match r {
        Err(AuthorizeError::Redirect { location, .. }) => location,
        other => panic!("expected redirect error, got {other:?}"),
    }
}

#[test]
fn start_without_session_requires_login_and_stores_request() {
    let (fx, client) = setup(false);
    let result = start(&fx, params(&client.id, &[])).unwrap();
    assert!(matches!(
        result.outcome,
        AuthorizeOutcome::LoginRequired { .. }
    ));
    assert!(result.csrf_token.is_some());
    assert_eq!(fx.env.store.state().authorization_requests.len(), 1);
}

#[test]
fn unknown_client_is_non_redirectable_and_stores_nothing() {
    let (fx, _) = setup(false);
    let unknown = komainu_domain::ClientId::try_new("nobody".to_owned()).unwrap();
    let e = non_redirectable(start(&fx, params(&unknown, &[])));
    assert!(matches!(e, NonRedirectableError::UnknownClient));
    assert!(fx.env.store.state().authorization_requests.is_empty());
}

#[test]
fn redirect_uri_must_match_exactly() {
    let (fx, client) = setup(false);
    let e = non_redirectable(start(
        &fx,
        params(&client.id, &[("redirect_uri", "https://app.example/cb2")]),
    ));
    assert!(
        matches!(e, NonRedirectableError::RedirectUriMismatch),
        "{e:?}"
    );
}

#[test]
fn unsupported_response_type_redirects_with_error() {
    let (fx, client) = setup(false);
    let location = redirect_location(start(
        &fx,
        params(&client.id, &[("response_type", "token")]),
    ));
    assert!(
        location.starts_with(&format!(
            "{REDIRECT}?error=unsupported_response_type&error_description="
        )),
        "{location}"
    );
    assert!(location.starts_with(&format!(
        "{REDIRECT}?error=unsupported_response_type&error_description="
    )));
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
}

#[test]
fn scope_not_allowed_redirects_with_invalid_scope() {
    let (fx, client) = setup(false);
    let location = redirect_location(start(&fx, params(&client.id, &[("scope", "admin")])));
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_scope")
    );
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
}

#[test]
fn missing_state_is_invalid_request_when_required() {
    let fx = Fixture::with_config(config().with_require_state(true));
    let client = register(&fx, confidential(&ALL_GRANTS));
    let p = AuthorizeParams::from_pairs([
        ("response_type".to_owned(), "code".to_owned()),
        ("client_id".to_owned(), client.id.as_inner().to_string()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
    ]);
    let location = redirect_location(start(&fx, p));
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn duplicate_parameters_are_rejected() {
    let (fx, client) = setup(false);
    let dup_client = AuthorizeParams::from_pairs([
        ("response_type".to_owned(), "code".to_owned()),
        ("client_id".to_owned(), client.id.as_inner().to_string()),
        ("client_id".to_owned(), client.id.as_inner().to_string()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
    ]);
    assert!(matches!(
        non_redirectable(start(&fx, dup_client)),
        NonRedirectableError::DuplicateParameter
    ));
    let mut dup_scope = params(&client.id, &[("scope", "read")]);
    dup_scope.duplicated.push("scope");
    let location = redirect_location(start(&fx, dup_scope));
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );
    // from_pairs tracks duplicates among the five known names only.
    let p = AuthorizeParams::from_pairs([
        ("scope".to_owned(), "read".to_owned()),
        ("scope".to_owned(), "write".to_owned()),
        ("other".to_owned(), "1".to_owned()),
        ("other".to_owned(), "2".to_owned()),
        ("state".to_owned(), String::new()),
    ]);
    assert_eq!(p.duplicated, vec!["scope"]);
    assert_eq!(p.state, None);
}

fn started(
    fx: &Fixture,
    client: &Registered,
) -> (
    komainu_domain::AuthorizationRequestId,
    komainu_domain::OpaqueToken,
) {
    let s = start(fx, params(&client.id, &[("scope", "read")])).unwrap();
    (request_id(&s.outcome), s.csrf_token.unwrap())
}

#[test]
fn wrong_password_fails_and_commits_login_failed_audit() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    let r = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", "wrong")),
    );
    assert!(matches!(r, Err(LoginError::InvalidCredentials)));
    assert_eq!(count_events(&fx, "login.failed"), 1);
}

#[test]
fn wrong_csrf_is_rejected() {
    let (fx, client) = setup(false);
    let (rid, _) = started(&fx, &client);
    let other = start(&fx, params(&client.id, &[]))
        .unwrap()
        .csrf_token
        .unwrap();
    let r = block_on(
        fx.authz
            .login(&ctx(), rid, &other, credentials("alice", PASSWORD)),
    );
    assert!(matches!(
        r,
        Err(LoginError::Authorize(AuthorizeError::NonRedirectable(
            NonRedirectableError::CsrfMismatch
        )))
    ));
}

#[test]
fn consent_flow_issues_code_and_stores_consent() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    let logged = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    )
    .unwrap();
    let outcome = block_on(fx.authz.resume(&ctx(), rid, Some(&logged.session_token))).unwrap();
    assert!(matches!(outcome, AuthorizeOutcome::ConsentRequired { .. }));
    let location = block_on(
        fx.authz
            .decide(&ctx(), rid, &csrf, Some(&logged.session_token), true),
    )
    .unwrap();
    assert!(location.starts_with(REDIRECT));
    assert_eq!(query_param(&location, "code").unwrap().len(), 43);
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
    assert_eq!(fx.env.store.state().consents.len(), 1);
}

#[test]
fn stored_consent_skips_prompt_unless_scope_grows() {
    let (fx, client) = setup(false);
    obtain_code(&fx, &client.id, "alice", &[("scope", "read")]);
    // Same scope: the session is needed, so log in again and resume.
    let s = start(&fx, params(&client.id, &[("scope", "read")])).unwrap();
    let rid = request_id(&s.outcome);
    let logged = block_on(fx.authz.login(
        &ctx(),
        rid,
        s.csrf_token.as_ref().unwrap(),
        credentials("alice", PASSWORD),
    ))
    .unwrap();
    let again = block_on(fx.authz.start(
        &ctx(),
        params(&client.id, &[("scope", "read")]),
        Some(&logged.session_token),
    ))
    .unwrap();
    match again.outcome {
        AuthorizeOutcome::Redirect { location } => {
            assert!(query_param(&location, "code").is_some())
        }
        other => panic!("expected redirect, got {other:?}"),
    }
    let more = block_on(fx.authz.start(
        &ctx(),
        params(&client.id, &[("scope", "read write")]),
        Some(&logged.session_token),
    ))
    .unwrap();
    assert!(matches!(
        more.outcome,
        AuthorizeOutcome::ConsentRequired { .. }
    ));
}

#[test]
fn skip_consent_client_redirects_after_login() {
    let (fx, client) = setup(true);
    let (rid, csrf) = started(&fx, &client);
    let logged = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    )
    .unwrap();
    let outcome = block_on(fx.authz.resume(&ctx(), rid, Some(&logged.session_token))).unwrap();
    assert!(matches!(outcome, AuthorizeOutcome::Redirect { .. }));
}

#[test]
fn denial_redirects_with_access_denied_and_request_is_consumed() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    let logged = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    )
    .unwrap();
    let location =
        block_on(
            fx.authz
                .decide(&ctx(), rid, &csrf, Some(&logged.session_token), false),
        )
        .unwrap();
    assert_eq!(
        location,
        format!(
            "{REDIRECT}?error=access_denied&error_description={}&state=xyz",
            query_param(&location, "error_description").unwrap()
        )
    );
    let again = block_on(
        fx.authz
            .decide(&ctx(), rid, &csrf, Some(&logged.session_token), false),
    );
    assert!(matches!(
        again,
        Err(AuthorizeError::NonRedirectable(
            NonRedirectableError::RequestNotFound
        ))
    ));
}

#[test]
fn expired_request_cannot_be_logged_into() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    fx.env.clock.advance(time::Duration::seconds(600));
    let r = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    );
    assert!(matches!(
        r,
        Err(LoginError::Authorize(AuthorizeError::NonRedirectable(
            NonRedirectableError::RequestNotFound
        )))
    ));
}

#[test]
fn empty_and_overlong_passwords_are_invalid_credentials() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    for pw in [String::new(), "a".repeat(129)] {
        let r = block_on(
            fx.authz
                .login(&ctx(), rid, &csrf, credentials("alice", &pw)),
        );
        assert!(matches!(r, Err(LoginError::InvalidCredentials)));
    }
    let failed: Vec<_> = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .filter(|e| e.kind.as_str() == "login.failed")
        .collect();
    assert_eq!(failed.len(), 2);
    assert!(
        failed
            .iter()
            .all(|e| e.details.get("reason").map(String::as_str) == Some("invalid_credentials"))
    );
}

#[test]
fn disabled_user_session_requires_login_again() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    let logged = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    )
    .unwrap();
    block_on(
        fx.admin
            .disable_user(&ctx(), &Username::try_new("alice".to_owned()).unwrap()),
    )
    .unwrap();
    let outcome = block_on(fx.authz.resume(&ctx(), rid, Some(&logged.session_token))).unwrap();
    assert!(matches!(outcome, AuthorizeOutcome::LoginRequired { .. }));
}

#[test]
fn logout_deletes_the_session_and_login_form_names_the_client() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    assert_eq!(
        block_on(fx.authz.login_form(&ctx(), rid))
            .unwrap()
            .client_name,
        "Example App"
    );
    let logged = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials("alice", PASSWORD)),
    )
    .unwrap();
    assert_eq!(fx.env.store.state().login_sessions.len(), 1);
    block_on(fx.authz.logout(&ctx(), &logged.session_token)).unwrap();
    assert!(fx.env.store.state().login_sessions.is_empty());
}

#[test]
fn authorization_futures_are_send() {
    let (fx, client) = setup(false);
    let (rid, csrf) = started(&fx, &client);
    let c = ctx();
    assert_send(&fx.authz.start(&c, params(&client.id, &[]), None));
    assert_send(&fx.authz.login_form(&c, rid));
    assert_send(
        &fx.authz
            .login(&c, rid, &csrf, credentials("alice", PASSWORD)),
    );
    assert_send(&fx.authz.resume(&c, rid, None));
    assert_send(&fx.authz.decide(&c, rid, &csrf, None, true));
    assert_send(&fx.authz.logout(&c, &csrf));
}
