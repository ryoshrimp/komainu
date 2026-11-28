//! Shared helpers for the integration tests.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use komainu_application::{
    AdminService, ApplicationConfig, AuthorizationService, AuthorizeOutcome, AuthorizeParams,
    ClientAuthentication, LoginCredentials, MaintenanceService, RegisterClient, RequestContext,
    ScopeDefinition, TokenRequest, TokenResponse, TokenService,
};
use komainu_domain::{
    AuthorizationRequestId, ClientId, ClientName, ClientType, GrantType, NewPassword, OpaqueToken,
    RedirectUri, ScopeSet, ScopeToken, Secret, TokenEndpointAuthMethod, Username,
};
use komainu_testkit::TestEnv;

pub const REDIRECT: &str = "https://app.example/cb";
pub const CODE_VERIFIER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The S256 challenge of [`CODE_VERIFIER`] (RFC 7636 §4.2).
pub const CODE_CHALLENGE: &str = "ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA";
pub const PASSWORD: &str = "correct horse";

/// Polls a future that never suspends (the in-memory adapters are synchronous).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("in-memory adapters must never suspend"),
    }
}

pub fn assert_send<T: Send>(_: &T) {}

pub fn ctx() -> RequestContext {
    RequestContext {
        request_id: "req-1".to_owned(),
        client_ip: None,
    }
}

pub fn config() -> ApplicationConfig {
    let scope = |name: &str, description: &str| ScopeDefinition {
        name: ScopeToken::try_new(name.to_owned()).unwrap(),
        description: description.to_owned(),
    };
    ApplicationConfig::default().with_scopes(vec![
        scope("read", "Read your data"),
        scope("write", "Write your data"),
    ])
}

pub struct Fixture {
    pub env: TestEnv,
    pub admin: AdminService,
    pub authz: AuthorizationService,
    pub token: TokenService,
    pub maintenance: MaintenanceService,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_config(config())
    }

    pub fn with_config(config: ApplicationConfig) -> Self {
        let env = TestEnv::new(config);
        let deps = env.deps.clone();
        Self {
            admin: AdminService::new(deps.clone()),
            authz: AuthorizationService::new(deps.clone()),
            token: TokenService::new(deps.clone()),
            maintenance: MaintenanceService::new(deps),
            env,
        }
    }
}

pub fn scopes(s: &str) -> ScopeSet {
    ScopeSet::parse(s).unwrap()
}

pub fn grants(list: &[GrantType]) -> BTreeSet<GrantType> {
    list.iter().copied().collect()
}

/// Registration input of a confidential client using `client_secret_basic`.
pub fn confidential(grant_types: &[GrantType]) -> RegisterClient {
    RegisterClient {
        name: ClientName::try_new("Example App".to_owned()).unwrap(),
        client_type: ClientType::Confidential,
        auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        redirect_uris: vec![RedirectUri::try_new(REDIRECT.to_owned()).unwrap()],
        grant_types: grants(grant_types),
        allowed_scopes: scopes("read write"),
        default_scopes: scopes("read"),
        skip_consent: false,
        keys: None,
    }
}

pub struct Registered {
    pub id: ClientId,
    pub secret: OpaqueToken,
}

impl Registered {
    pub fn basic(&self) -> ClientAuthentication {
        ClientAuthentication::Basic {
            client_id: self.id.as_inner().to_string(),
            secret: Secret::new(self.secret.expose().to_string()),
        }
    }

    pub fn post(&self) -> ClientAuthentication {
        ClientAuthentication::Post {
            client_id: self.id.as_inner().to_string(),
            secret: Secret::new(self.secret.expose().to_string()),
        }
    }
}

pub fn register(fx: &Fixture, input: RegisterClient) -> Registered {
    let registered = block_on(fx.admin.register_client(&ctx(), input)).unwrap();
    Registered {
        id: registered.client.id,
        secret: registered.secret.expect("confidential client has a secret"),
    }
}

pub fn create_user(fx: &Fixture, name: &str) {
    block_on(fx.admin.create_user(
        &ctx(),
        Username::try_new(name.to_owned()).unwrap(),
        NewPassword::try_new(Secret::new(PASSWORD.to_owned())).unwrap(),
    ))
    .unwrap();
}

pub fn credentials(name: &str, password: &str) -> LoginCredentials {
    LoginCredentials {
        username: name.to_owned(),
        password: Secret::new(password.to_owned()),
    }
}

pub fn params(client_id: &ClientId, extra: &[(&str, &str)]) -> AuthorizeParams {
    let mut pairs = vec![
        ("response_type".to_owned(), "code".to_owned()),
        ("client_id".to_owned(), client_id.as_inner().to_string()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("state".to_owned(), "xyz".to_owned()),
        ("code_challenge".to_owned(), CODE_CHALLENGE.to_owned()),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
    ];
    for (k, v) in extra {
        pairs.retain(|(name, _)| name != k);
        pairs.push(((*k).to_owned(), (*v).to_owned()));
    }
    AuthorizeParams::from_pairs(pairs)
}

pub fn query_param(location: &str, name: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

pub fn request_id(outcome: &AuthorizeOutcome) -> AuthorizationRequestId {
    match outcome {
        AuthorizeOutcome::LoginRequired { request_id }
        | AuthorizeOutcome::ConsentRequired { request_id, .. } => *request_id,
        AuthorizeOutcome::Redirect { .. } => panic!("expected a screen, got a redirect"),
    }
}

/// Runs the whole flow (start, login, resume, decide) and returns the authorization code.
pub fn obtain_code(fx: &Fixture, client: &ClientId, user: &str, extra: &[(&str, &str)]) -> String {
    let started = block_on(fx.authz.start(&ctx(), params(client, extra), None)).unwrap();
    let rid = request_id(&started.outcome);
    let csrf = started.csrf_token.unwrap();
    let logged_in = block_on(
        fx.authz
            .login(&ctx(), rid, &csrf, credentials(user, PASSWORD)),
    )
    .unwrap();
    let outcome = block_on(fx.authz.resume(&ctx(), rid, Some(&logged_in.session_token))).unwrap();
    let location = match outcome {
        AuthorizeOutcome::ConsentRequired { .. } => {
            block_on(
                fx.authz
                    .decide(&ctx(), rid, &csrf, Some(&logged_in.session_token), true),
            )
            .unwrap()
        }
        AuthorizeOutcome::Redirect { location } => location,
        AuthorizeOutcome::LoginRequired { .. } => panic!("still not logged in"),
    };
    query_param(&location, "code").expect("location carries a code")
}

pub fn code_request(code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: Some("authorization_code".to_owned()),
        code: Some(code.to_owned()),
        redirect_uri: Some(REDIRECT.to_owned()),
        code_verifier: Some(CODE_VERIFIER.to_owned()),
        ..TokenRequest::default()
    }
}

pub fn refresh_request(refresh_token: &str, scope: Option<&str>) -> TokenRequest {
    TokenRequest {
        grant_type: Some("refresh_token".to_owned()),
        refresh_token: Some(refresh_token.to_owned()),
        scope: scope.map(str::to_owned),
        ..TokenRequest::default()
    }
}

pub fn grant_request(grant_type: &str, scope: Option<&str>) -> TokenRequest {
    TokenRequest {
        grant_type: Some(grant_type.to_owned()),
        scope: scope.map(str::to_owned),
        ..TokenRequest::default()
    }
}

pub fn exchange(
    fx: &Fixture,
    auth: ClientAuthentication,
    request: TokenRequest,
) -> Result<TokenResponse, komainu_application::TokenError> {
    block_on(fx.token.exchange(&ctx(), auth, request))
}

/// The three grant types.
pub const ALL_GRANTS: [GrantType; 3] = [
    GrantType::AuthorizationCode,
    GrantType::ClientCredentials,
    GrantType::RefreshToken,
];

// ---- private_key_jwt ----

pub const ISSUER: &str = "https://as.example.com";

use std::sync::Arc;

use komainu_application::Clock;
use komainu_domain::{ClientKeys, JwksDocument, JwksUri};
use komainu_jose::jwt::{self, Audience, Claims, NoCustomClaims, RegisteredClaims};
use komainu_jose::{JwkSet, Kid, SigningKey};
use komainu_testkit::StaticJwksFetcher;
use time::Duration;

/// A fixture with `issuer` set and a [`StaticJwksFetcher`].
pub fn assertion_fixture() -> (Fixture, StaticJwksFetcher) {
    assertion_fixture_with_issuer(ISSUER)
}

/// [`assertion_fixture`] with another `issuer` value.
pub fn assertion_fixture_with_issuer(issuer: &str) -> (Fixture, StaticJwksFetcher) {
    let fetcher = StaticJwksFetcher::new();
    let config = config().with_issuer(issuer);
    let env = TestEnv::new(config).with_jwks_fetcher(Arc::new(fetcher.clone()));
    let deps = env.deps.clone();
    let fx = Fixture {
        admin: AdminService::new(deps.clone()),
        authz: AuthorizationService::new(deps.clone()),
        token: TokenService::new(deps.clone()),
        maintenance: MaintenanceService::new(deps),
        env,
    };
    (fx, fetcher)
}

pub fn key_with_kid(kid: &str) -> SigningKey {
    SigningKey::generate_es256()
        .unwrap()
        .with_kid(Kid::try_new(kid.to_owned()).unwrap())
}

pub fn jwks_json(keys: &[&SigningKey]) -> String {
    JwkSet::new(keys.iter().map(|k| k.verifying_key()).collect())
        .unwrap()
        .to_json()
}

pub fn jwks_keys(keys: &[&SigningKey]) -> ClientKeys {
    ClientKeys::Jwks(JwksDocument::try_new(jwks_json(keys)).unwrap())
}

pub fn jwks_uri() -> JwksUri {
    JwksUri::try_new("https://client.example.com/jwks".to_owned()).unwrap()
}

pub fn private_key_jwt(keys: ClientKeys) -> RegisterClient {
    RegisterClient {
        auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
        keys: Some(keys),
        ..confidential(&ALL_GRANTS)
    }
}

pub fn register_private_key_jwt(fx: &Fixture, keys: ClientKeys) -> ClientId {
    block_on(fx.admin.register_client(&ctx(), private_key_jwt(keys)))
        .unwrap()
        .client
        .id
}

/// A client assertion for `client` that expires `lifetime` from now.
pub fn assertion(fx: &Fixture, key: &SigningKey, client: &ClientId, jti: &str) -> String {
    assertion_with(
        fx,
        key,
        client.as_inner(),
        client.as_inner(),
        jti,
        ISSUER,
        60,
    )
}

pub fn assertion_with(
    fx: &Fixture,
    key: &SigningKey,
    iss: &str,
    sub: &str,
    jti: &str,
    aud: &str,
    lifetime_secs: i64,
) -> String {
    let now = fx.env.clock.now();
    jwt::encode(
        &Claims {
            registered: RegisteredClaims {
                iss: Some(iss.to_owned()),
                sub: Some(sub.to_owned()),
                aud: Some(Audience::One(aud.to_owned())),
                exp: Some(now + Duration::seconds(lifetime_secs)),
                nbf: None,
                iat: None,
                jti: Some(jti.to_owned()),
            },
            custom: NoCustomClaims,
        },
        key,
        &komainu_jose::jws::SignOptions::new(),
    )
    .unwrap()
}

pub fn assertion_auth(client_id: Option<&ClientId>, assertion: String) -> ClientAuthentication {
    ClientAuthentication::Assertion {
        client_id: client_id.map(|id| id.as_inner().to_owned()),
        assertion: Secret::new(assertion),
    }
}

/// `details["reason"]` of every `client_authentication.failed` event.
pub fn failure_reasons(fx: &Fixture) -> Vec<String> {
    fx.env
        .store
        .audit_events()
        .into_iter()
        .filter(|e| e.kind == komainu_application::AuditKind::ClientAuthenticationFailed)
        .map(|e| e.details.get("reason").cloned().unwrap_or_default())
        .collect()
}
