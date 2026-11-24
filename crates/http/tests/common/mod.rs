//! Shared helpers for the HTTP integration tests.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use komainu_application::{
    AdminService, ApplicationConfig, AuthorizationService, RegisterClient, RequestContext,
    ScopeDefinition, TokenService,
};
use komainu_domain::{
    ClientId, ClientName, ClientType, GrantType, NewPassword, OpaqueToken, RedirectUri, ScopeSet,
    ScopeToken, Secret, TokenEndpointAuthMethod, Username,
};
use komainu_http::{AppState, HttpConfig};
use komainu_testkit::TestEnv;
use tower::ServiceExt;

pub const REDIRECT: &str = "https://app.example/cb";
pub const PASSWORD: &str = "correct horse";
pub const BASE: &str = "https://auth.example.com";

pub struct Harness {
    pub env: TestEnv,
    pub admin: AdminService,
    pub router: Router,
    pub state: AppState,
}

pub struct Registered {
    pub id: ClientId,
    pub secret: Option<OpaqueToken>,
}

impl Registered {
    pub fn id(&self) -> String {
        self.id.as_inner().to_string()
    }

    pub fn secret(&self) -> String {
        self.secret.as_ref().expect("secret").expose().to_owned()
    }
}

pub fn app_config() -> ApplicationConfig {
    let scope = |name: &str, description: &str| ScopeDefinition {
        name: ScopeToken::try_new(name.to_owned()).unwrap(),
        description: description.to_owned(),
    };
    ApplicationConfig::default().with_scopes(vec![
        scope("read", "Read your data"),
        scope("write", "Write your data"),
    ])
}

impl Harness {
    pub fn new() -> Self {
        Self::with(false, 16 * 1024)
    }

    pub fn with(cookie_secure: bool, max_body_bytes: usize) -> Self {
        let env = TestEnv::new(app_config());
        let deps = env.deps.clone();
        let config = HttpConfig::new(BASE)
            .unwrap()
            .with_cookie_secure(cookie_secure)
            .with_max_body_bytes(max_body_bytes)
            .with_csrf_cookie_ttl(deps.config.authorization_request_ttl);
        Self::from_config(env, config)
    }

    pub fn from_config(env: TestEnv, config: HttpConfig) -> Self {
        let deps = env.deps.clone();
        let state = AppState::new(
            AuthorizationService::new(deps.clone()),
            TokenService::new(deps.clone()),
            config,
        );
        Self {
            admin: AdminService::new(deps),
            router: komainu_http::router(state.clone()),
            state,
            env,
        }
    }

    /// The default configuration with a custom renderer.
    pub fn with_screens(screens: std::sync::Arc<dyn komainu_http::ScreenRenderer>) -> Self {
        let env = TestEnv::new(app_config());
        let deps = env.deps.clone();
        let config = HttpConfig::new(BASE)
            .unwrap()
            .with_cookie_secure(false)
            .with_csrf_cookie_ttl(deps.config.authorization_request_ttl);
        let state = AppState::new(
            AuthorizationService::new(deps.clone()),
            TokenService::new(deps.clone()),
            config,
        )
        .with_screens(screens);
        Self {
            admin: AdminService::new(deps),
            router: komainu_http::router(state.clone()),
            state,
            env,
        }
    }

    pub async fn register_named(&self, name: &str, mut input: RegisterClient) -> Registered {
        input.name = ClientName::try_new(name.to_owned()).unwrap();
        self.register(input).await
    }

    pub async fn register(&self, input: RegisterClient) -> Registered {
        let ctx = ctx();
        let registered = self.admin.register_client(&ctx, input).await.unwrap();
        Registered {
            id: registered.client.id,
            secret: registered.secret,
        }
    }

    pub async fn create_user(&self, name: &str) {
        self.admin
            .create_user(
                &ctx(),
                Username::try_new(name.to_owned()).unwrap(),
                NewPassword::try_new(Secret::new(PASSWORD.to_owned())).unwrap(),
            )
            .await
            .unwrap();
    }

    pub async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.router.clone().oneshot(request).await.unwrap();
        Reply::from(response).await
    }
}

pub fn ctx() -> RequestContext {
    RequestContext {
        request_id: "test".to_owned(),
        client_ip: None,
    }
}

pub fn confidential(grants: &[GrantType]) -> RegisterClient {
    RegisterClient {
        name: ClientName::try_new("Example App".to_owned()).unwrap(),
        client_type: ClientType::Confidential,
        auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        redirect_uris: vec![RedirectUri::try_new(REDIRECT.to_owned()).unwrap()],
        grant_types: grants.iter().copied().collect(),
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        skip_consent: false,
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    async fn from(response: Response<Body>) -> Self {
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Self {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn location(&self) -> &str {
        self.header("location").expect("Location header")
    }

    /// The whole `Set-Cookie` line of the cookie `name`.
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with(&format!("{name}=")))
            .map(str::to_owned)
    }

    /// The value of the cookie `name`.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        let line = self.set_cookie(name)?;
        let first = line.split(';').next()?;
        Some(first.split_once('=')?.1.to_owned())
    }
}

pub fn get(uri: &str, cookies: &str) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies);
    }
    builder.body(Body::empty()).unwrap()
}

pub fn post_form(uri: &str, cookies: &str, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

pub fn query_param(location: &str, name: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

pub fn authorize_uri(client_id: &str, extra: &str) -> String {
    authorize_uri_with_scope(client_id, "read", extra)
}

/// The S256 challenge of a `code_verifier` of 43 `a` characters.
pub const CODE_CHALLENGE: &str = "ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA";

pub fn authorize_uri_with_scope(client_id: &str, scope: &str, extra: &str) -> String {
    format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope={scope}&state=xyz&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256{extra}"
    )
}
