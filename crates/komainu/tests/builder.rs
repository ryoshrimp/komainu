//! Acceptance tests of `KomainuBuilder`.

use komainu::{BuildError, Komainu};
use komainu_testkit::InMemoryUnitOfWorkFactory;

#[test]
fn missing_store_is_reported() {
    let error = Komainu::builder().build().err().unwrap();
    assert!(matches!(error, BuildError::MissingStore));
}

#[cfg(feature = "http")]
#[test]
fn missing_http_config_is_reported() {
    let builder = Komainu::builder().store(InMemoryUnitOfWorkFactory::new());
    #[cfg(not(feature = "std"))]
    let builder = no_std_parts(builder);
    let error = builder.build().err().unwrap();
    assert!(matches!(error, BuildError::MissingHttpConfig));
}

#[cfg(not(feature = "std"))]
fn no_std_parts(builder: komainu::KomainuBuilder) -> komainu::KomainuBuilder {
    use komainu_testkit::{FixedClock, PlainPasswordHasher, SequenceRandom};
    use std::sync::Arc;
    builder
        .clock(Arc::new(FixedClock::new(time::OffsetDateTime::UNIX_EPOCH)))
        .random(Arc::new(SequenceRandom::default()))
        .password_hasher(Arc::new(PlainPasswordHasher))
}

#[cfg(not(feature = "std"))]
#[test]
fn missing_clock_without_std() {
    let error = Komainu::builder()
        .store(InMemoryUnitOfWorkFactory::new())
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, BuildError::MissingComponent("clock")));
}

#[cfg(all(not(feature = "std"), not(feature = "http")))]
#[test]
fn all_components_without_std_build() {
    let builder = no_std_parts(Komainu::builder().store(InMemoryUnitOfWorkFactory::new()));
    assert!(builder.build().is_ok());
}

#[cfg(feature = "http")]
mod flow {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use komainu::Komainu;
    use komainu::application::{
        ApplicationConfig, AuthenticationOutcome, BoxFuture, LoginCredentials, RegisterClient,
        RequestContext, ResourceOwnerAuthenticator, ScopeDefinition, StoreError, UnitOfWork,
    };
    use komainu::domain::{
        ClientName, ClientType, GrantType, NewPassword, RedirectUri, ScopeSet, ScopeToken, Secret,
        Subject, TokenEndpointAuthMethod, Username,
    };
    use komainu::http::{
        ConsentScreen, DefaultScreens, ErrorScreen, HttpConfig, LoggedOutScreen, LoginScreen,
        RenderError, ScreenRenderer,
    };
    use komainu_testkit::{
        FixedClock, InMemoryUnitOfWorkFactory, PlainPasswordHasher, SequenceRandom,
    };
    use tower::ServiceExt;

    const BASE: &str = "https://auth.example.com";
    const REDIRECT: &str = "https://app.example/cb";

    fn config() -> ApplicationConfig {
        ApplicationConfig::default().with_scopes(vec![ScopeDefinition {
            name: ScopeToken::try_new("read".to_owned()).unwrap(),
            description: "Read your data".to_owned(),
        }])
    }

    fn builder() -> komainu::KomainuBuilder {
        Komainu::builder()
            .store(InMemoryUnitOfWorkFactory::new())
            .application_config(config())
            .clock(Arc::new(FixedClock::new(
                time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            )))
            .random(Arc::new(SequenceRandom::default()))
            .password_hasher(Arc::new(PlainPasswordHasher))
            .http_config(HttpConfig::new(BASE).unwrap())
    }

    fn ctx() -> RequestContext {
        RequestContext {
            request_id: "test".to_owned(),
            client_ip: None,
        }
    }

    async fn register(komainu: &Komainu) -> (String, String) {
        let registered = komainu
            .admin()
            .register_client(
                &ctx(),
                RegisterClient {
                    name: ClientName::try_new("Example App".to_owned()).unwrap(),
                    client_type: ClientType::Confidential,
                    auth_method: TokenEndpointAuthMethod::ClientSecretPost,
                    redirect_uris: vec![RedirectUri::try_new(REDIRECT.to_owned()).unwrap()],
                    grant_types: [GrantType::AuthorizationCode].into_iter().collect(),
                    allowed_scopes: ScopeSet::parse("read").unwrap(),
                    default_scopes: ScopeSet::parse("read").unwrap(),
                    skip_consent: false,
                },
            )
            .await
            .unwrap();
        (
            registered.client.id.as_inner().to_string(),
            registered.secret.unwrap().expose().to_owned(),
        )
    }

    async fn create_alice(komainu: &Komainu) {
        komainu
            .admin()
            .create_user(
                &ctx(),
                Username::try_new("alice".to_owned()).unwrap(),
                NewPassword::try_new(Secret::new("correct horse".to_owned())).unwrap(),
            )
            .await
            .unwrap();
    }

    struct Reply {
        status: StatusCode,
        headers: axum::http::HeaderMap,
        body: String,
    }

    impl Reply {
        fn header(&self, name: &str) -> &str {
            self.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        }

        fn cookie(&self, name: &str) -> Option<String> {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find(|v| v.starts_with(&format!("{name}=")))
                .map(str::to_owned)
        }

        fn cookie_value(&self, name: &str) -> String {
            let cookie = self.cookie(name).unwrap();
            cookie[name.len() + 1..]
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        }
    }

    async fn send(komainu: &Komainu, request: Request<Body>) -> Reply {
        let response = komainu.router().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    fn get(uri: &str, cookies: &str) -> Request<Body> {
        Request::get(uri)
            .header(header::COOKIE, cookies)
            .body(Body::empty())
            .unwrap()
    }

    fn post(uri: &str, cookies: &str, body: String) -> Request<Body> {
        Request::post(uri)
            .header(header::COOKIE, cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    fn authorize_uri(client_id: &str) -> String {
        format!(
            "/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=xyz"
        )
    }

    fn query_param(url: &str, name: &str) -> String {
        url.split(['?', '&'])
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn full_flow_issues_a_valid_access_token() {
        let komainu = builder().build().unwrap();
        let (client_id, secret) = register(&komainu).await;
        create_alice(&komainu).await;

        let start = send(&komainu, get(&authorize_uri(&client_id), "")).await;
        assert_eq!(start.status, StatusCode::FOUND);
        let request_id = query_param(start.header("location"), "request_id");
        let csrf = start.cookie_value("komainu_csrf");
        let cookies = format!("komainu_csrf={csrf}");

        let login = send(
            &komainu,
            post(
                "/login",
                &cookies,
                format!("request_id={request_id}&csrf_token={csrf}&username=alice&password=correct+horse"),
            ),
        )
        .await;
        assert_eq!(login.status, StatusCode::FOUND);
        let cookies = format!(
            "{cookies}; komainu_session={}",
            login.cookie_value("komainu_session")
        );

        let consent = send(
            &komainu,
            get(
                &format!("/authorize/resume?request_id={request_id}"),
                &cookies,
            ),
        )
        .await;
        assert_eq!(consent.status, StatusCode::OK);

        let decision = send(
            &komainu,
            post(
                "/authorize/decision",
                &cookies,
                format!("request_id={request_id}&csrf_token={csrf}&decision=approve"),
            ),
        )
        .await;
        assert_eq!(decision.status, StatusCode::FOUND);
        let code = query_param(decision.header("location"), "code");

        let token = send(
            &komainu,
            Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(token.status, StatusCode::OK, "{}", token.body);
        let json: serde_json::Value = serde_json::from_str(&token.body).unwrap();
        let access = json["access_token"].as_str().unwrap();
        let verified = komainu.token().verify_access_token(access).await;
        assert!(matches!(verified, Ok(Some(_))), "{verified:?}");
    }

    struct AlwaysAuthenticated;

    impl ResourceOwnerAuthenticator for AlwaysAuthenticated {
        fn authenticate<'a>(
            &'a self,
            _uow: &'a mut dyn UnitOfWork,
            _credentials: &'a LoginCredentials,
        ) -> BoxFuture<'a, Result<AuthenticationOutcome, StoreError>> {
            Box::pin(async {
                Ok(AuthenticationOutcome::Authenticated(
                    Subject::try_new("ext-user".to_owned()).unwrap(),
                ))
            })
        }

        fn is_active<'a>(
            &'a self,
            _uow: &'a mut dyn UnitOfWork,
            _subject: &'a Subject,
        ) -> BoxFuture<'a, Result<bool, StoreError>> {
            Box::pin(async { Ok(true) })
        }
    }

    #[tokio::test]
    async fn custom_authenticator_accepts_unknown_users() {
        let komainu = builder()
            .authenticator(Arc::new(AlwaysAuthenticated))
            .build()
            .unwrap();
        let (client_id, _) = register(&komainu).await;
        let start = send(&komainu, get(&authorize_uri(&client_id), "")).await;
        let request_id = query_param(start.header("location"), "request_id");
        let csrf = start.cookie_value("komainu_csrf");
        let login = send(
            &komainu,
            post(
                "/login",
                &format!("komainu_csrf={csrf}"),
                format!("request_id={request_id}&csrf_token={csrf}&username=nobody&password=whatever-pass"),
            ),
        )
        .await;
        assert_eq!(login.status, StatusCode::FOUND);
        assert!(login.header("location").contains("/authorize/resume"));
    }

    #[tokio::test]
    async fn csrf_cookie_lives_as_long_as_the_authorization_request() {
        let komainu = builder()
            .application_config(
                config().with_authorization_request_ttl(time::Duration::seconds(120)),
            )
            .build()
            .unwrap();
        let (client_id, _) = register(&komainu).await;
        let start = send(&komainu, get(&authorize_uri(&client_id), "")).await;
        assert!(
            start
                .cookie("komainu_csrf")
                .unwrap()
                .contains("Max-Age=120")
        );
    }

    struct Fixed;

    impl ScreenRenderer for Fixed {
        fn login(&self, _: &LoginScreen<'_>) -> Result<String, RenderError> {
            Ok("<p>custom login</p>".to_owned())
        }
        fn consent(&self, s: &ConsentScreen<'_>) -> Result<String, RenderError> {
            DefaultScreens.consent(s)
        }
        fn error(&self, s: &ErrorScreen<'_>) -> Result<String, RenderError> {
            DefaultScreens.error(s)
        }
        fn logged_out(&self, s: &LoggedOutScreen<'_>) -> Result<String, RenderError> {
            DefaultScreens.logged_out(s)
        }
    }

    #[tokio::test]
    async fn custom_screens_render_the_login_page() {
        let komainu = builder().screens(Arc::new(Fixed)).build().unwrap();
        let (client_id, _) = register(&komainu).await;
        let start = send(&komainu, get(&authorize_uri(&client_id), "")).await;
        let request_id = query_param(start.header("location"), "request_id");
        let csrf = start.cookie_value("komainu_csrf");
        let page = send(
            &komainu,
            get(
                &format!("/login?request_id={request_id}"),
                &format!("komainu_csrf={csrf}"),
            ),
        )
        .await;
        assert_eq!(page.status, StatusCode::OK);
        assert_eq!(page.body, "<p>custom login</p>");
    }
}
