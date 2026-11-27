//! jwt-bearer grant over HTTP (assertion design F-8, F-10).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use komainu_application::{Clock, RegisterIssuer};
use komainu_domain::{ExternalSubject, GrantType, IssuerId, JwksDocument, Username};
use komainu_http::HttpConfig;
use komainu_jose::jwt::{self, Audience, Claims, NoCustomClaims, RegisteredClaims};
use komainu_jose::{JwkSet, Kid, SigningKey};
use komainu_testkit::TestEnv;
use serde_json::Value;
use time::Duration;

const GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
const EXTERNAL: &str = "https://idp.example.org";

fn harness() -> Harness {
    Harness::from_config(
        TestEnv::new(app_config().with_issuer(BASE)),
        HttpConfig::new(BASE).unwrap(),
    )
}

fn form(auth: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, auth)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn assertion(h: &Harness, key: &SigningKey, iss: &str, sub: &str) -> String {
    let now = h.env.clock.now();
    jwt::encode(
        &Claims {
            registered: RegisteredClaims {
                iss: Some(iss.to_owned()),
                sub: Some(sub.to_owned()),
                aud: Some(Audience::One(BASE.to_owned())),
                exp: Some(now + Duration::seconds(60)),
                nbf: None,
                iat: None,
                jti: Some("j1".to_owned()),
            },
            custom: NoCustomClaims,
        },
        key,
        &komainu_jose::jws::SignOptions::new(),
    )
    .unwrap()
}

/// Registers a client, a user and a trusted issuer mapping `ext-1` to alice.
async fn setup(h: &Harness) -> (String, SigningKey) {
    let key = SigningKey::generate_es256()
        .unwrap()
        .with_kid(Kid::try_new("k1".to_owned()).unwrap());
    let mut input = confidential(&[GrantType::JwtBearer]);
    input.redirect_uris.clear();
    let c = h.register(input).await;
    h.create_user("alice").await;
    let issuer = IssuerId::try_new(EXTERNAL.to_owned()).unwrap();
    let doc = JwkSet::new(vec![key.verifying_key()]).unwrap().to_json();
    h.admin
        .register_issuer(
            &ctx(),
            RegisterIssuer {
                id: issuer.clone(),
                jwks: JwksDocument::try_new(doc).unwrap(),
                allowed_clients: [c.id.clone()].into(),
            },
        )
        .await
        .unwrap();
    h.admin
        .map_subject(
            &ctx(),
            &issuer,
            ExternalSubject::try_new("ext-1".to_owned()).unwrap(),
            &Username::try_new("alice".to_owned()).unwrap(),
        )
        .await
        .unwrap();
    (basic(&c.id(), &c.secret()), key)
}

fn basic(id: &str, secret: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

#[tokio::test]
async fn jwt_bearer_issues_an_access_token_without_refresh_token() {
    let h = harness();
    let (auth, key) = setup(&h).await;
    let jwt = assertion(&h, &key, EXTERNAL, "ext-1");
    let reply = h
        .send(form(&auth, &format!("grant_type={GRANT}&assertion={jwt}")))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let json: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["access_token"].is_string());
    assert!(json.get("refresh_token").is_none());
}

#[tokio::test]
async fn missing_assertion_is_invalid_request() {
    let h = harness();
    let (auth, _) = setup(&h).await;
    let reply = h.send(form(&auth, &format!("grant_type={GRANT}"))).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let json: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn unregistered_issuer_is_invalid_grant() {
    let h = harness();
    let (auth, key) = setup(&h).await;
    let jwt = assertion(&h, &key, "https://other.example.org", "ext-1");
    let reply = h
        .send(form(&auth, &format!("grant_type={GRANT}&assertion={jwt}")))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let json: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn metadata_lists_jwt_bearer_only_with_an_issuer() {
    let json = |body: String| serde_json::from_str::<Value>(&body).unwrap();
    let uri = "/.well-known/oauth-authorization-server";
    let urn = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    let with = json(harness().send(get(uri, "")).await.body);
    assert!(
        with["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&Value::from(urn))
    );
    let without = json(Harness::new().send(get(uri, "")).await.body);
    assert!(
        !without["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&Value::from(urn))
    );
}
