//! `private_key_jwt` over HTTP (assertion design F-2 to F-4, F-7).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use komainu_application::{Clock, RegisterClient};
use komainu_domain::{ClientKeys, GrantType, JwksDocument, TokenEndpointAuthMethod};
use komainu_http::HttpConfig;
use komainu_jose::jwt::{self, Audience, Claims, NoCustomClaims, RegisteredClaims};
use komainu_jose::{JwkSet, Kid, SigningKey};
use komainu_testkit::TestEnv;
use serde_json::Value;
use time::Duration;

const TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";

fn harness() -> Harness {
    Harness::from_config(
        TestEnv::new(app_config().with_issuer(BASE)),
        HttpConfig::new(BASE).unwrap(),
    )
}

fn form(uri: &str, auth: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

fn assertion(h: &Harness, key: &SigningKey, id: &str, jti: &str) -> String {
    let now = h.env.clock.now();
    jwt::encode(
        &Claims {
            registered: RegisteredClaims {
                iss: Some(id.to_owned()),
                sub: Some(id.to_owned()),
                aud: Some(Audience::One(BASE.to_owned())),
                exp: Some(now + Duration::seconds(60)),
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

async fn client(h: &Harness) -> (Registered, SigningKey) {
    let key = SigningKey::generate_es256()
        .unwrap()
        .with_kid(Kid::try_new("k1".to_owned()).unwrap());
    let doc = JwkSet::new(vec![key.verifying_key()]).unwrap().to_json();
    let mut input: RegisterClient = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    input.auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    input.keys = Some(ClientKeys::Jwks(JwksDocument::try_new(doc).unwrap()));
    (h.register(input).await, key)
}

fn body(extra: &str, jwt: &str) -> String {
    format!(
        "grant_type=client_credentials&client_assertion_type={TYPE}&client_assertion={jwt}{extra}"
    )
}

#[tokio::test]
async fn token_with_assertion_succeeds_and_replay_gives_401() {
    let h = harness();
    let (c, key) = client(&h).await;
    let jwt = assertion(&h, &key, &c.id(), "j1");
    let ok = h.send(form("/token", None, &body("", &jwt))).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    let replay = h.send(form("/token", None, &body("", &jwt))).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    let json: Value = serde_json::from_str(&replay.body).unwrap();
    assert_eq!(json["error"], "invalid_client");
    // No Basic was attempted, so no challenge header.
    assert!(replay.header("www-authenticate").is_none());
}

#[tokio::test]
async fn client_id_in_body_may_accompany_the_assertion() {
    let h = harness();
    let (c, key) = client(&h).await;
    let jwt = assertion(&h, &key, &c.id(), "j2");
    let r = h
        .send(form(
            "/token",
            None,
            &body(&format!("&client_id={}", c.id()), &jwt),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let jwt = assertion(&h, &key, &c.id(), "j3");
    let r = h
        .send(form("/token", None, &body("&client_id=someone-else", &jwt)))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_combinations_are_rejected() {
    let h = harness();
    let (c, key) = client(&h).await;
    let jwt = assertion(&h, &key, &c.id(), "j4");
    let only_type = format!("grant_type=client_credentials&client_assertion_type={TYPE}");
    let only_assertion = format!("grant_type=client_credentials&client_assertion={jwt}");
    let with_secret = body("&client_secret=x", &jwt);
    let duplicated = body(&format!("&client_assertion={jwt}"), &jwt);
    for case in [only_type, only_assertion, with_secret, duplicated] {
        let r = h.send(form("/token", None, &case)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{case}: {}", r.body);
    }
    // Together with Basic.
    let r = h
        .send(form("/token", Some("Basic eDp5"), &body("", &jwt)))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Empty values count as absent.
    let r = h
        .send(form(
            "/token",
            None,
            "grant_type=client_credentials&client_assertion_type=&client_assertion=",
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Unknown assertion type.
    let r = h
        .send(form(
            "/token",
            None,
            &format!(
                "grant_type=client_credentials&client_assertion_type=urn%3Ax&client_assertion={jwt}"
            ),
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_with_assertion_works_once() {
    let h = harness();
    let (c, key) = client(&h).await;
    let jwt = assertion(&h, &key, &c.id(), "j5");
    let issued = h.send(form("/token", None, &body("", &jwt))).await;
    let token = serde_json::from_str::<Value>(&issued.body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let jwt = assertion(&h, &key, &c.id(), "j6");
    let revoke_body = format!("token={token}&client_assertion_type={TYPE}&client_assertion={jwt}");
    let r = h.send(form("/revoke", None, &revoke_body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let again = h.send(form("/revoke", None, &revoke_body)).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metadata_advertises_private_key_jwt_only_with_an_issuer() {
    let h = harness();
    let json: Value = serde_json::from_str(
        &h.send(get("/.well-known/oauth-authorization-server", ""))
            .await
            .body,
    )
    .unwrap();
    assert_eq!(
        json["token_endpoint_auth_methods_supported"],
        serde_json::json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ])
    );
    assert_eq!(
        json["token_endpoint_auth_signing_alg_values_supported"],
        serde_json::json!(["RS256", "ES256"])
    );
    assert_eq!(
        json["revocation_endpoint_auth_signing_alg_values_supported"],
        serde_json::json!(["RS256", "ES256"])
    );
    let plain = Harness::new();
    let json: Value = serde_json::from_str(
        &plain
            .send(get("/.well-known/oauth-authorization-server", ""))
            .await
            .body,
    )
    .unwrap();
    assert!(
        json.get("token_endpoint_auth_signing_alg_values_supported")
            .is_none()
    );
    assert!(
        json.get("revocation_endpoint_auth_signing_alg_values_supported")
            .is_none()
    );
}
