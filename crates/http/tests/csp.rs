//! The configured Content-Security-Policy reaches HTML responses only (design F-6).

mod common;

use common::*;
use komainu_http::{ContentSecurityPolicy, HttpConfig};
use komainu_testkit::TestEnv;

fn harness(policy: ContentSecurityPolicy) -> Harness {
    let config = HttpConfig::new(BASE)
        .unwrap()
        .with_content_security_policy(policy);
    Harness::from_config(TestEnv::new(app_config()), config)
}

#[tokio::test]
async fn custom_policy_is_sent_with_html_and_frame_ancestors_none() {
    let policy =
        ContentSecurityPolicy::custom("default-src 'none'; img-src https://cdn.example").unwrap();
    let h = harness(policy);
    let reply = h.send(get("/login?request_id=x", "")).await;
    assert_eq!(
        reply.header("content-security-policy"),
        Some("default-src 'none'; img-src https://cdn.example; frame-ancestors 'none'")
    );
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
}

#[tokio::test]
async fn default_policy_is_strict() {
    let h = harness(ContentSecurityPolicy::strict());
    let reply = h.send(get("/login?request_id=x", "")).await;
    assert_eq!(
        reply.header("content-security-policy"),
        Some("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
    );
}

#[tokio::test]
async fn json_responses_carry_no_policy() {
    let h = harness(ContentSecurityPolicy::strict());
    let reply = h
        .send(post_form("/token", "", "grant_type=authorization_code"))
        .await;
    assert_eq!(reply.header("content-security-policy"), None);
}
