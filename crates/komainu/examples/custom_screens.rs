//! Replaces the login screen with a Japanese one and sets a custom Content-Security-Policy.
//! No database is needed: the store lives in memory.
//!
//! ```text
//! cargo run -p komainu --example custom_screens
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use komainu::Komainu;
use komainu::adapter_std::{OsSecureRandom, SystemClock};
use komainu::application::{
    ApplicationConfig, RegisterClient, RequestContext, ScopeDefinition, new_uuid_v7,
};
use komainu::domain::{
    ClientName, ClientType, GrantType, NewPassword, RedirectUri, ScopeSet, ScopeToken, Secret,
    TokenEndpointAuthMethod, Username,
};
use komainu::http::{
    ConsentScreen, ContentSecurityPolicy, DefaultScreens, ErrorScreen, HttpConfig, LoggedOutScreen,
    LoginScreen, RenderError, ScreenRenderer,
};
use komainu_testkit::InMemoryUnitOfWorkFactory;

/// Replaces `& < > " '`. Prefer a template engine such as askama in real code.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A Japanese login screen; the other screens stay the built-in ones.
struct JapaneseLogin;

impl ScreenRenderer for JapaneseLogin {
    fn login(&self, screen: &LoginScreen<'_>) -> Result<String, RenderError> {
        let error = if screen.error.is_some() {
            "<p>ユーザー名またはパスワードが違います。</p>"
        } else {
            ""
        };
        Ok(format!(
            "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">\
<title>ログイン</title></head><body>\
<h1>{client} にログイン</h1>{error}\
<form method=\"post\" action=\"{action}\">\
<input type=\"hidden\" name=\"request_id\" value=\"{request_id}\">\
<input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
<label>ユーザー名 <input name=\"username\" value=\"{username}\"></label>\
<label>パスワード <input type=\"password\" name=\"password\"></label>\
<button type=\"submit\">ログイン</button></form></body></html>",
            client = escape_html(screen.client_name),
            action = escape_html(screen.form.action),
            request_id = escape_html(screen.form.authorization_request_id),
            csrf = escape_html(screen.form.csrf_token),
            username = escape_html(screen.username),
        ))
    }

    fn consent(&self, screen: &ConsentScreen<'_>) -> Result<String, RenderError> {
        DefaultScreens.consent(screen)
    }

    fn error(&self, screen: &ErrorScreen<'_>) -> Result<String, RenderError> {
        DefaultScreens.error(screen)
    }

    fn logged_out(&self, screen: &LoggedOutScreen<'_>) -> Result<String, RenderError> {
        DefaultScreens.logged_out(screen)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let application = ApplicationConfig::default().with_scopes(vec![ScopeDefinition {
        name: ScopeToken::try_new("read".to_owned())?,
        description: "Read your data".to_owned(),
    }]);
    // `'unsafe-inline'` stays because the delegated `DefaultScreens` use an inline <style>.
    let csp = ContentSecurityPolicy::custom(
        "default-src 'none'; style-src 'unsafe-inline' https://cdn.example; img-src 'self'",
    )?;
    let komainu = Komainu::builder()
        .store(InMemoryUnitOfWorkFactory::new())
        .application_config(application)
        .http_config(
            HttpConfig::new_insecure("http://127.0.0.1:8080")?.with_content_security_policy(csp),
        )
        .screens(Arc::new(JapaneseLogin))
        .build()?;

    let ctx = RequestContext {
        request_id: new_uuid_v7(&SystemClock, &OsSecureRandom).to_string(),
        client_ip: None,
    };
    let registered = komainu
        .admin()
        .register_client(
            &ctx,
            RegisterClient {
                name: ClientName::try_new("Example".to_owned())?,
                client_type: ClientType::Confidential,
                auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
                redirect_uris: vec![RedirectUri::try_new("http://127.0.0.1:9000/cb".to_owned())?],
                grant_types: [GrantType::AuthorizationCode, GrantType::RefreshToken]
                    .into_iter()
                    .collect(),
                allowed_scopes: ScopeSet::parse("read")?,
                default_scopes: ScopeSet::parse("read")?,
                skip_consent: false,
            },
        )
        .await?;
    komainu
        .admin()
        .create_user(
            &ctx,
            Username::try_new("alice".to_owned())?,
            NewPassword::try_new(Secret::new("correct horse battery staple".to_owned()))?,
        )
        .await?;

    println!(
        "open: http://127.0.0.1:8080/authorize?response_type=code&client_id={}\
&redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcb&scope=read&state=xyz",
        registered.client.id.as_inner()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(
        listener,
        komainu
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
