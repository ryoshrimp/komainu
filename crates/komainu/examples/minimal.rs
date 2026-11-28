//! A complete authorization server: PostgreSQL, the built-in users and the default screens.
//!
//! ```text
//! DATABASE_URL=postgres://user:pass@localhost/komainu cargo run -p komainu --example minimal
//! ```

use std::net::SocketAddr;

use komainu::Komainu;
use komainu::adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
use komainu::adapter_std::{OsSecureRandom, SystemClock};
use komainu::application::{
    AdminError, ApplicationConfig, RegisterClient, RequestContext, ScopeDefinition, new_uuid_v7,
};
use komainu::domain::{
    ClientName, ClientType, GrantType, NewPassword, RedirectUri, ScopeSet, ScopeToken, Secret,
    TokenEndpointAuthMethod, Username,
};
use komainu::http::HttpConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pg = PgStoreConfig::new(Secret::new(std::env::var("DATABASE_URL")?));
    let pool = connect(&pg).await?;
    migrate(&pool).await?;

    let application = ApplicationConfig::default().with_scopes(vec![ScopeDefinition {
        name: ScopeToken::try_new("read".to_owned())?,
        description: "Read your data".to_owned(),
    }]);
    let komainu = Komainu::builder()
        .store(PgUnitOfWorkFactory::new(pool))
        .application_config(application)
        .http_config(HttpConfig::new_insecure("http://127.0.0.1:8080")?)
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
                keys: None,
            },
        )
        .await?;
    println!("client_id: {}", registered.client.id.as_inner());
    if let Some(secret) = &registered.secret {
        println!("client_secret: {}", secret.expose());
    }

    let created = komainu
        .admin()
        .create_user(
            &ctx,
            Username::try_new("alice".to_owned())?,
            NewPassword::try_new(Secret::new("correct horse battery staple".to_owned()))?,
        )
        .await;
    match created {
        Ok(_) | Err(AdminError::Conflict) => {}
        Err(error) => return Err(error.into()),
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    println!("listening on http://127.0.0.1:8080");
    axum::serve(
        listener,
        komainu
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
