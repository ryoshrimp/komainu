//! Shared helpers: a PostgreSQL container and record fixtures.
#![allow(dead_code)]

use std::collections::BTreeSet;

use komainu_adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
use komainu_domain::*;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use time::OffsetDateTime;

pub struct TestDb {
    pub pool: PgPool,
    pub factory: PgUnitOfWorkFactory,
    pub url: String,
    _container: ContainerAsync<Postgres>,
}

/// Starts `postgres:16-alpine` without running migrations.
pub async fn start_raw() -> TestDb {
    let container = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = connect(&PgStoreConfig::new(Secret::new(url.clone())))
        .await
        .expect("connect");
    TestDb {
        factory: PgUnitOfWorkFactory::new(pool.clone()),
        pool,
        url,
        _container: container,
    }
}

/// Starts a container and applies the migrations.
pub async fn start() -> TestDb {
    let db = start_raw().await;
    migrate(&db.pool).await.expect("migrate");
    db
}

pub fn t(secs: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + secs).unwrap()
}

pub fn hash(n: u8) -> TokenHash {
    TokenHash::from_bytes([n; 32])
}

pub fn cid(s: &str) -> ClientId {
    ClientId::try_new(s.to_owned()).unwrap()
}

pub fn subject(s: &str) -> Subject {
    Subject::try_new(s.to_owned()).unwrap()
}

pub fn scope(s: &str) -> ScopeSet {
    ScopeSet::parse(s).unwrap()
}

pub fn uri(s: &str) -> RedirectUri {
    RedirectUri::try_new(s.to_owned()).unwrap()
}

pub fn client_record(id: &str) -> ClientRecord {
    ClientRecord {
        id: cid(id),
        name: ClientName::try_new(format!("Client {id}")).unwrap(),
        client_type: ClientType::Confidential,
        auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        secret_hash: Some(hash(9)),
        redirect_uris: vec![uri("https://b.example/cb"), uri("https://a.example/cb")],
        grant_types: BTreeSet::from([GrantType::AuthorizationCode, GrantType::RefreshToken]),
        allowed_scopes: scope("read write"),
        default_scopes: scope("read"),
        skip_consent: true,
        status: ClientStatus::Active,
        created_at: t(0),
        updated_at: t(1),
    }
}

pub fn user_record(n: u128, name: &str) -> UserRecord {
    UserRecord {
        id: UserId::new(uuid::Uuid::from_u128(n)),
        username: Username::try_new(name.to_owned()).unwrap(),
        password_hash: PasswordHash::try_new("$argon2id$v=19$dummy".to_owned()).unwrap(),
        status: UserStatus::Active,
        created_at: t(0),
        updated_at: t(0),
    }
}

pub fn gid(n: u128) -> GrantId {
    GrantId::new(uuid::Uuid::from_u128(n))
}

pub fn grant_record(n: u128, client: &str) -> GrantRecord {
    GrantRecord {
        id: gid(n),
        client_id: cid(client),
        subject: Some(subject("alice")),
        scope: scope("read"),
        origin: GrantOrigin::AuthorizationCode { code_hash: hash(1) },
        status: GrantStatus::Active,
        created_at: t(0),
    }
}

/// Inserts a client through a unit of work and commits.
pub async fn seed_client(db: &TestDb, id: &str) {
    use komainu_application::UnitOfWorkFactory;
    let mut uow = db.factory.begin().await.unwrap();
    uow.clients()
        .insert(&Client::from_record(client_record(id)))
        .await
        .unwrap();
    uow.commit().await.unwrap();
}
