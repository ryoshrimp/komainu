//! Shared helpers: a PostgreSQL container, a config file and the `komainu` binary.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicU32, Ordering};

use komainu_adapter_postgres::{PgStoreConfig, connect, migrate};
use komainu_domain::Secret;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

pub struct TestDb {
    pub pool: PgPool,
    pub url: String,
    _container: ContainerAsync<Postgres>,
}

/// Starts `postgres:16-alpine` and applies the migrations.
pub async fn start_db() -> TestDb {
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
    migrate(&pool).await.expect("migrate");
    TestDb {
        pool,
        url,
        _container: container,
    }
}

/// A free local address (it may be taken again before use, which is unlikely in tests).
pub fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Writes a configuration file for `db_url` and returns its path.
pub fn write_config(db_url: &str, listen: SocketAddr, ops: SocketAddr) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "komainu-server-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("komainu.toml");
    let body = format!(
        r#"
[server]
listen = "{listen}"
public_base_url = "http://{listen}"
allow_insecure_http = true

[ops]
listen = "{ops}"

[database]
url = "{db_url}"

[session]
cookie_secure = false

[[scopes]]
name = "read"
description = "Read your data"

[[scopes]]
name = "write"
description = "Modify your data"

[cleanup]
enabled = false

[log]
format = "pretty"
"#
    );
    std::fs::write(&path, body).expect("write config");
    path
}

pub fn command(config: &std::path::Path) -> assert_cmd::Command {
    let mut command = assert_cmd::Command::new(env!("CARGO_BIN_EXE_komainu"));
    command
        .env_remove("RUST_LOG")
        .env_clear()
        .arg("--config")
        .arg(config);
    command
}

pub fn run(config: &std::path::Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = command(config);
    command.args(args);
    if let Some(stdin) = stdin {
        command.write_stdin(stdin);
    }
    command.output().expect("run komainu")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
