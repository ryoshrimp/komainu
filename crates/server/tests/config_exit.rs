//! Configuration errors end the process with exit code 2 (no database needed).

mod common;

use std::path::PathBuf;

fn write(name: &str, body: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("komainu-config-exit-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("komainu.toml");
    std::fs::write(&path, body).expect("write");
    path
}

const BASE: &str = r#"
[server]
public_base_url = "https://auth.example.com"
[database]
url = "postgres://u:p@localhost/db"
"#;

fn exit_code(path: &std::path::Path) -> (Option<i32>, String) {
    let output = common::run(path, &["migrate"], None);
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn config_non_string_database_url_exits_2() {
    let path = write(
        "url",
        "[server]\npublic_base_url = \"https://a.example\"\n[database]\nurl = 123\n",
    );
    let (code, stderr) = exit_code(&path);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("database.url"), "{stderr}");
    assert!(stderr.contains("failed to deserialize secret"), "{stderr}");
}

#[test]
fn config_http_public_base_url_without_opt_in_exits_2() {
    let path = write("http", &BASE.replace("https://auth", "http://auth"));
    assert_eq!(exit_code(&path).0, Some(2));
}

#[test]
fn config_duplicate_scope_names_exit_2() {
    let body = format!(
        "{BASE}\n[[scopes]]\nname = \"read\"\ndescription = \"a\"\n[[scopes]]\nname = \"read\"\ndescription = \"b\"\n"
    );
    let path = write("dup", &body);
    assert_eq!(exit_code(&path).0, Some(2));
}

#[test]
fn config_invalid_log_filter_exits_2_for_every_command() {
    let path = write(
        "filter",
        &format!("{BASE}\n[log]\nformat = \"json\"\nfilter = \"info,[\"\n"),
    );
    for command in ["migrate", "serve"] {
        common::command(&path)
            .arg(command)
            .assert()
            .code(2)
            .stderr(predicates::str::contains("log.filter"));
    }
}

#[test]
fn generate_encryption_key_needs_no_configuration() {
    let missing = std::env::temp_dir().join("komainu-no-such-dir/komainu.toml");
    let output = common::run(&missing, &["key", "generate-encryption-key"], None);
    assert_eq!(output.status.code(), Some(0));
    let key = String::from_utf8_lossy(&output.stdout);
    assert_eq!(key.trim().len(), 44, "{key}");
    let secret = komainu::domain::Secret::new(key.trim().to_owned());
    komainu::AesGcmKeySealer::from_base64(
        &secret,
        std::sync::Arc::new(komainu::adapter_std::OsSecureRandom),
    )
    .expect("the printed key is readable");
}

#[test]
fn key_commands_without_signing_exit_2_before_the_database() {
    let path = write("key-disabled", BASE);
    for args in [
        &["key", "list"][..],
        &["key", "rotate", "--alg", "ES256"],
        &["key", "revoke", "kid"],
    ] {
        let output = common::run(&path, args, None);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("signing is disabled"), "{stderr}");
    }
}

#[test]
fn invalid_encryption_key_exits_2_without_echoing_it() {
    let secret = "hunter2-not-base64";
    let body = format!("{BASE}\n[signing]\nencryption_key = \"{secret}\"\n");
    let path = write("key-bad", &body);
    let (code, stderr) = exit_code(&path);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.contains(secret), "{stderr}");
}
