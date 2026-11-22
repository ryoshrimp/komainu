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
