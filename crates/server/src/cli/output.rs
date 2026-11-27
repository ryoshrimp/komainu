//! Rendering of views as text or JSON.

use clap::ValueEnum;
use komainu::application::{ClientView, UserView};
use komainu::domain::{ClientKeys, OpaqueToken};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::Exit;

/// `--output` choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

fn status(active: bool) -> &'static str {
    if active { "active" } else { "disabled" }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KeysJson {
    Jwks { jwks: serde_json::Value },
    JwksUri { jwks_uri: String },
}

impl KeysJson {
    fn new(keys: &ClientKeys) -> Self {
        match keys {
            ClientKeys::Jwks(doc) => Self::Jwks {
                jwks: serde_json::from_str(doc.as_str())
                    .unwrap_or_else(|_| serde_json::Value::String(doc.as_str().to_owned())),
            },
            ClientKeys::JwksUri(uri) => Self::JwksUri {
                jwks_uri: uri.as_str().to_owned(),
            },
        }
    }
}

/// One line of `show` text output: `keys: jwks (N keys)` or `keys: jwks_uri <URL>`.
fn keys_line(keys: &ClientKeys) -> String {
    match keys {
        ClientKeys::Jwks(doc) => {
            let count = serde_json::from_str::<serde_json::Value>(doc.as_str())
                .ok()
                .and_then(|v| v.get("keys").and_then(|k| k.as_array().map(Vec::len)))
                .unwrap_or(0);
            format!("keys: jwks ({count} keys)")
        }
        ClientKeys::JwksUri(uri) => format!("keys: jwks_uri {}", uri.as_str()),
    }
}

#[derive(Serialize)]
struct ClientJson<'a> {
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    name: &'a str,
    client_type: &'static str,
    auth_method: &'static str,
    redirect_uris: Vec<&'a str>,
    grant_types: Vec<&'static str>,
    allowed_scopes: Vec<&'a str>,
    default_scopes: Vec<&'a str>,
    skip_consent: bool,
    keys: Option<KeysJson>,
    active: bool,
    created_at: String,
    updated_at: String,
}

impl<'a> ClientJson<'a> {
    fn new(view: &'a ClientView, secret: Option<&'a OpaqueToken>) -> Self {
        Self {
            client_id: view.id.as_inner(),
            client_secret: secret.map(OpaqueToken::expose),
            name: view.name.as_inner(),
            client_type: view.client_type.as_str(),
            auth_method: view.auth_method.as_str(),
            redirect_uris: view.redirect_uris.iter().map(|u| u.as_str()).collect(),
            grant_types: view.grant_types.iter().map(|g| g.as_str()).collect(),
            allowed_scopes: view.allowed_scopes.iter().map(|s| s.as_str()).collect(),
            default_scopes: view.default_scopes.iter().map(|s| s.as_str()).collect(),
            skip_consent: view.skip_consent,
            keys: view.keys.as_ref().map(KeysJson::new),
            active: view.active,
            created_at: rfc3339(view.created_at),
            updated_at: rfc3339(view.updated_at),
        }
    }
}

#[derive(Serialize)]
struct UserJson<'a> {
    user_id: String,
    username: &'a str,
    active: bool,
    created_at: String,
    updated_at: String,
}

impl<'a> UserJson<'a> {
    fn new(view: &'a UserView) -> Self {
        Self {
            user_id: view.id.as_inner().hyphenated().to_string(),
            username: view.username.as_str(),
            active: view.active,
            created_at: rfc3339(view.created_at),
            updated_at: rfc3339(view.updated_at),
        }
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<String, Exit> {
    serde_json::to_string(value).map_err(Exit::runtime)
}

/// Prints one client. The secret is passed only by `create` and `rotate-secret`.
pub fn print_client(
    format: OutputFormat,
    view: &ClientView,
    secret: Option<&OpaqueToken>,
) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => println!("{}", to_json(&ClientJson::new(view, secret))?),
        OutputFormat::Text => {
            println!("client_id: {}", view.id.as_inner());
            print_secret_line(secret);
        }
    }
    Ok(())
}

/// Prints the id and the secret of `rotate-secret`, in the same shape as `create`.
pub fn print_rotated(
    format: OutputFormat,
    view: &ClientView,
    secret: &OpaqueToken,
) -> Result<(), Exit> {
    print_client(format, view, Some(secret))
}

fn print_secret_line(secret: Option<&OpaqueToken>) {
    if let Some(secret) = secret {
        println!("client_secret: {}", secret.expose());
        eprintln!("Store the client secret now. It cannot be shown again.");
    }
}

/// Prints one client with all its fields (`show`, `update`).
pub fn print_client_details(format: OutputFormat, view: &ClientView) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => println!("{}", to_json(&ClientJson::new(view, None))?),
        OutputFormat::Text => {
            let join = |items: Vec<&str>| items.join(" ");
            println!("client_id: {}", view.id.as_inner());
            println!("name: {}", view.name.as_inner());
            println!("client_type: {}", view.client_type.as_str());
            println!("auth_method: {}", view.auth_method.as_str());
            println!(
                "redirect_uris: {}",
                join(view.redirect_uris.iter().map(|u| u.as_str()).collect())
            );
            println!(
                "grant_types: {}",
                join(view.grant_types.iter().map(|g| g.as_str()).collect())
            );
            println!("allowed_scopes: {}", view.allowed_scopes);
            println!("default_scopes: {}", view.default_scopes);
            println!("skip_consent: {}", view.skip_consent);
            if let Some(keys) = &view.keys {
                println!("{}", keys_line(keys));
            }
            println!("active: {}", view.active);
            println!("created_at: {}", rfc3339(view.created_at));
            println!("updated_at: {}", rfc3339(view.updated_at));
        }
    }
    Ok(())
}

/// Prints a list of clients: a JSON array, or one tab-separated line per client.
pub fn print_client_list(format: OutputFormat, views: &[ClientView]) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => {
            let items: Vec<_> = views.iter().map(|v| ClientJson::new(v, None)).collect();
            println!("{}", to_json(&items)?);
        }
        OutputFormat::Text => {
            for view in views {
                println!(
                    "{}\t{}\t{}\t{}",
                    view.id.as_inner(),
                    view.name.as_inner(),
                    view.client_type.as_str(),
                    status(view.active)
                );
            }
        }
    }
    Ok(())
}

/// Prints one user with all its fields.
pub fn print_user_details(format: OutputFormat, view: &UserView) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => println!("{}", to_json(&UserJson::new(view))?),
        OutputFormat::Text => {
            println!("user_id: {}", view.id.as_inner().hyphenated());
            println!("username: {}", view.username.as_str());
            println!("active: {}", view.active);
            println!("created_at: {}", rfc3339(view.created_at));
            println!("updated_at: {}", rfc3339(view.updated_at));
        }
    }
    Ok(())
}

/// Prints a list of users: a JSON array, or `<username>\t<active|disabled>` per line.
pub fn print_user_list(format: OutputFormat, views: &[UserView]) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => {
            let items: Vec<_> = views.iter().map(UserJson::new).collect();
            println!("{}", to_json(&items)?);
        }
        OutputFormat::Text => {
            for view in views {
                println!("{}\t{}", view.username.as_str(), status(view.active));
            }
        }
    }
    Ok(())
}
