//! Rendering of views as text or JSON.

use clap::ValueEnum;
use komainu::application::{ClientView, IssuerView, SubjectMappingView, UserView};
use komainu::domain::{ClientKeys, JwksDocument, OpaqueToken};
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
                jwks: jwks_value(doc),
            },
            ClientKeys::JwksUri(uri) => Self::JwksUri {
                jwks_uri: uri.as_str().to_owned(),
            },
        }
    }
}

/// The registered JWKS as a JSON value (the string itself if it does not parse).
fn jwks_value(doc: &JwksDocument) -> serde_json::Value {
    serde_json::from_str(doc.as_str())
        .unwrap_or_else(|_| serde_json::Value::String(doc.as_str().to_owned()))
}

fn jwks_key_count(doc: &JwksDocument) -> usize {
    jwks_value(doc)
        .get("keys")
        .and_then(|k| k.as_array().map(Vec::len))
        .unwrap_or(0)
}

/// One line of `show` text output: `keys: jwks (N keys)` or `keys: jwks_uri <URL>`.
fn keys_line(keys: &ClientKeys) -> String {
    match keys {
        ClientKeys::Jwks(doc) => {
            let count = jwks_key_count(doc);
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

#[derive(Serialize)]
struct IssuerJson<'a> {
    id: &'a str,
    status: &'static str,
    allowed_clients: Vec<&'a str>,
    jwks: serde_json::Value,
    created_at: String,
    updated_at: String,
}

impl<'a> IssuerJson<'a> {
    fn new(view: &'a IssuerView) -> Self {
        Self {
            id: view.id.as_inner(),
            status: view.status.as_str(),
            allowed_clients: view
                .allowed_clients
                .iter()
                .map(|c| c.as_inner().as_str())
                .collect(),
            jwks: jwks_value(&view.jwks),
            created_at: rfc3339(view.created_at),
            updated_at: rfc3339(view.updated_at),
        }
    }
}

#[derive(Serialize)]
struct SubjectMappingJson<'a> {
    subject: &'a str,
    username: &'a str,
    user_id: String,
    updated_at: String,
}

impl<'a> SubjectMappingJson<'a> {
    fn new(view: &'a SubjectMappingView) -> Self {
        Self {
            subject: view.subject.as_inner(),
            username: view.username.as_str(),
            user_id: view.user_id.as_inner().hyphenated().to_string(),
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

/// Prints one issuer with all its fields (`create`, `show`, `update`).
pub fn print_issuer_details(format: OutputFormat, view: &IssuerView) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => println!("{}", to_json(&IssuerJson::new(view))?),
        OutputFormat::Text => {
            let clients: Vec<&str> = view
                .allowed_clients
                .iter()
                .map(|c| c.as_inner().as_str())
                .collect();
            println!("id: {}", view.id.as_inner());
            println!("status: {}", view.status.as_str());
            println!("clients: {}", clients.join(","));
            println!("keys: {}", jwks_key_count(&view.jwks));
            println!("created_at: {}", rfc3339(view.created_at));
            println!("updated_at: {}", rfc3339(view.updated_at));
        }
    }
    Ok(())
}

/// Prints a list of issuers: a JSON array, or one tab-separated line per issuer.
pub fn print_issuer_list(format: OutputFormat, views: &[IssuerView]) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => {
            let items: Vec<_> = views.iter().map(IssuerJson::new).collect();
            println!("{}", to_json(&items)?);
        }
        OutputFormat::Text => {
            for view in views {
                println!("{}\t{}", view.id.as_inner(), view.status.as_str());
            }
        }
    }
    Ok(())
}

/// Prints one subject mapping (`map-subject`).
pub fn print_subject_mapping(format: OutputFormat, view: &SubjectMappingView) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => println!("{}", to_json(&SubjectMappingJson::new(view))?),
        OutputFormat::Text => {
            println!("subject: {}", view.subject.as_inner());
            println!("username: {}", view.username.as_str());
            println!("user_id: {}", view.user_id.as_inner().hyphenated());
            println!("updated_at: {}", rfc3339(view.updated_at));
        }
    }
    Ok(())
}

/// Prints a list of subject mappings: a JSON array, or one tab-separated line per mapping.
pub fn print_subject_mapping_list(
    format: OutputFormat,
    views: &[SubjectMappingView],
) -> Result<(), Exit> {
    match format {
        OutputFormat::Json => {
            let items: Vec<_> = views.iter().map(SubjectMappingJson::new).collect();
            println!("{}", to_json(&items)?);
        }
        OutputFormat::Text => {
            for view in views {
                println!(
                    "{}\t{}\t{}\t{}",
                    view.subject.as_inner(),
                    view.username.as_str(),
                    view.user_id.as_inner().hyphenated(),
                    rfc3339(view.updated_at)
                );
            }
        }
    }
    Ok(())
}
