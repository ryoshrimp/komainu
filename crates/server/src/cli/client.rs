//! `komainu client ...`

use std::collections::BTreeSet;

use clap::{Args, Subcommand};
use komainu::application::{AdminService, ListPage, RegisterClient};
use komainu::domain::{
    ClientId, ClientName, ClientType, ClientUpdate, GrantType, RedirectUri, ScopeSet,
    TokenEndpointAuthMethod,
};

use super::admin_exit;
use super::output::{self, OutputFormat};
use crate::Exit;
use crate::wiring::background_context;

const CLIENT_TYPES: [&str; 2] = ["confidential", "public"];
const AUTH_METHODS: [&str; 3] = ["client_secret_basic", "client_secret_post", "none"];
const GRANT_TYPES: [&str; 3] = ["authorization_code", "client_credentials", "refresh_token"];

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Register a client. The secret is shown once.
    Create(CreateArgs),
    /// List clients ordered by client id.
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, value_name = "CLIENT_ID")]
        after: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Show a client.
    Show {
        client_id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Change a client. A list option replaces the whole list; omitted items stay as they are.
    Update(UpdateArgs),
    /// Replace the secret of a confidential client. The new secret is shown once.
    RotateSecret {
        client_id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Disable a client and revoke its tokens.
    Disable { client_id: String },
    /// Enable a client.
    Enable { client_id: String },
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(long)]
    name: String,
    #[arg(long = "type", value_parser = CLIENT_TYPES, default_value = "confidential")]
    client_type: String,
    /// Default: client_secret_basic for confidential clients, none for public clients.
    #[arg(long, value_parser = AUTH_METHODS)]
    auth_method: Option<String>,
    #[arg(long = "redirect-uri", value_name = "URI")]
    redirect_uris: Vec<String>,
    /// Default: authorization_code.
    #[arg(long = "grant-type", value_parser = GRANT_TYPES)]
    grant_types: Vec<String>,
    /// Allowed scopes, space separated.
    #[arg(long, value_name = "SCOPES")]
    scope: Option<String>,
    /// Scopes granted when a request names none, space separated.
    #[arg(long, value_name = "SCOPES")]
    default_scope: Option<String>,
    #[arg(long)]
    skip_consent: bool,
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    client_id: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(
        long = "redirect-uri",
        value_name = "URI",
        conflicts_with = "clear_redirect_uris"
    )]
    redirect_uris: Vec<String>,
    /// Remove all redirect URIs.
    #[arg(long)]
    clear_redirect_uris: bool,
    #[arg(long = "grant-type", value_parser = GRANT_TYPES)]
    grant_types: Vec<String>,
    #[arg(long, value_name = "SCOPES")]
    scope: Option<String>,
    #[arg(long, value_name = "SCOPES")]
    default_scope: Option<String>,
    #[arg(long, value_name = "true|false")]
    skip_consent: Option<bool>,
    #[arg(long, value_parser = AUTH_METHODS)]
    auth_method: Option<String>,
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
}

fn parse<T: std::str::FromStr<Err = komainu::domain::DomainError>>(value: &str) -> Result<T, Exit> {
    value.parse().map_err(Exit::usage)
}

fn client_id(value: &str) -> Result<ClientId, Exit> {
    ClientId::try_new(value.to_owned()).map_err(Exit::usage)
}

/// Space separated scopes; an empty string is the empty set.
fn scopes(value: &str) -> Result<ScopeSet, Exit> {
    if value.is_empty() {
        Ok(ScopeSet::empty())
    } else {
        ScopeSet::parse(value).map_err(Exit::usage)
    }
}

fn redirect_uris(values: &[String]) -> Result<Vec<RedirectUri>, Exit> {
    values
        .iter()
        .map(|value| RedirectUri::try_new(value.clone()).map_err(Exit::usage))
        .collect()
}

fn grant_types(values: &[String]) -> Result<BTreeSet<GrantType>, Exit> {
    values.iter().map(|value| parse(value)).collect()
}

pub async fn run(admin: &AdminService, command: ClientCommand) -> Result<(), Exit> {
    let ctx = background_context();
    match command {
        ClientCommand::Create(args) => {
            let client_type: ClientType = parse(&args.client_type)?;
            let auth_method = match &args.auth_method {
                Some(value) => parse(value)?,
                None => match client_type {
                    ClientType::Confidential => TokenEndpointAuthMethod::ClientSecretBasic,
                    ClientType::Public => TokenEndpointAuthMethod::None,
                },
            };
            let grant_types = if args.grant_types.is_empty() {
                BTreeSet::from([GrantType::AuthorizationCode])
            } else {
                grant_types(&args.grant_types)?
            };
            let input = RegisterClient {
                name: ClientName::try_new(args.name).map_err(Exit::usage)?,
                client_type,
                auth_method,
                redirect_uris: redirect_uris(&args.redirect_uris)?,
                grant_types,
                allowed_scopes: scopes(args.scope.as_deref().unwrap_or(""))?,
                default_scopes: scopes(args.default_scope.as_deref().unwrap_or(""))?,
                skip_consent: args.skip_consent,
            };
            let registered = admin
                .register_client(&ctx, input)
                .await
                .map_err(admin_exit)?;
            output::print_client(args.output, &registered.client, registered.secret.as_ref())
        }
        ClientCommand::List {
            limit,
            after,
            output: format,
        } => {
            let after = after.as_deref().map(client_id).transpose()?;
            let views = admin
                .list_clients(&ctx, ListPage { after, limit })
                .await
                .map_err(admin_exit)?;
            output::print_client_list(format, &views)
        }
        ClientCommand::Show {
            client_id: id,
            output: format,
        } => {
            let view = admin
                .get_client(&ctx, &client_id(&id)?)
                .await
                .map_err(admin_exit)?;
            output::print_client_details(format, &view)
        }
        ClientCommand::Update(args) => {
            let id = client_id(&args.client_id)?;
            let update = ClientUpdate {
                name: args
                    .name
                    .map(|name| ClientName::try_new(name).map_err(Exit::usage))
                    .transpose()?,
                redirect_uris: if args.clear_redirect_uris {
                    Some(Vec::new())
                } else if args.redirect_uris.is_empty() {
                    None
                } else {
                    Some(redirect_uris(&args.redirect_uris)?)
                },
                grant_types: if args.grant_types.is_empty() {
                    None
                } else {
                    Some(grant_types(&args.grant_types)?)
                },
                allowed_scopes: args.scope.as_deref().map(scopes).transpose()?,
                default_scopes: args.default_scope.as_deref().map(scopes).transpose()?,
                skip_consent: args.skip_consent,
                auth_method: args.auth_method.as_deref().map(parse).transpose()?,
            };
            let view = admin
                .update_client(&ctx, &id, update)
                .await
                .map_err(admin_exit)?;
            output::print_client_details(args.output, &view)
        }
        ClientCommand::RotateSecret {
            client_id: id,
            output: format,
        } => {
            let id = client_id(&id)?;
            let secret = admin
                .rotate_client_secret(&ctx, &id)
                .await
                .map_err(admin_exit)?;
            let view = admin.get_client(&ctx, &id).await.map_err(admin_exit)?;
            output::print_rotated(format, &view, &secret)
        }
        ClientCommand::Disable { client_id: id } => admin
            .disable_client(&ctx, &client_id(&id)?)
            .await
            .map(drop)
            .map_err(admin_exit),
        ClientCommand::Enable { client_id: id } => admin
            .enable_client(&ctx, &client_id(&id)?)
            .await
            .map(drop)
            .map_err(admin_exit),
    }
}
