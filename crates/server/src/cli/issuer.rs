//! `komainu issuer ...`

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use komainu::application::{AdminService, ListPage, RegisterIssuer};
use komainu::domain::{
    ClientId, ExternalSubject, IssuerId, JwksDocument, TrustedIssuerUpdate, Username,
};

use super::admin_exit;
use super::output::{self, OutputFormat};
use crate::Exit;
use crate::wiring::background_context;

#[derive(Debug, Subcommand)]
pub enum IssuerCommand {
    /// Register a trusted issuer.
    Create(CreateArgs),
    /// List issuers ordered by issuer id.
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, value_name = "ID")]
        after: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Show an issuer.
    Show {
        id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Change an issuer. `--client` replaces the whole list of allowed clients.
    Update(UpdateArgs),
    /// Disable an issuer: its assertions are rejected.
    Disable { id: String },
    /// Enable an issuer.
    Enable { id: String },
    /// Map a subject of the issuer to a user. An existing mapping is overwritten.
    MapSubject {
        id: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        username: String,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Remove the mapping of a subject.
    UnmapSubject {
        id: String,
        #[arg(long)]
        subject: String,
    },
    /// List the subject mappings of an issuer.
    ListSubjects {
        id: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, value_name = "SUBJECT")]
        after: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// The `iss` of the assertions, e.g. https://idp.example.com.
    #[arg(long = "issuer", value_name = "ID")]
    id: String,
    /// JWK Set file with the issuer's public keys.
    #[arg(long, value_name = "PATH")]
    jwks_file: PathBuf,
    /// A client allowed to use the issuer's assertions (1 to 100).
    #[arg(long = "client", value_name = "CLIENT_ID", required = true)]
    clients: Vec<String>,
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
pub struct UpdateKeys {
    /// JWK Set file with the issuer's public keys.
    #[arg(long, value_name = "PATH")]
    jwks_file: Option<PathBuf>,
    /// A client allowed to use the issuer's assertions. Replaces the whole list.
    #[arg(long = "client", value_name = "CLIENT_ID")]
    clients: Vec<String>,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    id: String,
    #[command(flatten)]
    changes: UpdateKeys,
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
}

fn issuer_id(value: &str) -> Result<IssuerId, Exit> {
    IssuerId::try_new(value.to_owned()).map_err(Exit::usage)
}

fn subject(value: &str) -> Result<ExternalSubject, Exit> {
    ExternalSubject::try_new(value.to_owned()).map_err(Exit::usage)
}

/// A file is read here; whether it is a usable JWK Set is checked by the use case.
fn jwks(path: &PathBuf) -> Result<JwksDocument, Exit> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Exit::new(2, format!("cannot read {}: {e}", path.display())))?;
    JwksDocument::try_new(text).map_err(Exit::usage)
}

fn clients(values: &[String]) -> Result<BTreeSet<ClientId>, Exit> {
    values
        .iter()
        .map(|value| ClientId::try_new(value.clone()).map_err(Exit::usage))
        .collect()
}

pub async fn run(admin: &AdminService, command: IssuerCommand) -> Result<(), Exit> {
    let ctx = background_context();
    match command {
        IssuerCommand::Create(args) => {
            let input = RegisterIssuer {
                id: issuer_id(&args.id)?,
                jwks: jwks(&args.jwks_file)?,
                allowed_clients: clients(&args.clients)?,
            };
            let view = admin
                .register_issuer(&ctx, input)
                .await
                .map_err(admin_exit)?;
            output::print_issuer_details(args.output, &view)
        }
        IssuerCommand::List {
            limit,
            after,
            output: format,
        } => {
            let after = after.as_deref().map(issuer_id).transpose()?;
            let views = admin
                .list_issuers(&ctx, ListPage { after, limit })
                .await
                .map_err(admin_exit)?;
            output::print_issuer_list(format, &views)
        }
        IssuerCommand::Show { id, output: format } => {
            let view = admin
                .get_issuer(&ctx, &issuer_id(&id)?)
                .await
                .map_err(admin_exit)?;
            output::print_issuer_details(format, &view)
        }
        IssuerCommand::Update(args) => {
            let update = TrustedIssuerUpdate {
                jwks: args.changes.jwks_file.as_ref().map(jwks).transpose()?,
                allowed_clients: if args.changes.clients.is_empty() {
                    None
                } else {
                    Some(clients(&args.changes.clients)?)
                },
            };
            let view = admin
                .update_issuer(&ctx, &issuer_id(&args.id)?, update)
                .await
                .map_err(admin_exit)?;
            output::print_issuer_details(args.output, &view)
        }
        IssuerCommand::Disable { id } => admin
            .disable_issuer(&ctx, &issuer_id(&id)?)
            .await
            .map(drop)
            .map_err(admin_exit),
        IssuerCommand::Enable { id } => admin
            .enable_issuer(&ctx, &issuer_id(&id)?)
            .await
            .map(drop)
            .map_err(admin_exit),
        IssuerCommand::MapSubject {
            id,
            subject: sub,
            username,
            output: format,
        } => {
            let username = Username::try_new(username).map_err(Exit::usage)?;
            let view = admin
                .map_subject(&ctx, &issuer_id(&id)?, subject(&sub)?, &username)
                .await
                .map_err(admin_exit)?;
            output::print_subject_mapping(format, &view)
        }
        IssuerCommand::UnmapSubject { id, subject: sub } => admin
            .unmap_subject(&ctx, &issuer_id(&id)?, &subject(&sub)?)
            .await
            .map_err(admin_exit),
        IssuerCommand::ListSubjects {
            id,
            limit,
            after,
            output: format,
        } => {
            let after = after.as_deref().map(subject).transpose()?;
            let views = admin
                .list_subject_mappings(&ctx, &issuer_id(&id)?, ListPage { after, limit })
                .await
                .map_err(admin_exit)?;
            output::print_subject_mapping_list(format, &views)
        }
    }
}
