//! Command line: argument definitions and the dispatch of the admin commands.

mod client;
mod issuer;
mod output;
mod user;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use komainu::application::{AdminError, AdminService};

use crate::Exit;

/// komainu OAuth 2.0 authorization server.
#[derive(Debug, Parser)]
#[command(name = "komainu", version)]
pub struct Cli {
    /// Path of the TOML configuration file (default: ./komainu.toml when present).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the authorization server.
    Serve {
        /// Apply the database migrations before starting.
        #[arg(long)]
        migrate: bool,
    },
    /// Apply the database migrations.
    Migrate,
    /// Manage clients.
    #[command(subcommand)]
    Client(client::ClientCommand),
    /// Manage users of the built-in user store.
    #[command(subcommand)]
    User(user::UserCommand),
    /// Manage trusted external assertion issuers.
    #[command(subcommand)]
    Issuer(issuer::IssuerCommand),
}

/// An administration command, i.e. everything except `serve` and `migrate`.
#[derive(Debug)]
pub enum AdminCommand {
    Client(client::ClientCommand),
    User(user::UserCommand),
    Issuer(issuer::IssuerCommand),
}

/// Runs an administration command against `admin`.
pub(crate) async fn run_admin(admin: &AdminService, command: AdminCommand) -> Result<(), Exit> {
    match command {
        AdminCommand::Client(command) => client::run(admin, command).await,
        AdminCommand::User(command) => user::run(admin, command).await,
        AdminCommand::Issuer(command) => issuer::run(admin, command).await,
    }
}

/// Maps a use-case error onto the exit code table of server.md.
fn admin_exit(error: AdminError) -> Exit {
    match error {
        AdminError::Invalid(error) => Exit::usage(error),
        error @ (AdminError::UnknownScope(_)
        | AdminError::PublicClientsDisabled
        | AdminError::InvalidJwks(_)
        | AdminError::UnknownClient(_)) => Exit::usage(error),
        AdminError::NotFound => Exit::new(3, "not found"),
        AdminError::Conflict => Exit::new(4, "already exists"),
        error @ (AdminError::PasswordHash(_) | AdminError::Store(_)) => Exit::runtime(error),
    }
}
