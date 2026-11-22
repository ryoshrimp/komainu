//! The komainu authorization server binary: configuration, wiring, listeners, admin CLI and
//! the periodic purge job. `main` only calls [`run`].

pub mod cleanup;
pub mod cli;
pub mod config;
pub mod ops;
pub mod serve;
pub mod telemetry;
pub mod wiring;

use std::fmt::Display;

use clap::Parser;
use komainu_adapter_postgres::{PgUnitOfWorkFactory, connect};

use crate::cli::{AdminCommand, Cli, Command};
use crate::wiring::Settings;

/// A failure that ends the process: exit code and a one-line message.
#[derive(Debug)]
pub struct Exit {
    code: i32,
    message: String,
}

impl Exit {
    pub fn new(code: i32, message: impl Display) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    /// Exit code 1: a runtime error.
    pub fn runtime(message: impl Display) -> Self {
        Self::new(1, message)
    }

    /// Exit code 2: wrong usage, configuration or input.
    pub fn usage(message: impl Display) -> Self {
        Self::new(2, message)
    }
}

/// Runs the command line and returns the process exit code.
pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            let _ = error.print();
            return code;
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the async runtime: {error}");
            return 1;
        }
    };
    match runtime.block_on(execute(cli)) {
        Ok(()) => 0,
        Err(exit) => {
            eprintln!("error: {}", exit.message);
            exit.code
        }
    }
}

async fn execute(cli: Cli) -> Result<(), Exit> {
    let Cli { config, command } = cli;
    let mut config = config::load(config.as_deref()).map_err(Exit::usage)?;
    // `validate` may log a warning, so `serve` sets up logging first.
    let metrics = match command {
        Command::Serve { .. } => Some(telemetry::init(&config.log).map_err(Exit::runtime)?),
        _ => None,
    };
    config::validate(&mut config).map_err(Exit::usage)?;
    let settings = Settings::from_config(config).map_err(Exit::usage)?;
    match command {
        Command::Serve { migrate } => {
            let metrics = metrics.expect("serve initializes telemetry");
            serve::run_serve(settings, migrate, metrics).await
        }
        Command::Migrate => serve::run_migrate(settings).await,
        Command::Client(command) => admin(settings, AdminCommand::Client(command)).await,
        Command::User(command) => admin(settings, AdminCommand::User(command)).await,
    }
}

async fn admin(settings: Settings, command: AdminCommand) -> Result<(), Exit> {
    let pool = connect(&settings.pg).await.map_err(Exit::runtime)?;
    let services = wiring::services(
        PgUnitOfWorkFactory::new(pool),
        settings.application,
        settings.http,
    )
    .map_err(Exit::runtime)?;
    cli::run_admin(&services.admin, command).await
}
