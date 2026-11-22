//! `komainu user ...`

use std::io::BufRead;

use clap::Subcommand;
use komainu_application::{AdminService, ListPage};
use komainu_domain::{NewPassword, Secret, Username};

use super::admin_exit;
use super::output::{self, OutputFormat};
use crate::Exit;
use crate::wiring::background_context;

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a user. The password is the first line of standard input.
    Create { username: String },
    /// Change a password. The password is the first line of standard input.
    SetPassword { username: String },
    /// List users ordered by username.
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, value_name = "USERNAME")]
        after: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Show a user.
    Show {
        username: String,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Disable a user.
    Disable { username: String },
    /// Enable a user.
    Enable { username: String },
}

fn username(value: &str) -> Result<Username, Exit> {
    Username::try_new(value.to_owned()).map_err(Exit::usage)
}

/// First line of standard input without its line ending.
fn read_password() -> Result<NewPassword, Exit> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Exit::usage(format!("cannot read the password from standard input: {e}")))?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    NewPassword::try_new(Secret::new(line.to_owned())).map_err(Exit::usage)
}

pub async fn run(admin: &AdminService, command: UserCommand) -> Result<(), Exit> {
    let ctx = background_context();
    match command {
        UserCommand::Create { username: name } => {
            let name = username(&name)?;
            let password = read_password()?;
            admin
                .create_user(&ctx, name, password)
                .await
                .map(drop)
                .map_err(admin_exit)
        }
        UserCommand::SetPassword { username: name } => {
            let name = username(&name)?;
            let password = read_password()?;
            admin
                .set_user_password(&ctx, &name, password)
                .await
                .map(drop)
                .map_err(admin_exit)
        }
        UserCommand::List {
            limit,
            after,
            output: format,
        } => {
            let after = after.as_deref().map(username).transpose()?;
            let views = admin
                .list_users(&ctx, ListPage { after, limit })
                .await
                .map_err(admin_exit)?;
            output::print_user_list(format, &views)
        }
        UserCommand::Show {
            username: name,
            output: format,
        } => {
            let view = admin
                .get_user(&ctx, &username(&name)?)
                .await
                .map_err(admin_exit)?;
            output::print_user_details(format, &view)
        }
        UserCommand::Disable { username: name } => admin
            .disable_user(&ctx, &username(&name)?)
            .await
            .map(drop)
            .map_err(admin_exit),
        UserCommand::Enable { username: name } => admin
            .enable_user(&ctx, &username(&name)?)
            .await
            .map(drop)
            .map_err(admin_exit),
    }
}
