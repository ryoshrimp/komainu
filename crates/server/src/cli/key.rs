//! `komainu key ...`

use clap::Subcommand;
use komainu::domain::KeyStatus;
use komainu::{SigningAlgorithm, SigningKeyError, SigningKeyService, SigningKeySummary};
use serde_json::json;

use super::output::{OutputFormat, rfc3339, to_json};
use crate::Exit;
use crate::wiring::background_context;

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// List the signing keys.
    List {
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    /// Rotate one algorithm now: the current keys retire and a new one is active at once.
    Rotate {
        #[arg(long = "alg", value_name = "ALG")]
        alg: String,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    /// Delete a key. A replacement is made active if the algorithm would have none.
    Revoke {
        kid: String,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    /// Print a new key encryption key (needs no configuration or database).
    GenerateEncryptionKey,
}

fn key_exit(error: SigningKeyError) -> Exit {
    match error {
        SigningKeyError::AlgorithmNotEnabled(_) => Exit::usage(error),
        SigningKeyError::NotFound => Exit::new(3, error),
        error => Exit::runtime(error),
    }
}

fn status(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Pending => "pending",
        KeyStatus::Active => "active",
        KeyStatus::Retired => "retired",
        KeyStatus::Expired => "expired",
    }
}

fn line(key: &SigningKeySummary) -> String {
    format!(
        "{}  {}  {}  activates={}  retires={}  deletes={}",
        key.kid.as_inner(),
        key.algorithm.as_str(),
        status(key.status),
        rfc3339(key.activates_at),
        rfc3339(key.retires_at),
        rfc3339(key.deletes_at),
    )
}

fn value(key: &SigningKeySummary) -> serde_json::Value {
    json!({
        "kid": key.kid.as_inner(),
        "algorithm": key.algorithm.as_str(),
        "status": status(key.status),
        "created_at": rfc3339(key.created_at),
        "activates_at": rfc3339(key.activates_at),
        "retires_at": rfc3339(key.retires_at),
        "deletes_at": rfc3339(key.deletes_at),
    })
}

/// Runs a key command other than `generate-encryption-key`, which `execute` handles earlier.
pub(crate) async fn run(service: &SigningKeyService, command: KeyCommand) -> Result<(), Exit> {
    let ctx = background_context();
    match command {
        KeyCommand::List { format } => {
            let keys = service.list().await.map_err(key_exit)?;
            match format {
                OutputFormat::Text => keys.iter().for_each(|k| println!("{}", line(k))),
                OutputFormat::Json => println_json(&keys.iter().map(value).collect())?,
            }
        }
        KeyCommand::Rotate { alg, format } => {
            let algorithm = alg.parse::<SigningAlgorithm>().map_err(Exit::usage)?;
            let key = service
                .rotate_now(&ctx, algorithm)
                .await
                .map_err(key_exit)?;
            match format {
                OutputFormat::Text => println!("{}", line(&key)),
                OutputFormat::Json => println_json(&value(&key))?,
            }
        }
        KeyCommand::Revoke { kid, format } => {
            let kid = komainu::domain::SigningKeyId::try_new(kid).map_err(Exit::usage)?;
            let outcome = service.revoke(&ctx, &kid).await.map_err(key_exit)?;
            match format {
                OutputFormat::Text => {
                    println!("revoked {}", outcome.revoked.as_inner());
                    if let Some(key) = &outcome.replacement {
                        println!("replacement {}", line(key));
                    }
                }
                OutputFormat::Json => println_json(&json!({
                    "revoked": outcome.revoked.as_inner(),
                    "replacement": outcome.replacement.as_ref().map(value),
                }))?,
            }
        }
        KeyCommand::GenerateEncryptionKey => unreachable!("handled before the configuration"),
    }
    Ok(())
}

fn println_json(value: &serde_json::Value) -> Result<(), Exit> {
    println!("{}", to_json(value)?);
    Ok(())
}
