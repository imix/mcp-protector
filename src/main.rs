//! mcp-protector — security proxy for the Model Context Protocol.
//!
//! # Usage
//!
//! ```text
//! mcp-protector proxy --config config/my-config.toml
//! mcp-protector validate-config --config config/my-config.toml
//! ```

use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod audit;
mod config;
mod policy;
mod proxy;
mod shutdown;
mod transport;

/// Security proxy for the Model Context Protocol.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Start the proxy, forwarding MCP traffic through the configured policy.
    Proxy {
        /// Path to the TOML configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Validate a configuration file and exit without starting the proxy.
    ///
    /// Exits 0 and prints "Config is valid." to stderr if the config is valid.
    /// Exits 1 and prints all field-level errors to stderr if it is not.
    ValidateConfig {
        /// Path to the TOML configuration file to validate.
        #[arg(short, long)]
        config: PathBuf,
    },
}

// `main` returns `Result<()>` per Architecture Decision 7 (anyhow for fatal
// errors at the top level).  The proxy subcommand will use `?` once the proxy
// runtime is wired in Story 2.x; the return type is a permanent architectural
// contract and must not be removed simply because no `?` is used yet.
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    // tracing_subscriber must be initialised as the very first statement so
    // that all startup diagnostics, including argument parsing errors, are
    // captured through the structured logging pipeline.
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Proxy { config } => {
            tracing::info!(config = %config.display(), "starting proxy");
            match config::load(&config) {
                Ok(_cfg) => {
                    // Stub — proxy runtime wired in Story 2.x
                }
                Err(errors) => {
                    for error in &errors {
                        eprintln!("Error: {error}");
                    }
                    process::exit(1);
                }
            }
        }
        Command::ValidateConfig { config } => {
            tracing::info!(config = %config.display(), "validating config");
            match config::load(&config) {
                Ok(_) => {
                    eprintln!("Config is valid.");
                }
                Err(errors) => {
                    for error in &errors {
                        eprintln!("Error: {error}");
                    }
                    process::exit(1);
                }
            }
        }
    }

    Ok(())
}
