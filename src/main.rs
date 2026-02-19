//! mcp-protector — security proxy for the Model Context Protocol.
//!
//! # Usage
//!
//! ```text
//! mcp-protector proxy --config config/my-config.toml
//! mcp-protector validate-config --config config/my-config.toml
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    ValidateConfig {
        /// Path to the TOML configuration file to validate.
        #[arg(short, long)]
        config: PathBuf,
    },
}

// `main` returns `Result<()>` per Decision 7 (anyhow for fatal errors).
// The stub body has no fallible calls yet, but the return type is the
// permanent architectural contract and must not be removed.
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
            // Stub — proxy runtime initialised in Story 1.2
        }
        Command::ValidateConfig { config } => {
            tracing::info!(config = %config.display(), "validating config");
            // Stub — config validation implemented in Story 1.2
        }
    }

    Ok(())
}
