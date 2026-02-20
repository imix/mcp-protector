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

#[tokio::main]
async fn main() -> Result<()> {
    // Route all tracing diagnostics to stderr explicitly.  In stdio transport
    // mode stdout is the MCP protocol channel, so nothing must be written to
    // stdout by our logging infrastructure.
    // Honour RUST_LOG when set; default to "info" level otherwise.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Proxy { config } => {
            tracing::info!(config = %config.display(), "starting proxy");
            let cfg = match config::load(&config) {
                Ok(cfg) => cfg,
                Err(errors) => {
                    for error in &errors {
                        eprintln!("Error: {error}");
                    }
                    process::exit(1);
                }
            };

            // Audit log goes to stderr when the agent side is stdio (stdout is
            // the MCP channel in that mode).
            let audit_to_stderr = matches!(cfg.listen, config::ListenConfig::Stdio);

            // Set up graceful shutdown.
            let token = shutdown::create_token();
            shutdown::install_handlers(token.clone());

            // Start the audit writer task.
            let (audit_tx, audit_handle) =
                audit::start_writer(token.child_token(), audit_to_stderr);

            // Run the proxy; on error log and exit with code 2.
            if let Err(e) = proxy::run(cfg, audit_tx, token).await {
                tracing::error!("proxy runtime error: {e}");
                // Wait for audit flush before exiting.
                let _ = audit_handle.await;
                process::exit(2);
            }

            // Wait for the audit writer to flush all remaining entries.
            let _ = audit_handle.await;
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
