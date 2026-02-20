//! Agent-side stdio transport.
//!
//! Accepts a single MCP agent connection over the process's stdin/stdout
//! streams.  Used when the proxy itself is invoked as a subprocess by an AI
//! agent (the most common deployment for local development).
//!
//! **Important**: in stdio mode, `stdout` is the MCP protocol channel.
//! Nothing other than MCP JSON-RPC messages must be written to `stdout`.
//! Tracing diagnostics and the audit log must both go to `stderr`.

use anyhow::Context as _;
use rmcp::service::serve_server_with_ct;
use tokio_util::sync::CancellationToken;

use crate::proxy::ProxyHandler;

/// Agent-side stdio transport.
///
/// Bridges the AI agent (connected via this process's stdin/stdout) with the
/// [`ProxyHandler`] that enforces the tool allowlist policy.
pub(crate) struct AgentStdioTransport;

impl AgentStdioTransport {
    /// Accept an MCP agent connection on `stdin`/`stdout` and serve it using
    /// `handler` until the connection closes or `token` is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the MCP handshake fails or if the underlying I/O
    /// transport reports an unrecoverable error.
    pub(crate) async fn run(
        handler: ProxyHandler,
        token: CancellationToken,
    ) -> anyhow::Result<()> {
        let transport = (tokio::io::stdin(), tokio::io::stdout());

        // `serve_server_with_ct` is not re-exported via `rmcp::` at the top
        // level; it lives in `rmcp::service`.
        let service = serve_server_with_ct(handler, transport, token)
            .await
            .context("MCP server handshake with agent failed")?;

        // Wait for the agent connection to close or be cancelled.
        service
            .waiting()
            .await
            .context("agent stdio service task failed")?;

        Ok(())
    }
}
