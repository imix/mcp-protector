//! Proxy core.
//!
//! Accepts agent connections, applies the policy engine, and forwards
//! permitted requests to the upstream MCP server.  Each agent connection
//! runs on its own tokio task; a single upstream connection is shared for the
//! lifetime of the proxy instance.
//!
//! # Supported transport combinations
//!
//! | Agent side | Upstream side | Status      |
//! |------------|---------------|-------------|
//! | stdio      | stdio         | Implemented |
//! | stdio      | HTTPS         | Implemented |
//! | HTTP       | stdio         | Implemented |
//! | HTTP       | HTTPS         | Implemented |

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorCode, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, ToolsCapability,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, Peer, RoleClient, RoleServer, ServerHandler};
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditSender, LogEntry, LogEvent, LOG_SCHEMA_VERSION};
use crate::config::{Config, ListenConfig, UpstreamAuth, UpstreamConfig};
use crate::transport::{agent_http, agent_stdio, upstream_https, upstream_stdio};
use crate::{audit, policy};

// ── ProxyHandler ──────────────────────────────────────────────────────────────

/// MCP server handler that enforces the tool allowlist policy and forwards
/// permitted requests to the upstream [`Peer<RoleClient>`].
///
/// `ProxyHandler` implements [`ServerHandler`], allowing it to be passed
/// directly to `rmcp::serve_server`.
///
/// `Clone` is derived so that `StreamableHttpService` (Story 3.1) can create
/// a fresh handler per HTTP session via the factory closure.  All fields are
/// cheap to clone: `Peer<RoleClient>` is `Arc`-backed, `AuditSender` wraps
/// an `mpsc::UnboundedSender` (which is `Clone`), and the `Arc` fields share
/// the underlying data.
#[derive(Clone)]
pub(crate) struct ProxyHandler {
    /// Client-side handle to the upstream MCP server.
    upstream_peer: Peer<RoleClient>,
    /// Sender for the audit log writer task.
    audit_tx: AuditSender,
    /// Tool names the policy allows.  Stored in an `Arc` so cloning the
    /// handler is cheap (the set is read-only after construction).
    allowlist: Arc<HashSet<String>>,
    /// Session identifier for all audit entries produced by this handler.
    session_id: String,
    /// Display name of the upstream server (used in audit log entries).
    upstream_name: String,
}

impl ProxyHandler {
    /// Construct a new handler.
    pub(crate) fn new(
        upstream_peer: Peer<RoleClient>,
        audit_tx: AuditSender,
        allowlist: Arc<HashSet<String>>,
        session_id: String,
        upstream_name: String,
    ) -> Self {
        Self {
            upstream_peer,
            audit_tx,
            allowlist,
            session_id,
            upstream_name,
        }
    }
}

impl ServerHandler for ProxyHandler {
    /// Return the proxy's server identity to the connecting agent.
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: rmcp::model::ProtocolVersion::default(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: None }),
                ..ServerCapabilities::default()
            },
            server_info: Implementation {
                name: "mcp-protector".to_owned(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                description: None,
                icons: None,
                website_url: None,
            },
            instructions: None,
        }
    }

    /// Forward `tools/list` to the upstream, filter by the allowlist, and emit
    /// an audit entry.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let upstream_tools = self
            .upstream_peer
            .list_all_tools()
            .await
            .map_err(|err| {
                tracing::warn!("upstream tools/list failed: {err}");
                ErrorData::internal_error(
                    format!("upstream tools/list error: {err}"),
                    None,
                )
            })?;

        let tools_upstream =
            u32::try_from(upstream_tools.len()).unwrap_or(u32::MAX);

        let filtered = policy::filter_tools_list(upstream_tools, &self.allowlist);

        let tools_returned =
            u32::try_from(filtered.len()).unwrap_or(u32::MAX);

        self.audit_tx.send(LogEntry {
            version: LOG_SCHEMA_VERSION,
            timestamp: chrono::Utc::now(),
            event: LogEvent::ToolsList {
                tools_upstream,
                tools_returned,
            },
            session_id: self.session_id.clone(),
            upstream: self.upstream_name.clone(),
        });

        Ok(ListToolsResult {
            tools: filtered,
            next_cursor: None,
            meta: None,
        })
    }

    /// Enforce the allowlist policy on `tools/call` requests.
    ///
    /// Allowed calls are forwarded to the upstream; blocked calls return an
    /// `ErrorCode::METHOD_NOT_FOUND` error per FR8 (fail-closed design).
    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name = params.name.as_ref().to_owned();
        let allowed = policy::is_tool_allowed(&tool_name, &self.allowlist);

        self.audit_tx.send(LogEntry {
            version: LOG_SCHEMA_VERSION,
            timestamp: chrono::Utc::now(),
            event: LogEvent::ToolCall {
                tool_name: tool_name.clone(),
                allowed,
            },
            session_id: self.session_id.clone(),
            upstream: self.upstream_name.clone(),
        });

        if allowed {
            self.upstream_peer
                .call_tool(params)
                .await
                .map_err(|err| {
                    tracing::warn!("upstream tools/call failed for '{tool_name}': {err}");
                    ErrorData::internal_error(
                        format!("upstream call_tool error: {err}"),
                        None,
                    )
                })
        } else {
            Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("tool '{tool_name}' is not in the allowed list"),
                None,
            ))
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Start the proxy with the given configuration.
///
/// Selects the appropriate transport combination, wires up the policy engine
/// and audit writer, and runs until the connection closes or `token` is
/// cancelled.
///
/// # Errors
///
/// Returns an error if the upstream connection fails or if the MCP handshake
/// with the agent fails.
pub(crate) async fn run(
    cfg: Config,
    audit_tx: AuditSender,
    token: CancellationToken,
) -> anyhow::Result<()> {
    match (cfg.listen, cfg.upstream) {
        (ListenConfig::Stdio, UpstreamConfig::Stdio { command }) => {
            run_stdio_to_stdio(command, cfg.policy.allow, audit_tx, token).await
        }
        (ListenConfig::Stdio, UpstreamConfig::Https { url, auth }) => {
            run_stdio_to_https(url, auth, cfg.policy.allow, audit_tx, token).await
        }
        (ListenConfig::Http { port }, UpstreamConfig::Stdio { command }) => {
            run_http_to_stdio(port, command, cfg.policy.allow, audit_tx, token).await
        }
        (ListenConfig::Http { port }, UpstreamConfig::Https { url, auth }) => {
            run_http_to_https(port, url, auth, cfg.policy.allow, audit_tx, token).await
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Run the stdio↔stdio transport combination.
///
/// Connects to the upstream subprocess, wraps it with the policy handler, and
/// serves the agent connected on stdin/stdout.
async fn run_stdio_to_stdio(
    command: Vec<String>,
    allowlist: HashSet<String>,
    audit_tx: AuditSender,
    token: CancellationToken,
) -> anyhow::Result<()> {
    // 1. Connect to the upstream MCP server subprocess.
    let (upstream_service, upstream_name) =
        upstream_stdio::UpstreamStdioTransport::connect(&command, token.child_token())
            .await
            .context("failed to connect to upstream MCP server")?;

    // 2. Clone the peer handle (cheap — Arc-backed).
    let upstream_peer = upstream_service.peer().clone();

    // 3. Generate a unique session identifier for audit entries.
    let session_id = audit::next_session_id();

    // 4. Build the proxy handler.
    let handler = ProxyHandler::new(
        upstream_peer,
        audit_tx,
        Arc::new(allowlist),
        session_id,
        upstream_name,
    );

    tracing::info!("mcp-protector started — transport: stdio, upstream: stdio");

    // 5. Serve the agent connected on stdin/stdout.
    agent_stdio::AgentStdioTransport::run(handler, token.child_token())
        .await
        .context("agent stdio transport error")?;

    // 6. Cancel the upstream service and wait for cleanup.
    upstream_service
        .cancel()
        .await
        .context("error waiting for upstream service to stop")?;

    Ok(())
}

/// Run the stdio↔HTTPS transport combination.
///
/// Connects to the remote upstream MCP server over HTTPS, then serves the
/// agent on stdin/stdout.
async fn run_stdio_to_https(
    url: String,
    auth: Option<UpstreamAuth>,
    allowlist: HashSet<String>,
    audit_tx: AuditSender,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let (upstream_service, upstream_name) =
        upstream_https::UpstreamHttpsTransport::connect(&url, auth, token.child_token())
            .await
            .context("failed to connect to upstream MCP server")?;

    let upstream_peer = upstream_service.peer().clone();
    let session_id = audit::next_session_id();
    let handler = ProxyHandler::new(
        upstream_peer,
        audit_tx,
        Arc::new(allowlist),
        session_id,
        upstream_name,
    );

    tracing::info!("mcp-protector started — transport: stdio, upstream: https");

    agent_stdio::AgentStdioTransport::run(handler, token.child_token())
        .await
        .context("agent stdio transport error")?;

    upstream_service
        .cancel()
        .await
        .context("error waiting for upstream service to stop")?;

    Ok(())
}

/// Run the HTTP↔stdio transport combination.
///
/// Starts the HTTP agent listener first (so the `/health` endpoint is
/// available immediately) and then connects to the upstream subprocess
/// concurrently.  The `upstream_ready` flag is set to `true` once the MCP
/// handshake with the upstream subprocess completes, at which point
/// `/health` starts returning 200.
///
/// A fresh [`ProxyHandler`] is created per HTTP session via the factory
/// closure; all sessions share the single upstream subprocess connection.
async fn run_http_to_stdio(
    port: u16,
    command: Vec<String>,
    allowlist: HashSet<String>,
    audit_tx: AuditSender,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let upstream_ready = Arc::new(AtomicBool::new(false));

    // Deferred state that the factory closure will populate once upstream
    // connects.  We use a `tokio::sync::oneshot` to hand the peer from the
    // upstream task to the HTTP layer once the handshake succeeds.
    let (peer_tx, peer_rx) =
        tokio::sync::watch::channel::<Option<(rmcp::Peer<RoleClient>, String)>>(None);

    // 1. Spawn the upstream connection task.  When it succeeds it stores the
    //    peer into the watch channel and marks `upstream_ready`.
    {
        let command = command.clone();
        let upstream_ready = Arc::clone(&upstream_ready);
        let token = token.child_token();
        tokio::spawn(async move {
            match upstream_stdio::UpstreamStdioTransport::connect(&command, token.child_token())
                .await
            {
                Ok((service, name)) => {
                    let peer = service.peer().clone();
                    // Ignore send error — the HTTP task may have already exited.
                    let _ = peer_tx.send(Some((peer, name)));
                    upstream_ready.store(true, Ordering::Release);
                    // Keep `service` alive until cancellation.
                    () = token.cancelled().await;
                    let _ = service.cancel().await;
                }
                Err(err) => {
                    tracing::error!("failed to connect to upstream MCP server: {err}");
                    // Signal that upstream will never become ready so the
                    // health endpoint keeps returning 503 until the process
                    // exits via the cancellation token.
                    token.cancel();
                }
            }
        });
    }

    let allowlist = Arc::new(allowlist);
    let factory = {
        let audit_tx = audit_tx.clone();
        let allowlist = Arc::clone(&allowlist);
        move || {
            // Block until the upstream peer is available.
            let guard = peer_rx.borrow();
            match guard.as_ref() {
                Some((peer, name)) => Ok(ProxyHandler::new(
                    peer.clone(),
                    audit_tx.clone(),
                    Arc::clone(&allowlist),
                    audit::next_session_id(),
                    name.clone(),
                )),
                None => Err(anyhow::anyhow!("upstream not yet connected")),
            }
        }
    };

    tracing::info!(port, "mcp-protector started — transport: http, upstream: stdio");

    agent_http::AgentHttpTransport::run(factory, port, Arc::clone(&upstream_ready), token.child_token())
        .await
        .context("HTTP agent transport error")?;

    Ok(())
}

/// Run the HTTP↔HTTPS transport combination.
///
/// Starts the HTTP agent listener first (so the `/health` endpoint is
/// available immediately) and then connects to the upstream HTTPS server
/// concurrently.  The `upstream_ready` flag is set to `true` once the MCP
/// handshake with the upstream server completes, at which point `/health`
/// starts returning 200.
///
/// A fresh [`ProxyHandler`] is created per HTTP session.
async fn run_http_to_https(
    port: u16,
    url: String,
    auth: Option<UpstreamAuth>,
    allowlist: HashSet<String>,
    audit_tx: AuditSender,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let upstream_ready = Arc::new(AtomicBool::new(false));

    let (peer_tx, peer_rx) =
        tokio::sync::watch::channel::<Option<(rmcp::Peer<RoleClient>, String)>>(None);

    // 1. Spawn the upstream connection task.
    {
        let upstream_ready = Arc::clone(&upstream_ready);
        let token = token.child_token();
        tokio::spawn(async move {
            match upstream_https::UpstreamHttpsTransport::connect(&url, auth, token.child_token())
                .await
            {
                Ok((service, name)) => {
                    let peer = service.peer().clone();
                    let _ = peer_tx.send(Some((peer, name)));
                    upstream_ready.store(true, Ordering::Release);
                    () = token.cancelled().await;
                    let _ = service.cancel().await;
                }
                Err(err) => {
                    tracing::error!("failed to connect to upstream MCP server: {err}");
                    token.cancel();
                }
            }
        });
    }

    let allowlist = Arc::new(allowlist);
    let factory = {
        let audit_tx = audit_tx.clone();
        let allowlist = Arc::clone(&allowlist);
        move || {
            let guard = peer_rx.borrow();
            match guard.as_ref() {
                Some((peer, name)) => Ok(ProxyHandler::new(
                    peer.clone(),
                    audit_tx.clone(),
                    Arc::clone(&allowlist),
                    audit::next_session_id(),
                    name.clone(),
                )),
                None => Err(anyhow::anyhow!("upstream not yet connected")),
            }
        }
    };

    tracing::info!(port, "mcp-protector started — transport: http, upstream: https");

    agent_http::AgentHttpTransport::run(factory, port, Arc::clone(&upstream_ready), token.child_token())
        .await
        .context("HTTP agent transport error")?;

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Compile-time test: if proxy.rs compiles with an exhaustive match in
    // run(), then all four transport combinations are handled.  No runtime
    // assertions are needed here — the match arm exhaustiveness is enforced
    // by the Rust compiler.
    #[test]
    fn all_transport_combinations_are_handled() {
        // This test is intentionally empty.  Its purpose is to document that
        // the exhaustive match in run() covers all (ListenConfig, UpstreamConfig)
        // combinations; if a new variant were added to either enum without
        // updating run(), this file would fail to compile.
    }
}
