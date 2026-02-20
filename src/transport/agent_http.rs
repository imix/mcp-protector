//! Agent-side HTTP transport.
//!
//! Listens on a TCP port and accepts MCP agent connections over HTTP using
//! rmcp's `StreamableHttpService` mounted at `/mcp`.  Also exposes a
//! `GET /health` endpoint that returns 200 once the upstream handshake has
//! succeeded and 503 while the proxy is still starting up (FR21).
//!
//! All audit log output is written to stdout in HTTP mode (the MCP channel
//! is not on stdout here, so stdout is available for structured logs).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::response::IntoResponse;
use axum::routing::get;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio_util::sync::CancellationToken;

use crate::proxy::ProxyHandler;

/// Agent-side HTTP transport.
///
/// Binds an axum HTTP server on the configured port, mounts the MCP
/// `StreamableHttpService` at `/mcp`, and exposes `GET /health`.
pub(crate) struct AgentHttpTransport;

impl AgentHttpTransport {
    /// Run the HTTP agent transport.
    ///
    /// Binds to `0.0.0.0:<port>`, serves MCP over `/mcp`, exposes
    /// `GET /health`.  The `upstream_ready` flag must be set to `true` by the
    /// caller after the upstream handshake succeeds — the health endpoint
    /// returns 200 once the flag is set and 503 before that.
    ///
    /// Runs until `token` is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot be bound or if the HTTP
    /// server encounters an unrecoverable error.
    pub(crate) async fn run(
        handler_factory: impl Fn() -> anyhow::Result<ProxyHandler> + Send + Sync + 'static,
        port: u16,
        upstream_ready: Arc<AtomicBool>,
        token: CancellationToken,
    ) -> anyhow::Result<()> {
        let service: StreamableHttpService<ProxyHandler, LocalSessionManager> =
            StreamableHttpService::new(
                move || {
                    handler_factory()
                        .map_err(|e| std::io::Error::other(e.to_string()))
                },
                Arc::new(LocalSessionManager::default()),
                StreamableHttpServerConfig {
                    cancellation_token: token.child_token(),
                    ..StreamableHttpServerConfig::default()
                },
            );

        let app = Router::new()
            .nest_service("/mcp", service)
            .route("/health", get(health_handler))
            .with_state(upstream_ready);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind HTTP listener on port {port}"))?;

        tracing::info!(port, "HTTP agent listener bound");

        axum::serve(listener, app)
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await
            .context("HTTP server error")?;

        Ok(())
    }
}

/// Health check handler.
///
/// Returns 200 `{"status":"ok"}` once the upstream is ready, or 503
/// `{"status":"starting"}` while the handshake is still in progress.
async fn health_handler(
    axum::extract::State(upstream_ready): axum::extract::State<Arc<AtomicBool>>,
) -> impl IntoResponse {
    if upstream_ready.load(Ordering::Acquire) {
        (
            axum::http::StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"status":"ok"}"#,
        )
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "application/json")],
            r#"{"status":"starting"}"#,
        )
    }
}
