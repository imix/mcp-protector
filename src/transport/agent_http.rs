//! Agent-side HTTP transport.
//!
//! Listens on a TCP port and accepts MCP agent connections over HTTP using
//! rmcp's `StreamableHttpService` mounted at `/mcp`.  Also exposes a
//! `GET /health` endpoint that returns 200 once the upstream handshake has
//! succeeded and 503 while the proxy is still starting up (FR21).
//!
//! When `[listen.auth]` is configured, an axum Tower middleware layer is
//! inserted *between* the TCP listener and the MCP service.  Every request to
//! `/mcp` must pass the auth check; `GET /health` is intentionally outside the
//! auth layer so that container readiness probes work without credentials.
//!
//! All audit log output is written to stdout in HTTP mode (the MCP channel
//! is not on stdout here, so stdout is available for structured logs).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ipnet::IpNet;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use secrecy::ExposeSecret as _;
use subtle::ConstantTimeEq as _;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditSender, LogEntry, LogEvent, LOG_SCHEMA_VERSION};
use crate::config::AgentAuth;
use crate::proxy::ProxyHandler;

// ── Bearer auth middleware ────────────────────────────────────────────────────

/// State held by the bearer-token auth middleware.
///
/// `Clone` is required because axum clones the state for each request.
/// All fields are cheap to clone: `Arc` for the secret box and the upstream
/// name; `AuditSender` wraps an `mpsc::Sender` which is `Clone`.
#[derive(Clone)]
struct BearerAuthState {
    /// Expected token value.  Only exposed at the comparison point — never
    /// logged, never included in error messages.
    token: Arc<secrecy::SecretBox<String>>,
    /// Audit log sender for emitting rejection events.
    audit_tx: AuditSender,
    /// Upstream display name included in audit log entries.
    upstream_name: Arc<String>,
}

/// Tower middleware that enforces `Authorization: Bearer <token>` on every
/// request.
///
/// - Missing header → 401 with `WWW-Authenticate: Bearer`
/// - Incorrect token → 401 with `WWW-Authenticate: Bearer`
/// - Correct token → request forwarded to the next handler
///
/// The comparison uses `subtle::ConstantTimeEq` to prevent timing attacks.
async fn bearer_auth_middleware(
    State(state): State<BearerAuthState>,
    req: Request,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let provided = auth_header.and_then(|h| h.strip_prefix("Bearer "));

    let rejection_reason: Option<&str> = if auth_header.is_none() {
        Some("missing Authorization header")
    } else if provided.is_none() {
        Some("Authorization header is not a Bearer token")
    } else {
        // Constant-time comparison — never expose secret in branches or logs.
        let expected = state.token.expose_secret();
        let ok: bool = expected
            .as_bytes()
            .ct_eq(provided.expect("checked above").as_bytes())
            .into();
        if ok { None } else { Some("invalid token") }
    };

    if let Some(reason) = rejection_reason {
        state.audit_tx.send(&LogEntry {
            version: LOG_SCHEMA_VERSION,
            timestamp: chrono::Utc::now(),
            event: LogEvent::AgentAuthRejected {
                method: "bearer".to_owned(),
                reason: reason.to_owned(),
            },
            session_id: "0".to_owned(),
            upstream: (*state.upstream_name).clone(),
        });
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }

    next.run(req).await
}

// ── IP allowlist middleware ───────────────────────────────────────────────────

/// State held by the IP-allowlist middleware.
#[derive(Clone)]
struct IpAllowlistState {
    /// Parsed CIDR ranges.  `Arc` makes cloning cheap.
    ranges: Arc<Vec<IpNet>>,
    /// Audit log sender for emitting rejection events.
    audit_tx: AuditSender,
    /// Upstream display name included in audit log entries.
    upstream_name: Arc<String>,
}

/// Tower middleware that restricts access to a list of source IP CIDRs.
///
/// - Source IP not in any range → 403 Forbidden
/// - Source IP in an allowed range → request forwarded to the next handler
///
/// IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalised to IPv4
/// before the containment check so that IPv4 CIDRs match connections arriving
/// on a dual-stack listener regardless of how the OS presents them.
async fn ip_allowlist_middleware(
    State(state): State<IpAllowlistState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = normalize_ip(addr.ip());
    let allowed = state.ranges.iter().any(|net| net.contains(&ip));

    if !allowed {
        state.audit_tx.send(&LogEntry {
            version: LOG_SCHEMA_VERSION,
            timestamp: chrono::Utc::now(),
            event: LogEvent::AgentAuthRejected {
                method: "ip_allowlist".to_owned(),
                reason: format!("source IP {ip} is not in the allowlist"),
            },
            session_id: "0".to_owned(),
            upstream: (*state.upstream_name).clone(),
        });
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(req).await
}

/// Normalise an IP address for allowlist checks.
///
/// Converts IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) to plain IPv4 so
/// that IPv4 CIDR rules match connections on dual-stack listeners regardless
/// of how the OS presents the remote address.  All other addresses are
/// returned unchanged.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

// ── Agent HTTP transport ──────────────────────────────────────────────────────

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
    /// When `auth` is configured:
    /// - `AgentAuth::Bearer` — all requests to `/mcp` must carry a valid
    ///   `Authorization: Bearer` header.
    /// - `AgentAuth::IpAllowlist` — only requests from allowed source IPs
    ///   reach `/mcp`.
    ///
    /// In both cases `GET /health` is always accessible without credentials
    /// (for container readiness probes).
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
        auth: Option<AgentAuth>,
        audit_tx: AuditSender,
        upstream_name: String,
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

        // Build the MCP sub-router, optionally protected by an auth layer.
        // The auth layer is applied ONLY to this sub-router so that /health
        // (registered on the outer router) is always reachable without credentials.
        let mcp_router: Router<()> = {
            let r = Router::new().nest_service("/mcp", service);
            let upstream_name_arc = Arc::new(upstream_name);
            match auth {
                Some(AgentAuth::Bearer { token: bearer_token }) => {
                    let state = BearerAuthState {
                        token: Arc::new(bearer_token),
                        audit_tx,
                        upstream_name: upstream_name_arc,
                    };
                    r.layer(axum::middleware::from_fn_with_state(
                        state,
                        bearer_auth_middleware,
                    ))
                }
                Some(AgentAuth::IpAllowlist { ranges }) => {
                    let state = IpAllowlistState {
                        ranges: Arc::new(ranges),
                        audit_tx,
                        upstream_name: upstream_name_arc,
                    };
                    r.layer(axum::middleware::from_fn_with_state(
                        state,
                        ip_allowlist_middleware,
                    ))
                }
                None => r,
            }
        };

        // Health endpoint lives on a separate router so it is never wrapped by
        // the auth middleware, regardless of auth configuration.
        let health_router: Router<()> = Router::new()
            .route("/health", get(health_handler))
            .with_state(upstream_ready);

        let app = mcp_router.merge(health_router);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind HTTP listener on port {port}"))?;

        tracing::info!(port, "HTTP agent listener bound");

        // Use into_make_service_with_connect_info so that ConnectInfo<SocketAddr>
        // is available to middleware (required by the IP allowlist middleware;
        // harmless overhead when not used).
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn normalize_ip_leaves_plain_ipv4_unchanged() {
        let ip = IpAddr::V4([192, 168, 1, 1].into());
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn normalize_ip_leaves_plain_ipv6_unchanged() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x20, 0x01, 0x0db8, 0, 0, 0, 0, 1));
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn normalize_ip_converts_ipv4_mapped_ipv6_to_ipv4() {
        // ::ffff:192.168.1.1 is the IPv4-mapped IPv6 form of 192.168.1.1
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        let expected = IpAddr::V4([192, 168, 1, 1].into());
        assert_eq!(normalize_ip(mapped), expected);
    }

    #[test]
    fn normalize_ip_converts_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        let expected = IpAddr::V4([127, 0, 0, 1].into());
        assert_eq!(normalize_ip(mapped), expected);
    }
}
