//! Graceful shutdown coordinator.
//!
//! Listens for SIGTERM and SIGINT, signals all active components to stop
//! accepting new work, waits for in-flight requests to drain, and ensures the
//! audit log is fully flushed before the process exits.
//!
//! # Example
//!
//! ```rust,no_run
//! # use mcp_protector::shutdown;
//! let token = shutdown::create_token();
//! shutdown::install_handlers(token.clone());
//! // pass token to proxy components
//! ```

use tokio_util::sync::CancellationToken;

/// Create the root cancellation token for this proxy instance.
///
/// All proxy components receive a child token derived from this root via
/// [`CancellationToken::child_token`].  Cancelling the root cancels all
/// children simultaneously.
pub(crate) fn create_token() -> CancellationToken {
    CancellationToken::new()
}

/// Install OS signal handlers.
///
/// Spawns a background task that cancels `token` on the first SIGTERM or
/// SIGINT (Ctrl-C).  The task handle is intentionally dropped — the task
/// continues running until the signal arrives.
///
/// On Unix platforms both SIGTERM and SIGINT are handled.  On Windows only
/// Ctrl-C (the equivalent of SIGINT) is handled.
pub(crate) fn install_handlers(token: CancellationToken) {
    tokio::spawn(wait_for_signal(token));
}

#[cfg(unix)]
async fn wait_for_signal(token: CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())
        .expect("SIGTERM handler registration must succeed at startup");
    let mut sigint = signal(SignalKind::interrupt())
        .expect("SIGINT handler registration must succeed at startup");

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received — initiating graceful shutdown");
        }
        _ = sigint.recv() => {
            tracing::info!("SIGINT received — initiating graceful shutdown");
        }
    }

    token.cancel();
}

#[cfg(not(unix))]
async fn wait_for_signal(token: CancellationToken) {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!("failed to listen for Ctrl-C: {err}");
    } else {
        tracing::info!("Ctrl-C received — initiating graceful shutdown");
    }
    token.cancel();
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_token_returns_non_cancelled_token() {
        let token = create_token();
        assert!(!token.is_cancelled(), "newly created token must not be pre-cancelled");
    }

    #[test]
    fn child_token_is_not_cancelled_initially() {
        let token = create_token();
        let child = token.child_token();
        assert!(!child.is_cancelled());
    }

    #[test]
    fn cancelling_root_cancels_child() {
        let token = create_token();
        let child = token.child_token();
        token.cancel();
        assert!(child.is_cancelled(), "child must be cancelled when root is cancelled");
    }
}
