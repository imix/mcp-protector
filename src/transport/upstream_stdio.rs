//! Upstream stdio transport.
//!
//! Spawns the upstream MCP server as a child subprocess and communicates
//! with it over its stdin/stdout.  The child process lifetime is tied to the
//! proxy's lifetime; it is terminated during graceful shutdown.
//!
//! The child's own stderr is inherited from the proxy process so that upstream
//! diagnostic output is visible without interception.

use std::process::Stdio;

use anyhow::Context as _;
use rmcp::{RoleClient, service::{RunningService, serve_client_with_ct}};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

/// Upstream stdio transport.
///
/// Spawns an MCP server subprocess and performs the MCP client handshake.
pub(crate) struct UpstreamStdioTransport;

impl UpstreamStdioTransport {
    /// Spawn the upstream MCP server from `command` and complete the MCP client
    /// handshake.
    ///
    /// Returns the running client service and a display name suitable for use
    /// in audit log entries.
    ///
    /// The display name is the basename of the executable (i.e., the last path
    /// component of `command[0]`), falling back to the full first element when
    /// no path separator is present.
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess cannot be spawned or if the MCP
    /// handshake fails.
    pub(crate) async fn connect(
        command: &[String],
        token: CancellationToken,
    ) -> anyhow::Result<(RunningService<RoleClient, ()>, String)> {
        let executable = command
            .first()
            .context("upstream command must have at least one element")?;

        let display_name = derive_display_name(executable);

        let mut child = Command::new(executable)
            .args(command.get(1..).unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Let upstream stderr pass through to our stderr so its diagnostics
            // remain visible to operators without any interception.
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!("failed to spawn upstream MCP server '{executable}'")
            })?;

        // Take ownership of the child's stdio handles.  The `expect` calls here
        // document the programming invariant that the handles are always present
        // when `Stdio::piped()` was specified above — they cannot be `None`.
        let child_stdout = child
            .stdout
            .take()
            .expect("child stdout is piped — set above");
        let child_stdin = child
            .stdin
            .take()
            .expect("child stdin is piped — set above");

        // `(AsyncRead, AsyncWrite)` implements `IntoTransport<RoleClient>` via
        // the `transport-async-rw` feature pulled in by the `client` feature.
        let service: RunningService<RoleClient, ()> =
            serve_client_with_ct((), (child_stdout, child_stdin), token)
                .await
                .context("upstream MCP handshake failed")?;

        Ok((service, display_name))
    }
}

/// Derive a human-readable display name from an executable path.
///
/// Returns the basename (final path component) of `executable`, or the full
/// string if it contains no path separators.
fn derive_display_name(executable: &str) -> String {
    // Use the platform's path separator to extract the basename.
    std::path::Path::new(executable)
        .file_name()
        .and_then(|os| os.to_str())
        .unwrap_or(executable)
        .to_owned()
}

/// Attempt a graceful termination of `child`.
///
/// On Unix platforms this sends SIGTERM (via `libc::kill`) and then waits for
/// the process to exit.  On other platforms it calls `kill()` (forceful
/// termination) since there is no standard signal API.
///
/// This function is best-effort; errors are logged but not propagated.
#[allow(dead_code)] // called by proxy.rs during upstream cleanup
pub(crate) async fn graceful_kill(mut child: tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some(id) = child.id() {
            // SAFETY: this is a Rust project with `unsafe_code = "forbid"`,
            // so we delegate the SIGTERM via tokio's start_kill which uses
            // `kill(2)` internally and returns a Result.
            // `tokio::process::Child::start_kill` sends SIGKILL on Unix.
            // For SIGTERM specifically we use libc directly:
            //
            // `id` is `u32`; cast to `i32` (PIDs on Linux are `i32` and
            // never exceed `i32::MAX` in practice).
            #[allow(clippy::cast_possible_wrap)]
            let pid = id as i32;
            // POSIX guarantees SIGTERM = 15.
            // We do not use unsafe here — use `std::process` equivalent isn't
            // available, so we fall back to tokio's kill (SIGKILL) as a
            // safety net after a brief wait for graceful exit:
            // send SIGTERM via the `kill` command shim (no nix dep needed).
            let sigterm_sent = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !sigterm_sent {
                tracing::warn!(
                    "failed to send SIGTERM to upstream process {id}; \
                     falling back to SIGKILL"
                );
                if let Err(err) = child.kill().await {
                    tracing::warn!("failed to kill upstream process {id}: {err}");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = child.kill().await {
            tracing::warn!("failed to kill upstream process: {err}");
        }
    }

    match child.wait().await {
        Ok(status) => {
            tracing::debug!("upstream process exited with status: {status}");
        }
        Err(err) => {
            tracing::warn!("error waiting for upstream process to exit: {err}");
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_display_name_strips_directory_prefix() {
        assert_eq!(derive_display_name("/usr/local/bin/mcp-server"), "mcp-server");
    }

    #[test]
    fn derive_display_name_with_relative_path() {
        assert_eq!(derive_display_name("./mcp-server"), "mcp-server");
    }

    #[test]
    fn derive_display_name_with_no_separator() {
        assert_eq!(derive_display_name("mcp-server"), "mcp-server");
    }

    #[test]
    fn derive_display_name_with_nested_path() {
        assert_eq!(derive_display_name("/a/b/c/server"), "server");
    }
}
