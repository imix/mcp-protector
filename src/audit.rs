//! Audit log writer.
//!
//! Emits one JSON-Lines entry to stdout (HTTP mode) or stderr (stdio mode) for
//! every `tools/call` and `tools/list` request processed by the proxy
//! (FR16–FR19).  Entries must never be lost: the writer flushes all buffered
//! entries during graceful shutdown before the process exits.
//!
//! # Schema
//!
//! Each line is a JSON object conforming to the contract in
//! `docs/audit-log-schema.md`.  The `version`, `timestamp`, `session_id`, and
//! `upstream` fields appear on every entry; event-specific fields are merged
//! via `#[serde(flatten)]`.
//!
//! # Example output
//!
//! ```text
//! {"version":1,"timestamp":"2026-02-19T16:00:00.000Z","event":"tool_call","session_id":"1","upstream":"my-server","tool_name":"read_file","allowed":true}
//! {"version":1,"timestamp":"2026-02-19T16:00:00.000Z","event":"tools_list","session_id":"1","upstream":"my-server","tools_upstream":10,"tools_returned":3}
//! ```

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// ── Schema version ────────────────────────────────────────────────────────────

/// Current audit log schema version (public contract — never decrement).
pub const LOG_SCHEMA_VERSION: u32 = 1;

// ── Log types ─────────────────────────────────────────────────────────────────

/// A single audit log entry.  One entry is emitted per `tools/call` and
/// `tools/list` request.  Serialised as a JSON-Lines record.
#[derive(Debug, serde::Serialize)]
pub struct LogEntry {
    /// Schema version — always [`LOG_SCHEMA_VERSION`].
    pub version: u32,
    /// UTC timestamp of the event.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event-specific payload (flattened into the top-level JSON object).
    #[serde(flatten)]
    pub event: LogEvent,
    /// Monotonically increasing session identifier.
    pub session_id: String,
    /// Human-readable upstream server name (basename of the command, or the
    /// first element of the argv if no path separator is present).
    pub upstream: String,
}

/// The set of events that can appear in the audit log.
///
/// The `event` field in the JSON output is derived from the variant name via
/// `rename_all = "snake_case"`.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LogEvent {
    /// A `tools/call` request was received.
    ToolCall {
        /// Name of the tool the agent requested.
        tool_name: String,
        /// `true` if the tool is in the allowlist; `false` if it was blocked.
        allowed: bool,
    },
    /// A `tools/list` request was received.
    ToolsList {
        /// Number of tools reported by the upstream server.
        tools_upstream: u32,
        /// Number of tools returned to the agent after policy filtering.
        tools_returned: u32,
    },
}

// ── Session ID counter ────────────────────────────────────────────────────────

/// Monotonically increasing session counter.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Return a unique, monotonically increasing session identifier as a decimal
/// string.
///
/// The counter starts at 1 and is safe for concurrent use across threads.
pub(crate) fn next_session_id() -> String {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

// ── Sender handle ─────────────────────────────────────────────────────────────

/// Cloneable handle to the audit writer task.
///
/// Call [`AuditSender::send`] to enqueue a log entry.  Sending never blocks —
/// if the writer task has exited the error is logged via `tracing` and the
/// entry is silently dropped (rather than panicking).
#[derive(Clone, Debug)]
pub struct AuditSender {
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl AuditSender {
    /// Enqueue `entry` for writing.
    ///
    /// Logs to `tracing::warn` if the channel is closed, but never panics.
    pub(crate) fn send(&self, entry: LogEntry) {
        if let Err(err) = self.tx.send(entry) {
            tracing::warn!("audit writer channel closed; entry dropped: {err}");
        }
    }
}

// ── Writer task ───────────────────────────────────────────────────────────────

/// Spawn the audit writer background task.
///
/// Returns an [`AuditSender`] for enqueuing log entries and a [`JoinHandle`]
/// that resolves when the writer has flushed all entries and exited.
///
/// # Parameters
///
/// - `token`: cancellation token; the writer exits once cancelled **and** the
///   channel is drained.
/// - `use_stderr`: when `true` the writer emits to `stderr` (stdio transport
///   mode, where `stdout` is the MCP protocol channel).  When `false` it emits
///   to `stdout` (HTTP transport mode).
pub(crate) fn start_writer(
    token: CancellationToken,
    use_stderr: bool,
) -> (AuditSender, JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel::<LogEntry>();
    let sender = AuditSender { tx };
    let handle = tokio::spawn(writer_task(rx, token, use_stderr));
    (sender, handle)
}

/// Background writer task.
async fn writer_task(
    mut rx: mpsc::UnboundedReceiver<LogEntry>,
    token: CancellationToken,
    use_stderr: bool,
) {
    loop {
        tokio::select! {
            biased;
            entry = rx.recv() => {
                match entry {
                    Some(e) => write_entry(&e, use_stderr),
                    // Channel closed — sender side dropped.
                    None => break,
                }
            }
            () = token.cancelled() => break,
        }
    }

    // Drain any remaining entries that arrived before cancellation.
    while let Ok(entry) = rx.try_recv() {
        write_entry(&entry, use_stderr);
    }

    // Flush the appropriate output stream.
    if use_stderr {
        let _ = std::io::stderr().flush();
    } else {
        let _ = std::io::stdout().flush();
    }
}

/// Serialise `entry` as a JSON-Lines record and write it to the configured
/// output stream.  Errors are logged via `tracing::warn` rather than
/// propagated (NFR-R2: no panics in production paths).
fn write_entry(entry: &LogEntry, use_stderr: bool) {
    match serde_json::to_string(entry) {
        Ok(json) => {
            if use_stderr {
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                // Ignore write errors — best-effort in production.
                let _ = writeln!(handle, "{json}");
            } else {
                let stdout = std::io::stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "{json}");
            }
        }
        Err(err) => {
            tracing::warn!("failed to serialise audit entry: {err}");
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LogEntry JSON serialisation ───────────────────────────────────────────

    /// Parse the JSON and compare field by field to avoid fragility around key
    /// ordering.
    fn parse(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("valid JSON")
    }

    fn make_entry(event: LogEvent) -> LogEntry {
        LogEntry {
            version: LOG_SCHEMA_VERSION,
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-02-19T16:00:00.000Z")
                .expect("valid RFC-3339 timestamp")
                .with_timezone(&chrono::Utc),
            event,
            session_id: "42".to_owned(),
            upstream: "my-server".to_owned(),
        }
    }

    #[test]
    fn tool_call_entry_serialises_to_correct_json() {
        let entry = make_entry(LogEvent::ToolCall {
            tool_name: "read_file".to_owned(),
            allowed: true,
        });
        let json = serde_json::to_string(&entry).unwrap();
        let v = parse(&json);

        assert_eq!(v["version"], 1);
        assert_eq!(v["event"], "tool_call");
        assert_eq!(v["session_id"], "42");
        assert_eq!(v["upstream"], "my-server");
        assert_eq!(v["tool_name"], "read_file");
        assert_eq!(v["allowed"], true);
        // timestamp must be present and parseable
        assert!(v["timestamp"].is_string());
    }

    #[test]
    fn tools_list_entry_serialises_to_correct_json() {
        let entry = make_entry(LogEvent::ToolsList {
            tools_upstream: 10,
            tools_returned: 3,
        });
        let json = serde_json::to_string(&entry).unwrap();
        let v = parse(&json);

        assert_eq!(v["version"], 1);
        assert_eq!(v["event"], "tools_list");
        assert_eq!(v["session_id"], "42");
        assert_eq!(v["upstream"], "my-server");
        assert_eq!(v["tools_upstream"], 10);
        assert_eq!(v["tools_returned"], 3);
    }

    #[test]
    fn tool_call_blocked_entry_has_allowed_false() {
        let entry = make_entry(LogEvent::ToolCall {
            tool_name: "delete_all".to_owned(),
            allowed: false,
        });
        let json = serde_json::to_string(&entry).unwrap();
        let v = parse(&json);
        assert_eq!(v["allowed"], false);
    }

    #[test]
    fn log_schema_version_is_one() {
        assert_eq!(LOG_SCHEMA_VERSION, 1);
    }

    // ── next_session_id ───────────────────────────────────────────────────────

    #[test]
    fn session_ids_are_monotonically_increasing() {
        let a: u64 = next_session_id().parse().expect("numeric session id");
        let b: u64 = next_session_id().parse().expect("numeric session id");
        let c: u64 = next_session_id().parse().expect("numeric session id");
        assert!(a < b, "session ids must be strictly increasing");
        assert!(b < c, "session ids must be strictly increasing");
    }

    #[test]
    fn session_id_is_non_zero() {
        let id: u64 = next_session_id().parse().expect("numeric session id");
        assert!(id > 0, "session id must be positive");
    }
}
