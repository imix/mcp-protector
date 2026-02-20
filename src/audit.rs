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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// ── Schema version ────────────────────────────────────────────────────────────

/// Current audit log schema version (public contract — never decrement).
pub const LOG_SCHEMA_VERSION: u32 = 1;

/// Capacity of the bounded audit log channel.
///
/// When the channel is full, new entries are dropped rather than blocking
/// the proxy's hot path.  A single `warn`-level log is emitted on the first
/// drop to alert operators without flooding the log.
const AUDIT_CHANNEL_CAPACITY: usize = 4096;

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
    /// Monotonically increasing session identifier (decimal-string).
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

/// Return a unique, monotonically increasing session identifier as a
/// decimal-string (e.g. `"1"`, `"2"`, …).
///
/// The counter starts at 1 and is safe for concurrent use across threads.
/// The value serialises to a JSON string (quoted), not a JSON number.
pub(crate) fn next_session_id() -> String {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

// ── Sender handle ─────────────────────────────────────────────────────────────

/// Cloneable handle to the audit writer task.
///
/// Call [`AuditSender::send`] to enqueue a log entry.  Sending never blocks:
/// entries are serialised to JSON on the caller's task and placed in a bounded
/// channel.  When the channel is full the entry is dropped and a single
/// `warn`-level diagnostic is emitted (rather than panicking or blocking).
#[derive(Clone, Debug)]
pub struct AuditSender {
    tx: mpsc::Sender<String>,
    /// Set to `true` on the first channel-full drop to avoid log spam.
    warned: Arc<AtomicBool>,
}

impl AuditSender {
    /// Serialise `entry` to JSON and enqueue it for writing.
    ///
    /// Serialisation happens on the caller's task (not the writer task) so
    /// the writer can focus purely on I/O.  Returns without blocking even if
    /// the channel is full — excess entries are silently dropped after a
    /// one-time `warn` diagnostic.
    pub(crate) fn send(&self, entry: &LogEntry) {
        match serde_json::to_string(entry) {
            Ok(mut json) => {
                json.push('\n');
                match self.tx.try_send(json) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Warn only once to avoid flooding the log under
                        // pathological request rates.
                        if !self.warned.swap(true, Ordering::Relaxed) {
                            tracing::warn!(
                                capacity = AUDIT_CHANNEL_CAPACITY,
                                "audit log channel full; entries are being dropped"
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        tracing::warn!("audit writer channel closed; entry dropped");
                    }
                }
            }
            Err(err) => {
                tracing::warn!("failed to serialise audit entry: {err}");
            }
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
/// - `audit_to_stderr`: when `true` the writer emits to `stderr` (stdio
///   transport mode, where `stdout` is the MCP protocol channel).  When
///   `false` it emits to `stdout` (HTTP transport mode).
pub(crate) fn start_writer(
    token: CancellationToken,
    audit_to_stderr: bool,
) -> (AuditSender, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<String>(AUDIT_CHANNEL_CAPACITY);
    let sender = AuditSender {
        tx,
        warned: Arc::new(AtomicBool::new(false)),
    };
    let handle = tokio::spawn(writer_task(rx, token, audit_to_stderr));
    (sender, handle)
}

/// Background writer task.
///
/// Receives pre-serialised JSON lines from the channel and writes them
/// directly to the configured output stream.  All serialisation is done on
/// the sender side; this task is pure I/O.
async fn writer_task(
    mut rx: mpsc::Receiver<String>,
    token: CancellationToken,
    audit_to_stderr: bool,
) {
    loop {
        tokio::select! {
            biased;
            line = rx.recv() => {
                match line {
                    Some(s) => write_line(&s, audit_to_stderr),
                    // Channel closed — sender side dropped.
                    None => break,
                }
            }
            () = token.cancelled() => break,
        }
    }

    // Drain any remaining entries that arrived before cancellation.
    while let Ok(line) = rx.try_recv() {
        write_line(&line, audit_to_stderr);
    }

    // Flush the appropriate output stream.
    if audit_to_stderr {
        let _ = std::io::stderr().flush();
    } else {
        let _ = std::io::stdout().flush();
    }
}

/// Write a pre-serialised JSON line (including the trailing `\n`) to the
/// configured output stream.  Errors are silently ignored — best-effort in
/// production (NFR-R2: no panics).
fn write_line(line: &str, audit_to_stderr: bool) {
    if audit_to_stderr {
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    } else {
        let _ = std::io::stdout().lock().write_all(line.as_bytes());
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

    #[test]
    fn session_id_serialises_as_json_string_not_number() {
        let entry = make_entry(LogEvent::ToolCall {
            tool_name: "x".to_owned(),
            allowed: true,
        });
        let v = parse(&serde_json::to_string(&entry).unwrap());
        // session_id must be a JSON string ("42"), not a number (42).
        assert!(v["session_id"].is_string(), "session_id must be a JSON string");
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
