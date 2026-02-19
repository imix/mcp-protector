//! Audit log writer.
//!
//! Emits one JSON-Lines entry to stdout for every `tools/call` and
//! `tools/list` request processed by the proxy (FR16–FR19).  Entries must
//! never be lost: the writer flushes all buffered entries during graceful
//! shutdown before the process exits.
//!
//! Stub — full implementation in Story 1.4.

// Stub module: items will be populated in subsequent stories.
