//! Proxy core.
//!
//! Accepts agent connections, applies the policy engine, and forwards
//! permitted requests to the upstream MCP server.  Each agent connection
//! runs on its own tokio task; a single upstream connection is shared for the
//! lifetime of the proxy instance.
//!
//! Stub — full implementation in Story 1.5.

// Stub module: items will be populated in subsequent stories.
