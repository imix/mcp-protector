---
stepsCompleted: ['step-01-init', 'step-02-context', 'step-03-starter', 'step-04-decisions', 'step-05-patterns', 'step-06-structure', 'step-07-validation', 'step-08-complete']
inputDocuments:
  - '_bmad-output/planning-artifacts/product-brief-mcp-protector-2026-02-19.md'
  - '_bmad-output/planning-artifacts/prd.md'
workflowType: 'architecture'
project_name: 'mcp-protector'
user_name: 'Master'
date: '2026-02-19'
lastStep: 8
status: 'complete'
completedAt: '2026-02-19'
---

# Architecture Decision Document

_This document builds collaboratively through step-by-step discovery. Sections are appended as we work through each architectural decision together._

## Project Context Analysis

### Requirements Overview

**Functional Requirements (30 total across 8 categories):**

- **Proxy Core (FR1–FR4):** Transparent MCP forwarding, concurrent agent connections,
  single-upstream-per-instance constraint, rmcp version negotiation at the connection boundary.
- **Policy Enforcement (FR5–FR9):** Exact-name allowlist, tools/list filtering (intersection of
  allowlist and upstream actual tools), tools/call blocking, deny-on-empty-allowlist,
  fail-closed on missing/malformed config. The entire product value proposition lives here.
- **Transport & Connectivity (FR10–FR13):** Agent-side stdio and HTTP; upstream-side stdio
  (subprocess spawn) and HTTPS. Four transport combinations, all required for MVP.
- **Upstream Authentication (FR14–FR15):** Bearer token in config, attached to all outbound
  HTTPS requests. No token must ever appear in logs or errors.
- **Audit Logging (FR16–FR20):** Structured JSON-Lines log entry per tools/call and
  tools/list, always to stdout, never suppressed, never lost on shutdown. Format is a
  versioned public contract.
- **Observability & Operations (FR21–FR23):** GET /health (HTTP mode), diagnostics to stderr
  (stdout reserved for audit log), graceful SIGTERM/SIGINT shutdown with in-flight drain.
- **Configuration Management (FR24–FR27):** Config path via CLI flag, full validation before
  any connections, human-readable field-level errors to stderr, validate-config subcommand.
- **CLI & Distribution (FR28–FR30):** `mcp-protector proxy` subcommand, exit codes 0/1/2,
  precompiled binaries for Linux (x86_64 + aarch64), macOS (x86_64 + arm64), Windows (x86_64).

**Non-Functional Requirements:**

- **Performance:** ≤10ms p99 latency overhead; async audit log writes with guaranteed flush on
  shutdown; per-instance concurrency (not unbounded horizontal scale within one instance).
- **Security:** TLS 1.2+ via rustls only (no custom cert validation); credentials never in logs;
  no `unsafe` in policy enforcement layer; `cargo audit` clean on every release.
- **Reliability:** No audit log entry loss on graceful shutdown; no process crash on malformed
  upstream messages; fail-closed on any policy evaluation error; no silent request drops.
- **Correctness:** Case-sensitive, byte-for-byte tool name comparison across all platforms;
  tools/list intersection (allowlist ∩ upstream actual tools, not allowlist alone).
- **Maintainability:** Minimal deps with justification in Cargo.toml; 100% branch coverage on
  policy enforcement as a CI gate; versioned log and config schemas with explicit breaking-change
  policy.

**Scale & Complexity:**

- Primary domain: CLI tool / systems programming / security proxy
- Complexity level: Medium-high (security-critical domain; correctness requirements are absolute,
  not targets; fail-closed semantics must hold across all failure modes including partial failures)
- Estimated architectural components: 5–7 (config, transport-agent, transport-upstream, policy
  engine, audit logger, signal handler, optional HTTP server for health)

### Technical Constraints & Dependencies

- **Language:** Rust — required for memory safety at enforcement boundary; no negotiation
- **MCP protocol library:** rmcp — pinned in Cargo.lock; version negotiation delegated entirely
- **TLS:** rustls — memory-safe TLS; no openssl; no custom certificate validation logic
- **Config format:** TOML — as specified in PRD config schema
- **Supply chain:** Cargo.lock committed; `cargo audit` on every CI PR; minimal direct deps
- **Policy layer safety:** No `unsafe` blocks permitted in the tool-name matching,
  allowlist lookup, or log-writing modules (NFR-S3)
- **Log format stability:** JSON-Lines schema is a versioned public contract; breaking changes
  require major version bump (NFR-M3)

### Cross-Cutting Concerns Identified

1. **Fail-closed guarantee** — Must hold at every layer: config load, policy evaluation,
   transport error, upstream error. No component may silently permit a call when in doubt.
2. **Audit completeness** — Every tools/call and tools/list must produce a log entry. This
   concern spans from the transport receive layer through policy evaluation to log emission.
3. **Credential protection** — Bearer tokens must not surface in logs, errors, or debug output.
   This spans config loading, upstream auth, error formatting, and any panic handlers.
4. **Transport abstraction** — Agent (stdio/HTTP) and upstream (stdio/HTTPS) must be cleanly
   abstracted to allow the policy/logging core to be transport-agnostic and independently testable.
5. **Graceful shutdown** — Spans signal handling, in-flight request draining, and audit log
   flushing. All three must coordinate without data loss.
6. **Config validation lifecycle** — Config is the only trust root; it must be fully validated
   before any network connection is attempted. Validation errors must be human-readable and
   actionable.

## Starter Template & Foundation

### Primary Technology Domain

Rust binary (async CLI security proxy) — all core technology decisions are
pre-determined by PRD constraints, not discovered via template selection.

### Starter Approach

**Selected: `cargo new --bin mcp-protector` (manual foundation)**

Rationale: NFR-M1 requires every dependency to be justified in `Cargo.toml`.
Using a cargo-generate template would introduce pre-wired dependencies that were
not explicitly chosen for this project. Since all technology decisions are already
documented in the PRD (Rust, tokio, clap, rmcp, rustls, serde/toml, tracing),
the correct foundation is a clean binary crate with each dependency added
deliberately.

**Initialization Command:**

```bash
cargo new --bin mcp-protector
cd mcp-protector
```

### Initial Dependency Set

| Crate | Purpose | Justification |
|---|---|---|
| `clap` (derive feature) | CLI argument parsing, subcommands | Required for `proxy` and `validate-config` subcommands; derive macro minimizes boilerplate |
| `tokio` (full features) | Async runtime | Required for concurrent agent connections and async audit log writes (NFR-P2) |
| `rmcp` | MCP protocol implementation | Delegates protocol parsing and version negotiation; eliminates custom protocol code |
| `rustls` + `tokio-rustls` | TLS for upstream HTTPS connections | Memory-safe TLS; no openssl; strict cert validation by default (NFR-S1) |
| `serde` + `serde_derive` | Serialization framework | Required for TOML config deserialization and JSON-Lines audit log serialization |
| `toml` | TOML config file parsing | Config format specified in PRD |
| `serde_json` | JSON-Lines audit log output | Required for structured audit log format (FR16–FR19) |
| `tracing` + `tracing-subscriber` | Structured diagnostics to stderr | Separates diagnostic output (stderr) from audit log (stdout); async-aware |
| `tokio-util` | Codec/framing utilities | Required for stdio transport framing |
| `thiserror` | Typed error handling | Ergonomic typed errors in policy and config layers |

**Dev dependencies:**

| Crate | Purpose |
|---|---|
| `cargo-audit` (CI tool) | Supply chain vulnerability scanning on every PR (NFR-S4) |
| `tokio-test` | Async test utilities |
| `assert_cmd` | CLI integration test helpers |
| `tempfile` | Isolated config file testing |

### Architectural Decisions Provided by Foundation

- **Language & Runtime:** Rust 2021 edition; tokio multi-thread runtime
- **Build Tooling:** `cargo check -q` for fast compilation checks; `cargo build -q --release`
  for distribution binaries; `cargo test -q` for CI; `cargo audit -q` as required CI step
  (quiet flags used throughout to minimize output noise)
- **Testing:** Built-in test framework + `assert_cmd` for CLI integration; coverage via
  `cargo-llvm-cov --quiet`
- **Cross-Platform:** GitHub Actions matrix builds for all six distribution targets

**Additional dependencies from decisions (steps 4 and 7 validation):**

| Crate | Purpose | Justification |
|---|---|---|
| `secrecy` | Secure in-memory credential handling | Zeroizes bearer token on drop; prevents accidental `Debug` leakage (NFR-S2). Verify latest version on crates.io before pinning. |
| `anyhow` | Top-level error propagation | Ergonomic `?` in `main.rs` where errors are always fatal; no exhaustive matching needed at top level (Decision 7). |
| `chrono` (serde feature) | Timestamp serialization | `DateTime<Utc>` serializes to ISO 8601 UTC automatically via serde; required for `LogEntry.timestamp` in the audit log public contract (Decision 8). |
| `rustls-native-certs` | TLS root certificate source | Loads system certificate store at runtime; supports corporate/private CAs without config changes (Decision 9). |

**Note:** Project initialization using `cargo new --bin mcp-protector` with
this complete dependency set should be the first implementation story.

## Core Architectural Decisions

### Decision Summary

| # | Category | Decision | Option |
|---|---|---|---|
| 1 | Module Structure | Flat modules in `src/` | A |
| 2 | Transport Abstraction | Enum dispatch | B |
| 3 | Policy Engine | Pure functions module | A |
| 4 | Graceful Shutdown | `CancellationToken` | A |
| 5 | Credential Security | `secrecy::Secret<String>` | B |
| 6 | Audit Log Writes | `mpsc` channel + dedicated writer task | A |
| 7 | Error Handling | `thiserror` (domain) + `anyhow` (top-level) | — |
| 8 | Audit Log Schema | `LogEntry` wrapper + `LogEvent` enum, flat JSON | — |
| 9 | TLS Root Certificates | `rustls-native-certs` (system store) | — |

### Decision 1: Module Structure

**Decision:** Flat modules within a single binary crate (`src/`).

**Rationale:** MVP is a single binary with a solo developer. A workspace with separate crates
adds indirection without benefit until the policy engine is needed as an embeddable library
(post-MVP consideration). Flat structure keeps the dependency graph simple and auditable.

```
src/
  main.rs              ← CLI entry point, subcommand dispatch, top-level error handling
  config.rs            ← TOML parsing, validation, typed config structs
  policy.rs            ← allowlist enforcement (pure functions, no state)
  transport/
    mod.rs             ← AgentTransport and UpstreamTransport enums
    agent_stdio.rs     ← agent-side stdio transport
    agent_http.rs      ← agent-side HTTP transport + /health endpoint
    upstream_stdio.rs  ← upstream stdio (subprocess spawn)
    upstream_https.rs  ← upstream HTTPS + bearer token injection
  audit.rs             ← mpsc sender API + writer task + flush-on-shutdown
  proxy.rs             ← session orchestration: connect agent ↔ upstream, run policy
  shutdown.rs          ← CancellationToken wiring, SIGTERM/SIGINT handlers
```

**Post-MVP:** If the policy engine is to be embedded by third parties, extract
`config.rs` + `policy.rs` into a `mcp-protector-core` library crate at that point.

### Decision 2: Transport Abstraction

**Decision:** Enum dispatch for both agent-side and upstream-side transports.

```rust
pub enum AgentTransport { Stdio(StdioAgent), Http(HttpAgent) }
pub enum UpstreamTransport { Stdio(StdioUpstream), Https(HttpsUpstream) }
```

**Rationale:** Transport type is fixed at startup from config — no runtime switching occurs.
Enum dispatch avoids `dyn Trait` overhead and the need for `Box<dyn ...>` allocations on
the hot path. Each variant is fully known at compile time. Matching is exhaustive, so adding
a new transport variant in future forces all call sites to handle it.

**Affects:** `transport/mod.rs`, `proxy.rs`, `config.rs` (transport selection from config).

### Decision 3: Policy Engine Design

**Decision:** Pure functions module — no struct, no state, no side effects.

```rust
// policy.rs
pub fn is_tool_allowed(tool_name: &str, allowlist: &HashSet<String>) -> bool {
    allowlist.contains(tool_name)
}

pub fn filter_tools_list(tools: Vec<Tool>, allowlist: &HashSet<String>) -> Vec<Tool> {
    tools.into_iter().filter(|t| allowlist.contains(&t.name)).collect()
}
```

**Rationale:** The policy is a pure mathematical function: allowlist × tool_name → bool.
No mocking required for tests — call the function directly with known inputs. 100% branch
coverage is trivially verifiable. The stateless design guarantees no policy mutation at
runtime (NFR-R3: fail-closed; no state drift possible).

**Allowlist storage:** `HashSet<String>` built once from config at startup — O(1) lookup,
no reallocation during proxy operation.

**Affects:** `policy.rs`, `proxy.rs` (calls policy functions), all policy enforcement tests.

### Decision 4: Graceful Shutdown Mechanism

**Decision:** `tokio_util::sync::CancellationToken` propagated to all tasks.

```rust
// shutdown.rs
let token = CancellationToken::new();
// Clone and pass to: proxy session tasks, audit writer task, HTTP server
// Signal handler calls token.cancel() on SIGTERM / SIGINT
```

**Shutdown sequence:**
1. Signal received → `token.cancel()`
2. Agent listener stops accepting new connections
3. In-flight proxy sessions complete current request (or timeout)
4. Audit writer task drains mpsc channel, flushes stdout
5. Process exits with code 0

**Rationale:** `CancellationToken` is cloneable and composable — each task receives its own
clone and polls `token.cancelled()` at async yield points. Simpler to wire than a broadcast
channel; no need to send a shutdown "reason". Satisfies NFR-R1 (no log entry loss) when
combined with the audit channel drain in step 6.

**Affects:** `shutdown.rs`, `proxy.rs`, `audit.rs`, `transport/agent_http.rs`.

### Decision 5: Credential Security In Memory

**Decision:** `secrecy::Secret<String>` for bearer token storage.

```rust
use secrecy::{Secret, ExposeSecret};

pub struct UpstreamAuth {
    pub bearer_token: Secret<String>,
}
// Token is accessed only at injection point:
// request.header("Authorization", format!("Bearer {}", auth.bearer_token.expose_secret()))
```

**Rationale:** `Secret<T>` implements `Zeroize` on drop (clears heap memory) and suppresses
`Debug`/`Display` output (prints `[REDACTED]`). This provides compile-time enforcement of
NFR-S2 — the bearer token cannot accidentally appear in a `tracing` span, a `println!`, or
a `{:?}` debug format without an explicit `.expose_secret()` call. One small, well-maintained
crate from the iqlusion organization (same maintainers as `zeroize`).

**Verify:** Check latest version on [crates.io/crates/secrecy](https://crates.io/crates/secrecy)
before pinning in `Cargo.toml`.

**Affects:** `config.rs` (bearer token field), `transport/upstream_https.rs` (token injection).

### Decision 6: Audit Log Write Strategy

**Decision:** `tokio::sync::mpsc` channel with a dedicated writer task.

```
proxy session task  ──┐
proxy session task  ──┤─→  mpsc::Sender<LogEntry>  →  writer task  →  stdout (JSON-Lines)
proxy session task  ──┘
                              ↑ closed on shutdown
                              writer drains queue then exits
```

**Rationale:**
- **NFR-P2:** Tool call handlers send to channel without blocking — channel send is async and
  near-instant. No Mutex contention on stdout.
- **NFR-R1:** On shutdown, `CancellationToken` signals the writer task; writer continues
  draining the channel until all senders are dropped (channel close), then flushes and exits.
  Guaranteed: no log entries are lost if the shutdown sequence is followed.
- **NFR-R4:** Every `tools/call` handler sends a log entry before returning to the caller —
  the send is not optional. A failed send (full/closed channel) is itself logged to stderr.

**Channel capacity:** Unbounded (`mpsc::unbounded_channel`) to ensure tool call handlers
never block waiting for the writer. Memory usage is bounded by in-flight request count.

**Affects:** `audit.rs` (channel + writer task + LogEntry type), `proxy.rs` (sender handle),
`shutdown.rs` (drain coordination).

### Decision 7: Error Handling Split

**Decision:** `thiserror` for typed domain errors; `anyhow` for top-level orchestration.

```rust
// config.rs — typed, mapped to exit codes
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    ReadFailed { path: PathBuf, source: io::Error },
    #[error("invalid config field '{field}': {reason}")]
    InvalidField { field: String, reason: String },
}

// main.rs — top-level, just propagate to stderr
fn main() -> anyhow::Result<()> { ... }
```

**Rationale:** Domain errors (`ConfigError`, `PolicyError`, `TransportError`) need typed
variants to map cleanly to specific exit codes (0/1/2) and human-readable field-level messages
(FR-26). `thiserror` generates `Display` impls from format strings. `anyhow` at `main` allows
ergonomic `?` propagation for orchestration paths where the error is always fatal and
formatted to stderr — no need for exhaustive matching at the top level.

**Exit code mapping:**
- `ConfigError` → exit 1
- Unrecoverable `TransportError` / runtime failure → exit 2
- Clean shutdown → exit 0

**Affects:** `config.rs`, `policy.rs`, `transport/`, `proxy.rs`, `main.rs`.

### Decision 8: Audit Log Schema (LogEntry Type)

**Decision:** Typed `LogEntry` wrapper struct with a `LogEvent` enum for event variants.

```rust
pub const LOG_SCHEMA_VERSION: u32 = 1;

#[derive(serde::Serialize)]
pub struct LogEntry {
    pub version: u32,                        // always LOG_SCHEMA_VERSION
    pub timestamp: chrono::DateTime<chrono::Utc>, // serializes to ISO 8601 UTC
    #[serde(flatten)]
    pub event: LogEvent,
    pub session_id: String,                  // opaque per-connection identifier
    pub upstream: String,                    // upstream server name from config
}

#[derive(serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LogEvent {
    ToolCall {
        tool_name: String,
        allowed: bool,
    },
    ToolsList {
        tools_upstream: u32,   // count of tools returned by upstream
        tools_returned: u32,   // count of tools returned to agent after allowlist filter
    },
}
```

**Resulting JSON (tool_call):**

```json
{"version":1,"timestamp":"2026-02-19T16:00:00.000Z","event":"tool_call","session_id":"42","upstream":"my-server","tool_name":"read_file","allowed":true}
```

**Resulting JSON (tools_list):**

```json
{"version":1,"timestamp":"2026-02-19T16:00:00.000Z","event":"tools_list","session_id":"42","upstream":"my-server","tools_upstream":10,"tools_returned":3}
```

**Session ID generation:** Atomic `u64` counter incremented per accepted connection —
no UUID crate required. `std::sync::atomic::AtomicU64`, formatted as decimal string.

**Rationale:** `#[serde(flatten)]` merges event-specific fields into the top-level JSON
object — no nested `"data"` wrapper, keeping the schema flat and grep-friendly.
`#[serde(tag = "event")]` produces the `"event"` discriminator field automatically.
`chrono::DateTime<Utc>` with the `serde` feature serializes to RFC 3339/ISO 8601 with no
manual formatting. Fields shared by all events (`version`, `timestamp`, `session_id`,
`upstream`) live in the wrapper; event-specific fields live in the enum variants.

**This schema is the public contract.** Any addition of a new field to an existing variant,
removal of a field, or rename is a breaking change requiring a `version` bump.
New event types (new enum variants) are non-breaking additions.

**Affects:** `audit.rs` (LogEntry/LogEvent types), `proxy.rs` (populates and sends entries),
`docs/audit-log-schema.md` (documents the contract).

### Decision 9: TLS Root Certificate Source

**Decision:** `rustls-native-certs` — load system certificate store at runtime.

```rust
// transport/upstream_https.rs
use rustls_native_certs::load_native_certs;

let mut root_store = rustls::RootCertStore::empty();
for cert in load_native_certs()? {
    root_store.add(cert)?;
}
let tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

**Rationale:** mcp-protector proxies to operator-configured upstream MCP servers.
Enterprise deployments commonly use private/corporate CAs — these are in the system
cert store but not in `webpki-roots` (Mozilla root program). Using native certs means
the proxy works transparently in corporate environments without any TLS configuration.
On minimal Docker images without a cert store, operators add `ca-certificates` as they
would for any TLS client.

**Trade-off vs `webpki-roots`:** Native certs require a usable system cert store at runtime
(present on all supported platforms: Linux with `ca-certificates`, macOS, Windows).
`webpki-roots` bundles Mozilla roots, works on cert-store-less environments, but would
silently fail for private CAs without additional config plumbing.

**Affects:** `transport/upstream_https.rs`, `Cargo.toml` (rustls-native-certs dep).

### Decision Impact Analysis

**Implementation Sequence (dependencies between decisions):**

1. `config.rs` first — all other components depend on validated config
2. `policy.rs` second — pure functions, no dependencies beyond config types
3. `audit.rs` third — writer task needed before proxy sessions can log
4. `shutdown.rs` fourth — CancellationToken must exist before tasks are spawned
5. `transport/` — each variant implemented; enum assembled in `mod.rs`
6. `proxy.rs` last — orchestrates all of the above

**Cross-Component Dependencies:**

- Policy engine (`policy.rs`) depends only on `std::collections::HashSet` — fully isolated
- Audit writer (`audit.rs`) depends on `shutdown.rs` (CancellationToken) for drain coordination
- Transport enum (`transport/`) depends on `config.rs` (determines which variant to construct)
- Proxy session (`proxy.rs`) depends on all: transport, policy, audit, shutdown
- `secrecy` usage crosses `config.rs` → `transport/upstream_https.rs` only
- `LogEntry`/`LogEvent` types defined in `audit.rs`; populated and sent from `proxy.rs`
- `rustls-native-certs` used only in `transport/upstream_https.rs`

**Deferred Decisions (Post-MVP):**

| Decision | Deferred Until |
|---|---|
| Workspace split (`mcp-protector-core` crate) | When policy engine needs to be embedded externally |
| Shell completion generation (`clap_complete`) | Phase 2 (PRD: deferred) |
| OAuth2 upstream auth | Phase 2 |
| Remote audit log forwarding | Phase 2 |
| Rate limiting | Phase 2 |

## Implementation Patterns & Consistency Rules

### Conflict Points Identified

**8 areas where AI agents could make different choices:**

Error type naming, test placement, audit log JSON schema, panic/unwrap policy,
tracing conventions, clippy configuration, visibility policy, async function usage.

---

### Naming Patterns

**Error Type Naming:**

Each module uses `{Domain}Error` — no shorthand:

```rust
// CORRECT
pub enum ConfigError { ... }
pub enum PolicyError { ... }
pub enum TransportError { ... }

// FORBIDDEN
pub enum Error { ... }       // too generic
pub enum ConfigErr { ... }   // shorthand not permitted
```

**Audit Log JSON Field Names (Public Contract):**

All audit log JSON fields use `snake_case`. This is the versioned public schema — no
agent may rename, camelCase, or add unreferenced fields without a major version bump.

```json
{
  "version": 1,
  "timestamp": "<ISO 8601 UTC>",
  "event": "tool_call",
  "tool_name": "read_file",
  "session_id": "...",
  "allowed": true,
  "upstream": "my-server"
}
```

**TOML Config Field Names:**

All config fields use `snake_case`. The config schema is a versioned public contract
(same breaking-change policy as the audit log schema).

**Tracing Span & Field Names:**

- Span names: verb-noun, snake_case: `"proxy_request"`, `"load_config"`, `"connect_upstream"`
- Field names: snake_case: `tool_name`, `session_id`, `upstream_addr`, `allowed`
- Never include bearer tokens or anything from `secrecy::Secret` as a tracing field

**Test Function Names:**

Descriptive, scenario-focused names within each file — consistent within a module:

```rust
// CORRECT — consistent within a module
fn allows_listed_tool_name() { ... }
fn blocks_unlisted_tool_name() { ... }
fn empty_allowlist_blocks_all() { ... }

// AVOID — mixing naming styles within one module
fn test_allow() { ... }
fn blocks_unlisted_tool_name_returns_false() { ... }
```

---

### Structure Patterns

**Test Placement:**

- **Unit tests:** Inline `#[cfg(test)]` module at the bottom of the source file under test.
  Never a separate `src/*_test.rs` file.
- **Integration tests:** External `tests/` directory, one file per concern:
  `tests/config_validation.rs`, `tests/policy_enforcement.rs`, `tests/proxy_e2e.rs`
- **Shared integration test helpers:** `tests/common/mod.rs`

```
src/
  policy.rs          ← inline #[cfg(test)] at bottom
  config.rs          ← inline #[cfg(test)] at bottom
tests/
  common/mod.rs      ← shared helpers
  policy_enforcement.rs
  config_validation.rs
  proxy_e2e.rs
```

**Module Visibility:**

Default to most restrictive visibility that compiles:

- `pub` — crosses module boundary as part of an intended external API
- `pub(crate)` — needed across modules but not external
- Private (no qualifier) — everything else

```rust
// CORRECT
pub(crate) struct AuditSender { ... }
pub fn is_tool_allowed(...) -> bool { }

// AVOID — over-exposing internals
pub struct InternalWriterState { ... }
```

---

### Format Patterns

**Error Messages:**

- Lowercase, no trailing punctuation
- Field names and paths in single quotes
- Include the problematic value where possible

```rust
// CORRECT
"invalid field 'allowed_tools': list cannot be empty"
"failed to read config file '/etc/mcp.toml': permission denied"

// AVOID
"Configuration error"
"Invalid config!"
```

**Exit Code Mapping:**

| Code | Meaning |
|------|---------|
| `0` | Clean shutdown or successful validation |
| `1` | Config error (user-fixable) |
| `2` | Runtime/transport error (infrastructure issue) |

---

### Communication Patterns

**Tracing Log Level Policy:**

| Level | Usage |
|-------|-------|
| `error!` | Unrecoverable; causes process exit or session abort |
| `warn!` | Recoverable; unexpected-but-handled condition |
| `info!` | Lifecycle events: startup, shutdown, connection open/closed |
| `debug!` | Internal state transitions useful during development |
| `trace!` | Per-message detail; disabled in release builds |

**Stdout vs Stderr:**

- `stdout` — exclusively for audit log JSON-Lines. No other output ever.
- `stderr` — all diagnostics (`tracing-subscriber` routes here automatically)
- `println!()` and `print!()` — **FORBIDDEN** in all production code

---

### Process Patterns

**`unwrap()` and `expect()` Policy:**

- `unwrap()` — **FORBIDDEN** in all non-test code. No exceptions.
- `expect()` — permitted only for programming invariants (cannot fail if code is
  correct), with a message stating the invariant:

```rust
// CORRECT — invariant documented
let sender = AUDIT_SENDER.get()
    .expect("audit sender must be initialized before the proxy loop starts");

// FORBIDDEN — runtime condition, not an invariant
let config = parse_toml(&content).expect("valid TOML");

// IN TESTS — unwrap() acceptable
let config = parse_config(path).unwrap();
```

**Async Function Policy:**

- `async fn` only when the function performs I/O or awaits futures
- Pure computation (e.g., all of `policy.rs`) must be plain `fn`
- Every `tokio::spawn` must have its `JoinHandle` captured and joined at shutdown

```rust
// CORRECT
pub fn is_tool_allowed(tool_name: &str, allowlist: &HashSet<String>) -> bool { ... }

// AVOID — unnecessary async on pure function
pub async fn is_tool_allowed(...) -> bool { ... }
```

**Clippy Configuration:**

Configured in `Cargo.toml` using the `[lints]` table (Rust 1.73+):

```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = "deny"
pedantic = "deny"
```

**Policy: fix first, suppress last.**

When a pedantic lint fires, fix the code. `#[allow(clippy::...)]` is a last resort,
used only when the lint fires on genuinely correct code that cannot be restructured.
Every `#[allow(...)]` requires a comment on the preceding line explaining why:

```rust
// CORRECT — justified allow
#[allow(clippy::large_enum_variant)]
// Variants differ in size but only one is constructed per instance; boxing would
// add a heap allocation on the hot path with no benefit.
pub enum AgentTransport { Stdio(StdioAgent), Http(HttpAgent) }

// FORBIDDEN — unexplained suppression
#[allow(clippy::too_many_arguments)]
pub fn setup(...) { ... }
```

**CI gate:** `cargo clippy -- -D warnings` (the `[lints]` table makes pedantic
warnings errors without additional flags needed at call sites).

---

### Enforcement Guidelines

**All AI agents MUST:**

- Use inline `#[cfg(test)]` modules for unit tests — never `src/*_test.rs`
- Use `snake_case` for all audit log JSON fields (public contract, no exceptions)
- Never write `unwrap()` in non-test production code
- Never write to `stdout` outside the audit writer task
- Never format a `secrecy::Secret<T>` without `.expose_secret()` (compiler enforces)
- Name error types `{Domain}Error` — never bare `Error`
- Fix clippy pedantic warnings; use `#[allow]` only with a justification comment

**Anti-Patterns:**

```rust
// NEVER: bare unwrap in production
let f = File::open(path).unwrap();

// NEVER: println! for any output
println!("{}", serde_json::to_string(&entry)?);

// NEVER: async on pure functions
pub async fn is_tool_allowed(...) -> bool { ... }

// NEVER: unexplained lint suppression
#[allow(clippy::cast_possible_truncation)]
let n = value as u32;

// NEVER: secret in tracing span
tracing::debug!(token = %config.auth.bearer_token, "connecting");
```

## Project Structure & Boundaries

### Complete Project Directory Structure

```
mcp-protector/
├── Cargo.toml                    ← binary manifest + [lints] table (clippy pedantic)
├── Cargo.lock                    ← committed; supply chain audit baseline
├── README.md
├── CHANGELOG.md                  ← versioned entries; required for schema breaking-change tracking
├── .gitignore
│
├── .github/
│   └── workflows/
│       ├── ci.yml                ← PR/push: check, test, clippy, cargo audit
│       └── release.yml           ← tag: cross-compile 5 targets, attach binaries
│
├── config/
│   └── example.toml              ← annotated example config (no real tokens)
│
├── docs/
│   ├── audit-log-schema.md       ← versioned JSON-Lines schema (public contract)
│   └── config-schema.md          ← versioned TOML config schema (public contract)
│
├── src/
│   ├── main.rs                   ← CLI entry point; subcommand dispatch; exit code mapping
│   ├── config.rs                 ← TOML parse + validate; typed config structs; ConfigError
│   ├── policy.rs                 ← pure allowlist functions; no state; PolicyError
│   ├── audit.rs                  ← LogEntry type; mpsc sender API; writer task; flush-on-shutdown
│   ├── proxy.rs                  ← session orchestration: agent ↔ policy ↔ upstream ↔ audit
│   ├── shutdown.rs               ← CancellationToken creation; SIGTERM/SIGINT wiring
│   └── transport/
│       ├── mod.rs                ← AgentTransport enum; UpstreamTransport enum
│       ├── agent_stdio.rs        ← agent-side stdio transport (StdioAgent)
│       ├── agent_http.rs         ← agent-side HTTP transport + GET /health (HttpAgent)
│       ├── upstream_stdio.rs     ← upstream stdio subprocess spawn (StdioUpstream)
│       └── upstream_https.rs     ← upstream HTTPS + bearer token injection (HttpsUpstream)
│
└── tests/
    ├── common/
    │   └── mod.rs                ← shared helpers: config builders, fixture paths
    ├── config_validation.rs      ← FR24–FR27: parse, validate, field-level errors
    ├── policy_enforcement.rs     ← FR5–FR9: allowlist logic, deny-on-empty, intersection
    ├── proxy_e2e.rs              ← FR1–FR4, FR10–FR13: end-to-end stdio proxy flow
    └── validate_config_cmd.rs    ← FR28–FR30: CLI subcommand, exit codes
```

**Note:** `target/` is gitignored. No `build.rs` unless cross-compilation requires it.

---

### FR Category to File Mapping

| FR Category | Files |
|---|---|
| FR1–FR4: Proxy Core | `proxy.rs`, `transport/mod.rs` |
| FR5–FR9: Policy Enforcement | `policy.rs`, `proxy.rs` (call sites) |
| FR10–FR13: Transport & Connectivity | `transport/agent_stdio.rs`, `transport/agent_http.rs`, `transport/upstream_stdio.rs`, `transport/upstream_https.rs` |
| FR14–FR15: Upstream Authentication | `transport/upstream_https.rs`, `config.rs` (Secret<String> field) |
| FR16–FR20: Audit Logging | `audit.rs`, `proxy.rs` (send sites) |
| FR21–FR23: Observability & Operations | `transport/agent_http.rs` (/health), `shutdown.rs`, `main.rs` |
| FR24–FR27: Configuration Management | `config.rs`, `main.rs` (validate-config subcommand) |
| FR28–FR30: CLI & Distribution | `main.rs`, `.github/workflows/release.yml` |

---

### Architectural Boundaries

**Config Boundary (`config.rs`):**

- `config.rs` owns all TOML parsing and validation
- No other module reads raw TOML or touches the config file path
- Other modules receive fully-typed structs; `Secret<String>` fields are opaque outside `transport/upstream_https.rs`

**Policy Boundary (`policy.rs`):**

- `policy.rs` exposes only pure functions — no structs, no state, no async
- `proxy.rs` calls policy functions directly; no other module does
- `HashSet<String>` allowlist is built once in `config.rs`, passed by reference to policy functions

**Audit Boundary (`audit.rs`):**

- `audit.rs` owns the `mpsc::Sender<LogEntry>` and the writer task
- `proxy.rs` holds a cloned sender; it sends log entries but never writes to stdout directly
- No module other than `audit.rs` may write to stdout

**Transport Boundary (`transport/`):**

- `proxy.rs` interacts only with `AgentTransport` and `UpstreamTransport` enums (defined in `transport/mod.rs`)
- Concrete transport structs (`StdioAgent`, `HttpAgent`, etc.) are private to their respective files
- `proxy.rs` has no `use transport::agent_stdio::StdioAgent` imports — only `use transport::AgentTransport`

**Shutdown Boundary (`shutdown.rs`):**

- `shutdown.rs` creates the root `CancellationToken` and installs OS signal handlers
- All other tasks receive `.child_token()` clones — they observe cancellation but cannot initiate it
- `main.rs` coordinates join ordering: agent listener → in-flight sessions → audit writer

---

### Integration Points

**rmcp (MCP protocol):**

- Integration in `transport/agent_stdio.rs`, `transport/agent_http.rs`, `transport/upstream_stdio.rs`, `transport/upstream_https.rs`
- `proxy.rs` works with rmcp message types but does not call rmcp transport APIs directly

**rustls / tokio-rustls (TLS):**

- Integration confined to `transport/upstream_https.rs`
- No other file configures or directly calls rustls APIs
- Root certificates via `rustls-native-certs` (system cert store) — see Decision 9

**tokio subprocess (upstream stdio):**

- Integration confined to `transport/upstream_stdio.rs`
- `Command::new()`, `stdin`/`stdout` piping — all in one file

---

### Data Flow

```
Agent connection (stdio or HTTP)
  │
  ▼
AgentTransport::receive_message()          [transport/agent_*.rs]
  │
  ▼
proxy.rs: match message type
  ├─ tools/list  → policy::filter_tools_list()   [policy.rs]
  │               → audit::send(ToolsList entry)  [audit.rs]
  │               → return filtered list to agent
  │
  └─ tools/call  → policy::is_tool_allowed()      [policy.rs]
                 → audit::send(ToolCall entry)    [audit.rs]
                 ├─ allowed  → UpstreamTransport::forward()  [transport/upstream_*.rs]
                 │             → response back to agent
                 └─ blocked  → error response to agent (no upstream call)
```

---

### CI/CD Structure

**`ci.yml` (runs on every PR and push to main):**

```
cargo check -q
cargo test -q
cargo clippy -- -D warnings        ← pedantic enforced via [lints] table
cargo audit -q
cargo llvm-cov --quiet             ← 100% branch coverage gate on policy.rs
```

**`release.yml` (runs on version tags `v*`):**

Cross-compile matrix for all 5 distribution targets:

| Target | Runner |
|---|---|
| `x86_64-unknown-linux-gnu` | ubuntu-latest |
| `aarch64-unknown-linux-gnu` | ubuntu-latest + cross |
| `x86_64-apple-darwin` | macos-latest |
| `aarch64-apple-darwin` | macos-latest |
| `x86_64-pc-windows-msvc` | windows-latest |

Artifacts: `mcp-protector-{target}.tar.gz` (Linux/macOS), `mcp-protector-{target}.zip` (Windows), attached to GitHub release.

---

### Schema Document Locations

Both public contracts live in `docs/` and are updated in the same PR as any schema change:

| File | Contains |
|---|---|
| `docs/audit-log-schema.md` | JSON-Lines field definitions, version history, breaking-change policy |
| `docs/config-schema.md` | TOML field definitions, version history, breaking-change policy |

## Architecture Validation Results

### Coherence Validation ✅

**Decision Compatibility:**

All 9 decisions compose without conflict:
- Enum dispatch (D2) × pure policy functions (D3) × mpsc audit channel (D6) — no shared
  mutable state; no contention on the hot path
- `CancellationToken` (D4) × audit writer drain (D6) — channel close triggers drain-then-flush;
  no race between shutdown and log completion
- `secrecy::Secret<String>` (D5) × tracing convention (never log secrets) — `Debug` suppression
  is compiler-enforced; `.expose_secret()` is the only escape hatch
- `thiserror` typed errors (D7) × clippy pedantic — `thiserror`-generated `Display` impls
  satisfy pedantic format string requirements without manual impl
- `LogEntry` serde schema (D8) × `snake_case` audit JSON pattern — Rust snake_case field names
  serialize to snake_case JSON by default; no `#[serde(rename)]` needed on common fields
- `rustls-native-certs` (D9) × rustls TLS constraint — native certs feed directly into
  `rustls::RootCertStore`; no openssl dependency introduced

**Pattern Consistency:**

- `[lints.clippy] pedantic = "deny"` + fix-first policy — mutually reinforcing; pedantic
  lints encourage the idiomatic patterns already chosen (e.g., explicit return types,
  `must_use`, iterator idioms)
- No `println!` rule + audit writer owns stdout — architecturally mutually enforcing;
  violating the rule is visible in code review and clippy catches some cases
- `unwrap()` forbidden + `thiserror` typed errors — typed errors make `?` propagation
  natural; no pressure to unwrap at intermediate layers

**Structure Alignment:**

All 9 decisions map to named files in the project tree. Boundary definitions (config,
policy, audit, transport, shutdown) are consistent with the module design.
FR-to-file mapping covers all 8 FR categories without overlap or gap.

---

### Requirements Coverage Validation ✅

**Functional Requirements (30 total):**

| FR Category | Architectural Coverage | Status |
|---|---|---|
| FR1–FR4: Proxy Core | `proxy.rs` + `transport/mod.rs` | ✅ |
| FR5–FR9: Policy Enforcement | `policy.rs` (pure fns) + `proxy.rs` (call sites) | ✅ |
| FR10–FR13: Transport & Connectivity | All 4 transport files | ✅ |
| FR14–FR15: Upstream Auth | `config.rs` (Secret<String>) + `upstream_https.rs` | ✅ |
| FR16–FR20: Audit Logging | `audit.rs` + `proxy.rs` + Decision 8 schema | ✅ |
| FR21–FR23: Observability & Operations | `agent_http.rs` (/health) + `shutdown.rs` | ✅ |
| FR24–FR27: Config Management | `config.rs` + validate-config in `main.rs` | ✅ |
| FR28–FR30: CLI & Distribution | `main.rs` + `release.yml` (5 targets) | ✅ |

**Non-Functional Requirements:**

| NFR | Architectural Coverage | Status |
|---|---|---|
| NFR-P1: ≤10ms p99 overhead | Enum dispatch (no dyn), mpsc non-blocking send | ✅ |
| NFR-P2: Async audit writes | Unbounded mpsc channel; send never blocks callers | ✅ |
| NFR-S1: TLS 1.2+ via rustls | `rustls` + `tokio-rustls` in `upstream_https.rs` | ✅ |
| NFR-S2: Credentials never in logs | `secrecy::Secret<String>`; Debug → `[REDACTED]` | ✅ |
| NFR-S3: No `unsafe` in policy layer | `[lints.rust] unsafe_code = "forbid"` | ✅ |
| NFR-S4: `cargo audit` clean | CI gate in `ci.yml` on every PR | ✅ |
| NFR-R1: No audit log loss on shutdown | CancellationToken + channel drain + flush | ✅ |
| NFR-R3: Fail-closed | Pure policy functions; no state drift possible | ✅ |
| NFR-C1: Case-sensitive byte comparison | `HashSet<String>::contains()` exact match | ✅ |
| NFR-M2: 100% branch coverage on policy | `cargo llvm-cov` gate in `ci.yml` | ✅ |
| NFR-M3: Versioned log schema | Decision 8 + `docs/audit-log-schema.md` | ✅ |

---

### Gap Analysis — Resolved

Three gaps identified and resolved during validation:

**Gap 1 (resolved): `anyhow` missing from dependency table**
Added to dep table. Required for `fn main() -> anyhow::Result<()>` (Decision 7).

**Gap 2 (resolved): Incomplete audit log schema**
Added Decision 8: full `LogEntry`/`LogEvent` type definitions, JSON examples for both
`tool_call` and `tools_list` events, session ID generation strategy (AtomicU64 counter),
and breaking-change policy for the public contract. `chrono` added to dep table.

**Gap 3 (resolved): TLS root certificate source undecided**
Added Decision 9: `rustls-native-certs` chosen for system cert store support (corporate
CA compatibility). `rustls-native-certs` added to dependency table.

**Nice-to-Have Gaps (deferred):**

| Gap | Deferred Until |
|---|---|
| MSRV (`rust-version` in Cargo.toml) | First release; pin to Rust stable at that time |
| `/health` response body format | Implementation of `agent_http.rs`; `{"status":"ok"}` is the obvious default |
| Startup log message wording | First implementation pass; `info!` level |

---

### Architecture Completeness Checklist

**✅ Requirements Analysis**
- [x] Project context thoroughly analyzed
- [x] Scale and complexity assessed
- [x] Technical constraints identified
- [x] Cross-cutting concerns mapped (6 concerns, all addressed)

**✅ Architectural Decisions**
- [x] 9 decisions documented with rationale, code examples, and affected files
- [x] Technology stack fully specified with dependency justifications
- [x] Integration patterns defined
- [x] Performance and security NFRs addressed

**✅ Implementation Patterns**
- [x] Naming conventions: error types, JSON fields, tracing spans, test functions
- [x] Structure: test placement, module visibility
- [x] Process: unwrap/expect policy, async function policy, clippy configuration
- [x] Communication: log level policy, stdout/stderr ownership

**✅ Project Structure**
- [x] Complete directory tree defined
- [x] All 9 source files named and described
- [x] Component boundaries established
- [x] FR-to-file mapping complete
- [x] CI/CD pipeline structure defined (ci.yml + release.yml)
- [x] Schema document locations defined

---

### Architecture Readiness Assessment

**Overall Status: READY FOR IMPLEMENTATION**

**Confidence Level: High**

The architecture is unusually concrete for a project of this size because:
1. Technology decisions were pre-determined by the PRD (Rust, tokio, rmcp, rustls, TOML)
2. The domain is narrow and well-specified (security proxy, not a general platform)
3. Correctness requirements are absolute (fail-closed, audit completeness) — ambiguity
   was resolved in favour of the stricter interpretation throughout

**Key Strengths:**

- Policy engine design (pure functions, `HashSet`, no state) makes 100% branch coverage
  trivially achievable and guarantees no runtime policy mutation
- `CancellationToken` + mpsc channel drain gives a clean, verifiable shutdown sequence
  with no audit log loss
- `secrecy::Secret<String>` enforces credential protection at compile time — not by convention
- Clippy pedantic with fix-first policy means code quality is enforced mechanically, not by review

**Areas for Future Enhancement (post-MVP):**

- Workspace split when policy engine needs to be embedded externally
- OAuth2 upstream auth
- Rate limiting per session
- Remote audit log forwarding

---

### Implementation Handoff

**First Implementation Step:**

```bash
cargo new --bin mcp-protector
cd mcp-protector
# Add all dependencies from the dep table to Cargo.toml
# Add [lints.rust] and [lints.clippy] table to Cargo.toml
```

**Implementation Order (from Decision Impact Analysis):**

1. `config.rs` — all other components depend on validated config
2. `policy.rs` — pure functions, no dependencies beyond config types
3. `audit.rs` — writer task needed before proxy sessions can log
4. `shutdown.rs` — CancellationToken must exist before tasks are spawned
5. `transport/` — each variant implemented; enum assembled in `mod.rs`
6. `proxy.rs` — orchestrates all of the above

**All agents must treat this document as the authoritative source for architectural
questions. Any deviation from a documented decision requires explicit discussion —
do not infer or improvise.**
