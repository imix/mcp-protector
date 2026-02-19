---
stepsCompleted: ['step-01-validate-prerequisites', 'step-02-design-epics', 'step-03-create-stories', 'step-04-final-validation']
status: 'complete'
completedAt: '2026-02-19'
inputDocuments:
  - '_bmad-output/planning-artifacts/prd.md'
  - '_bmad-output/planning-artifacts/architecture.md'
---

# mcp-protector - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for mcp-protector, decomposing the requirements from the PRD and Architecture into implementable stories.

## Requirements Inventory

### Functional Requirements

FR1: The proxy can forward MCP protocol messages transparently between a connected agent and the configured upstream MCP server without requiring any modification to the agent
FR2: The proxy can accept multiple concurrent agent connections on a single listener
FR3: The proxy can restrict each running instance to exactly one upstream MCP server
FR4: The proxy can reject agent connections using MCP protocol versions not supported by the rmcp library version in use
FR5: Operators can define a tool allowlist as a list of exact tool name strings in the config file
FR6: The proxy can filter tools/list responses from upstream, returning only tools whose names exactly match an entry in the allowlist and that exist on the upstream server (intersection of allowlist and upstream's actual tools)
FR7: The proxy can block tools/call requests for any tool name that does not exactly match an entry in the allowlist
FR8: The proxy can deny all tool calls when no allowlist entries are configured
FR9: The proxy can deny all tool calls when the config file is absent, empty, or unparseable (fail closed — no permissive fallback)
FR10: Agents can connect to the proxy via stdio
FR11: Agents can connect to the proxy via HTTP
FR12: The proxy can connect to an upstream MCP server by spawning and communicating with a local process via stdio
FR13: The proxy can connect to an upstream MCP server via HTTPS
FR14: Operators can configure a bearer token for authenticating outbound upstream HTTPS connections in the config file
FR15: The proxy can attach the configured bearer token to all outbound requests sent to the upstream MCP server
FR16: The proxy can emit a structured log entry for every tools/call request, recording: tool name, agent identifier, ALLOW or BLOCK decision, and timestamp
FR17: The proxy can emit a structured log entry for every tools/list request, recording: agent identifier and timestamp
FR18: The proxy can write all audit log entries to stdout in JSON-Lines format (one JSON object per line)
FR19: The proxy can write audit log entries for blocked calls regardless of how many times the agent retries the same call (entries are never suppressed)
FR20: Agents can identify themselves to the proxy via an identifier asserted at connection time, which the proxy records in audit log entries
FR21: The proxy can expose a GET /health endpoint returning HTTP 200 when operating in HTTP transport mode and ready to accept agent connections
FR22: The proxy can write all diagnostic output (startup confirmation, shutdown notice, errors) to stderr, keeping stdout reserved for audit log entries
FR23: The proxy can perform a graceful shutdown when it receives SIGTERM or SIGINT, completing in-flight requests before exiting
FR24: Operators can specify the path to the config file via a CLI flag on the proxy subcommand
FR25: The proxy can validate the complete config file before establishing any agent-side or upstream connections
FR26: The proxy can emit a human-readable error message to stderr identifying each invalid config field and the reason it is invalid
FR27: Operators can validate a config file and receive any errors without starting the proxy, using the validate-config subcommand
FR28: Operators can start the proxy using the mcp-protector proxy subcommand
FR29: The proxy can exit with code 0 on clean shutdown, 1 on config validation failure at startup, and 2 on unrecoverable runtime error
FR30: Operators can obtain a pre-compiled binary for Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64) from the project's GitHub Releases page

### NonFunctional Requirements

NFR-P1: The proxy must add no more than 10ms of latency (p99) to a tool call round-trip under normal operating conditions. The proxy must never be the bottleneck in a tool call workflow.
NFR-P2: Audit log writes must not block tool call processing. Log entries may be written asynchronously provided they are guaranteed to be flushed before graceful shutdown completes.
NFR-P3: The proxy must sustain correct policy enforcement under concurrent agent connections without degradation. Enterprise scale is achieved by running multiple instances; each instance is not required to support unbounded concurrency.
NFR-S1: All upstream HTTPS connections must use TLS 1.2 or higher, enforced via rustls. The proxy must not support TLS 1.0 or 1.1 and must not implement custom certificate validation logic.
NFR-S2: Bearer tokens, credentials, and authentication material must never appear in audit log output, diagnostic output, or error messages.
NFR-S3: The policy enforcement layer — tool name matching, allowlist lookup, and log writing — must contain no unsafe blocks.
NFR-S4: The binary must be built from a Cargo.lock that passes cargo audit with zero known vulnerabilities at the time of each release. cargo audit must run on every CI build.
NFR-S5: The proxy must not accept self-signed certificates from upstream servers unless explicitly configured to do so. Default behaviour is strict certificate validation.
NFR-R1: The proxy must not lose any in-flight audit log entries during graceful shutdown. All entries buffered at the time SIGTERM is received must be flushed to stdout before the process exits.
NFR-R2: The proxy must not crash on receipt of a malformed, unexpected, or protocol-violating message from the upstream MCP server. Such conditions must be logged to stderr and result in closure of the affected session, not process termination.
NFR-R3: The proxy must never enter a permissive state as a result of a runtime error. Any condition that prevents the policy from being evaluated must result in the tool call being blocked, not allowed.
NFR-R4: The proxy must not silently drop tool call requests. Every received tools/call request must produce either an ALLOW or BLOCK audit log entry, or a logged error entry explaining why neither was produced.
NFR-C1: Tool name matching must be case-sensitive exact string comparison with no normalisation. A tool name matches the allowlist entry if and only if the strings are byte-for-byte identical.
NFR-C2: Policy enforcement must produce identical results for identical inputs across all supported platforms (Linux, macOS, Windows). No platform-specific code paths may exist in the policy enforcement layer.
NFR-C3: The tools/list filtered response must contain only tools that are both present in the upstream server's actual tool list AND in the allowlist. A tool listed in the allowlist but not offered by the upstream must not appear in the filtered response.
NFR-M1: The Cargo dependency tree must be kept to the minimum required. Each direct dependency must be justified in a comment in Cargo.toml.
NFR-M2: The policy enforcement module must have 100% branch coverage in automated tests. Coverage is enforced as a CI quality gate.
NFR-M3: The audit log JSON-Lines format is a versioned public contract. Any change to field names, types, or required fields is a breaking change requiring a major version bump.
NFR-M4: The config file schema is a versioned public contract. Backwards-incompatible changes require a major version bump.

### Additional Requirements

- **Project foundation (Architecture Decision 1):** Initialize with `cargo new --bin mcp-protector`; flat module structure: main.rs, config.rs, policy.rs, audit.rs, proxy.rs, shutdown.rs, transport/ (mod.rs + 4 transport files)
- **Full dependency set (Architecture):** clap, tokio, rmcp, rustls+tokio-rustls, serde+serde_derive, toml, serde_json, tracing+tracing-subscriber, tokio-util, thiserror, secrecy, anyhow, chrono (serde feature), rustls-native-certs — each with Cargo.toml comment justification
- **Lint configuration (Architecture):** `[lints.rust] unsafe_code = "forbid"` and `[lints.clippy] all = "deny" pedantic = "deny"` in Cargo.toml
- **LogEntry/LogEvent schema (Architecture Decision 8):** Exact struct/enum definition with serde attributes; AtomicU64 session ID counter; flat JSON output matching public contract
- **secrecy::Secret<String> for bearer token (Architecture Decision 5):** Enforced at compile time; expose_secret() only at injection point in upstream_https.rs
- **CancellationToken shutdown wiring (Architecture Decision 4):** Root token in shutdown.rs, child tokens distributed to all tasks; defined drain sequence
- **mpsc audit channel (Architecture Decision 6):** Unbounded channel; writer task owns stdout; drain-then-flush on shutdown
- **rustls-native-certs TLS roots (Architecture Decision 9):** System cert store loaded at startup in upstream_https.rs
- **CI pipeline setup:** ci.yml (check, test, clippy -D warnings, cargo audit, llvm-cov 100% gate on policy.rs) and release.yml (5-target cross-compile matrix)
- **Schema documentation:** docs/audit-log-schema.md and docs/config-schema.md created alongside their implementation
- **Example config:** config/example.toml with annotated fields

### FR Coverage Map

| FR | Epic | Summary |
|---|---|---|
| FR1 | Epic 2 | Transparent MCP forwarding |
| FR2 | Epic 2 | Concurrent agent connections |
| FR3 | Epic 2 | Single upstream per instance |
| FR4 | Epic 2 | rmcp version rejection |
| FR5 | Epic 1 | Allowlist config definition |
| FR6 | Epic 2 | tools/list filtering (intersection) |
| FR7 | Epic 2 | tools/call blocking |
| FR8 | Epic 2 | Deny on empty allowlist |
| FR9 | Epic 1 | Fail-closed on bad/missing config |
| FR10 | Epic 2 | Agent stdio transport |
| FR11 | Epic 3 | Agent HTTP transport |
| FR12 | Epic 2 | Upstream stdio transport |
| FR13 | Epic 3 | Upstream HTTPS transport |
| FR14 | Epic 3 | Bearer token config |
| FR15 | Epic 3 | Bearer token attachment to upstream requests |
| FR16 | Epic 2 | tools/call audit entry |
| FR17 | Epic 2 | tools/list audit entry |
| FR18 | Epic 2 | stdout JSON-Lines output |
| FR19 | Epic 2 | Never suppress retry entries |
| FR20 | Epic 2 | Agent session identifier |
| FR21 | Epic 3 | GET /health endpoint |
| FR22 | Epic 2 | Diagnostics to stderr |
| FR23 | Epic 2 | Graceful SIGTERM/SIGINT shutdown |
| FR24 | Epic 1 | --config CLI flag |
| FR25 | Epic 1 | Validate config before connecting |
| FR26 | Epic 1 | Human-readable field-level errors |
| FR27 | Epic 1 | validate-config subcommand |
| FR28 | Epics 1+2 | CLI subcommand (skeleton E1, fully wired E2) |
| FR29 | Epics 1+2 | Exit codes (code 1 in E1, code 0/2 in E2) |
| FR30 | Epic 4 | Pre-compiled binaries on GitHub Releases |

## Epic List

### Epic 1: Project Foundation & Config System
Operators can initialize the project, write a TOML config file, validate it with field-level error messages, and run CI checks — all before any proxy is started.
**FRs covered:** FR5, FR9, FR24, FR25, FR26, FR27, FR28 (skeleton), FR29 (exit code 1)
**Additional:** Project initialization (cargo new), full dependency set with Cargo.toml justifications, [lints] table (unsafe_code = forbid; clippy pedantic), policy.rs pure functions, ci.yml pipeline (check/test/clippy/audit/llvm-cov 100% gate)

### Epic 2: Core Proxy with Stdio Transports
AI agents connecting via stdio can have their MCP tool requests transparently proxied to a stdio upstream server, with allowlist enforcement, complete audit logging, and graceful shutdown.
**FRs covered:** FR1, FR2, FR3, FR4, FR6, FR7, FR8, FR9 (runtime), FR10, FR12, FR16, FR17, FR18, FR19, FR20, FR22, FR23, FR28 (fully wired), FR29 (exit codes 0/2)
**NFRs addressed:** NFR-P1, NFR-P2, NFR-R1, NFR-R2, NFR-R3, NFR-R4, NFR-C1, NFR-C2, NFR-C3, NFR-M2 (coverage gate), NFR-M3 (log schema published)

### Epic 3: HTTP/HTTPS Transports & Authenticated Upstreams
Operators can deploy mcp-protector as a long-running HTTP service that connects to hosted MCP servers over HTTPS with bearer token authentication — suitable for container and enterprise deployment.
**FRs covered:** FR11, FR13, FR14, FR15, FR21, FR22 (tracing-subscriber fully configured)
**NFRs addressed:** NFR-S1, NFR-S2, NFR-S3, NFR-S5, NFR-P3

### Epic 4: Cross-Platform Distribution
Anyone can download a pre-compiled mcp-protector binary for their platform from GitHub Releases and start using it immediately.
**FRs covered:** FR30
**NFRs addressed:** NFR-S4 (cargo audit gate), NFR-M1 (dep justification review), NFR-M4 (config schema doc published)

---

## Epic 1: Project Foundation & Config System

Operators can initialize the project, write a TOML config file, validate it with field-level error messages, and run CI checks — all before any proxy is started.

### Story 1.1: Project Initialization and Repository Skeleton

As a developer,
I want the project initialized with all required dependencies, the lint configuration, and a compiling module skeleton,
So that every subsequent story builds on a correctly configured foundation with quality gates active from day one.

**Acceptance Criteria:**

**Given** a fresh workspace with `cargo new --bin mcp-protector` run and all dependencies from the architecture dependency table added to Cargo.toml with inline justification comments
**When** `cargo check` is run
**Then** it exits 0 with zero errors or warnings

**Given** Cargo.toml contains `[lints.rust] unsafe_code = "forbid"` and `[lints.clippy] all = "deny"` and `pedantic = "deny"`
**When** `cargo clippy -- -D warnings` is run on the initial stub files
**Then** it exits 0

**Given** stub files exist for every module defined in Architecture Decision 1: `src/main.rs`, `src/config.rs`, `src/policy.rs`, `src/audit.rs`, `src/proxy.rs`, `src/shutdown.rs`, `src/transport/mod.rs`, `src/transport/agent_stdio.rs`, `src/transport/agent_http.rs`, `src/transport/upstream_stdio.rs`, `src/transport/upstream_https.rs`
**When** `cargo build` is run
**Then** it succeeds

**Given** `Cargo.lock` is committed and `cargo audit` is run
**When** the audit completes
**Then** it exits 0 with zero known vulnerabilities

**Given** the repository root
**When** the directory is inspected
**Then** `.gitignore` excludes `target/`, `config/example.toml` exists with annotated placeholder fields, and `README.md` exists

**Given** `main.rs` is the entry point
**When** the binary starts (any subcommand)
**Then** `tracing_subscriber::fmt::init()` is called as the first statement, enabling INFO-level diagnostic output to `stderr` for all Epic 2 development (Story 3.4 will upgrade this to full RUST_LOG configuration)

---

### Story 1.2: Config File Parsing into Typed Structs

As an operator,
I want the proxy to read my TOML config file into typed Rust structs,
So that all subsequent components receive a fully typed, structured configuration rather than raw strings.

**Acceptance Criteria:**

**Given** a valid TOML config file with `[upstream]`, `[listen]`, and `[policy]` sections
**When** `config::load(path)` is called
**Then** it returns a typed `Config` struct with no errors

**Given** `upstream.url = "https://example.com/mcp"` in the config
**When** the config is parsed
**Then** the upstream variant is `UpstreamConfig::Https` with the URL preserved exactly

**Given** `upstream.url = "stdio"` in the config
**When** the config is parsed
**Then** the upstream variant is `UpstreamConfig::Stdio`

**Given** `[policy] allow = ["tool_a", "tool_b"]` in the config
**When** the config is parsed
**Then** the allowlist is stored as a `HashSet<String>` containing exactly `"tool_a"` and `"tool_b"`

**Given** `upstream.auth = { type = "bearer", token = "s3cr3t" }` in the config
**When** the config is parsed
**Then** the token is stored as `secrecy::Secret<String>` and the string `"s3cr3t"` does not appear in any `{:?}` debug-format output of the config struct

---

### Story 1.3: Config Validation with Field-Level Errors

As an operator,
I want invalid config fields to produce clear, human-readable error messages to stderr that identify exactly which field is wrong and why,
So that I can fix my configuration without guessing.

**Acceptance Criteria:**

**Given** a config with `listen.transport = "http"` but no `listen.port` field
**When** config validation runs
**Then** it returns a `ConfigError::InvalidField` naming `"listen.port"` with reason `"required when transport is 'http'"`

**Given** a config with `upstream.auth.type = "basic"` (unsupported auth type)
**When** config validation runs
**Then** it returns an error naming `"upstream.auth.type"` with reason containing `"unknown value 'basic'"`

**Given** a config with `listen.port = 99999` (exceeds max port)
**When** config validation runs
**Then** it returns an error naming `"listen.port"` with reason containing `"exceeds maximum"`

**Given** a config with `[policy] allow = []` (empty allowlist)
**When** config validation runs
**Then** it succeeds — an empty allowlist is valid (means block all; this is not a config error)

**Given** config validation finds multiple invalid fields
**When** the errors are reported to stderr
**Then** each invalid field produces a separate, human-readable error line (FR26: all errors reported, not just the first)

**Given** the config file does not exist at the specified path
**When** `config::load(path)` is called
**Then** it returns a `ConfigError::ReadFailed` with the file path and the OS error message

---

### Story 1.4: validate-config Subcommand

As an operator,
I want to run `mcp-protector validate-config --config <path>` to check my config file for errors without starting the proxy,
So that I can safely validate configs in CI pipelines and pre-deploy scripts.

**Acceptance Criteria:**

**Given** a valid config file at the specified path
**When** `mcp-protector validate-config --config path/to/config.toml` is run
**Then** it exits with code 0 and prints a confirmation to stderr (e.g., `Config is valid.`)

**Given** a config file with one or more validation errors
**When** `mcp-protector validate-config --config path/to/config.toml` is run
**Then** it exits with code 1 and all field-level errors are printed to stderr

**Given** the validate-config subcommand is run with any config (valid or invalid)
**When** the command executes
**Then** no upstream connections are attempted, no agent-side listener is started, and nothing is written to stdout

**Given** a missing config file
**When** `mcp-protector validate-config --config /nonexistent.toml` is run
**Then** it exits with code 1 and reports the missing file path to stderr

---

### Story 1.5: Policy Engine — Allowlist Enforcement Functions

As the proxy system,
I want pure functions that correctly determine whether a tool name is allowed or filtered from a list based on the configured allowlist,
So that policy decisions are deterministic, independently testable, and provably correct with 100% branch coverage enforced by CI.

**Acceptance Criteria:**

**Given** an allowlist containing `"read_file"`
**When** `is_tool_allowed("read_file", &allowlist)` is called
**Then** it returns `true`

**Given** an allowlist containing `"read_file"`
**When** `is_tool_allowed("execute_sql", &allowlist)` is called
**Then** it returns `false`

**Given** an empty `HashSet<String>` allowlist
**When** `is_tool_allowed("any_tool", &allowlist)` is called
**Then** it returns `false` (FR8: deny on empty allowlist)

**Given** an allowlist containing `"Read_File"` (capital R and F)
**When** `is_tool_allowed("read_file", &allowlist)` is called
**Then** it returns `false` (NFR-C1: byte-for-byte exact match; `"Read_File"` ≠ `"read_file"`)

**Given** an upstream tools list of `["read_file", "execute_sql", "delete_table"]` and an allowlist of `["read_file", "list_dir"]`
**When** `filter_tools_list(tools, &allowlist)` is called
**Then** it returns only `["read_file"]` — `"list_dir"` is excluded because it is not in the upstream list (NFR-C3: intersection, not allowlist alone); `"execute_sql"` and `"delete_table"` are excluded because they are not in the allowlist

**Given** `policy.rs` with its full test suite
**When** `cargo llvm-cov` is run targeting `policy.rs`
**Then** 100% branch coverage is reported with no uncovered branches

---

### Story 1.6: CI Pipeline

As a developer,
I want a CI pipeline that runs checks, tests, linting, security auditing, and branch coverage verification automatically on every PR,
So that code quality, security, and correctness are enforced mechanically without manual review.

**Acceptance Criteria:**

**Given** `.github/workflows/ci.yml` exists and a PR is opened against main
**When** the pipeline runs
**Then** it executes in sequence: `cargo check -q`, `cargo test -q`, `cargo clippy -- -D warnings`, `cargo audit -q`, `cargo llvm-cov --quiet`

**Given** any clippy pedantic warning exists in the codebase
**When** the CI pipeline runs
**Then** the pipeline fails and reports the violation

**Given** branch coverage on `policy.rs` is below 100%
**When** `cargo llvm-cov` runs in CI
**Then** the pipeline fails

**Given** a direct dependency with a known vulnerability is present in `Cargo.lock`
**When** `cargo audit` runs in CI
**Then** the pipeline fails

**Given** the pipeline passes all checks
**When** it completes
**Then** it exits 0 and no release artifact is triggered (release is a separate `release.yml` workflow)

---

## Epic 2: Core Proxy with Stdio Transports

AI agents connecting via stdio can have their MCP tool requests transparently proxied to a stdio upstream server, with allowlist enforcement, complete audit logging, and graceful shutdown.

### Story 2.1: Graceful Shutdown Orchestration

As the proxy system,
I want a shutdown module that installs SIGTERM and SIGINT handlers and distributes a `CancellationToken` to all long-running tasks,
So that the proxy can complete in-flight requests, flush audit logs, and exit cleanly on any termination signal (FR23, NFR-R1).

**Acceptance Criteria:**

**Given** `shutdown.rs` instantiates a root `tokio_util::sync::CancellationToken`
**When** `shutdown::install_handlers(root_token.clone())` is called at startup
**Then** receiving SIGTERM or SIGINT cancels the root token, and every holder of a child token observes cancellation within one tokio task-yield

**Given** child tokens are created via `root_token.child_token()` and passed to the audit writer task, agent listener, and upstream connector
**When** the root token is cancelled
**Then** all tasks that `select!` on `token.cancelled()` enter their shutdown branch before the process exits

**Given** `shutdown.rs` defines the drain sequence: (1) stop accepting new agent connections, (2) await current session tasks, (3) send flush signal to audit writer, (4) await writer task completion
**When** the drain sequence runs to completion
**Then** `main` receives all `JoinHandle` results and can determine the exit code

**Given** the proxy receives SIGTERM while one tools/call request is in flight
**When** the graceful drain completes
**Then** the in-flight request's audit log entry is flushed before the process exits (NFR-R1)

---

### Story 2.2: Audit Logging System

As the proxy system,
I want an audit module that accepts `LogEntry` values over an `mpsc` channel and writes them as JSON-Lines to the correct output stream,
So that every tool call decision is durably recorded without blocking the proxy session loop (NFR-P2, FR16, FR17, FR18, FR19, NFR-M3).

**Acceptance Criteria:**

**Given** `audit.rs` creates an `mpsc::unbounded_channel::<LogEntry>()` and spawns a writer task that owns the sending end
**When** `audit::send(entry)` is called from any proxy task
**Then** the entry is queued and the calling task is not blocked

**Given** the proxy is running in HTTP agent transport mode
**When** the writer task receives a `LogEntry`
**Then** it serializes it as a single JSON object followed by `\n` and writes it to **stdout** (FR18, FR22)

**Given** the proxy is running in stdio agent transport mode
**When** the writer task receives a `LogEntry`
**Then** it writes the JSON-Lines entry to **stderr** (stdout is reserved for the MCP protocol channel in stdio mode)

**Given** the `LogEntry` struct matches Architecture Decision 8: `version`, `timestamp` (ISO 8601), `session_id`, `upstream`, and `#[serde(flatten)] event: LogEvent`
**When** `serde_json::to_string(&entry)` is called
**Then** the output matches the public JSON contract defined in `docs/audit-log-schema.md` (NFR-M3)

**Given** no auth token, credential, or `secrecy::Secret` value is passed to `LogEntry`
**When** any log entry is serialized
**Then** `cargo grep -r "expose_secret"` in `audit.rs` returns no matches (NFR-S2)

**Given** the shutdown drain signal is received by the writer task
**When** the writer task processes the signal
**Then** it drains all remaining queued entries, calls `flush()` on the output stream, and exits its task loop — no entries are dropped (NFR-R1)

**Given** `docs/audit-log-schema.md` does not yet exist
**When** this story is completed
**Then** `docs/audit-log-schema.md` exists and documents the versioned JSON-Lines contract with field descriptions and example entries for both `tool_call` and `tools_list` event types (NFR-M3)

---

### Story 2.3: Stdio Agent Transport

As an AI agent,
I want to connect to mcp-protector over stdio,
So that I can use the proxy as a local MCP subprocess without any network configuration (FR10).

**Acceptance Criteria:**

**Given** `transport/agent_stdio.rs` implements an `AgentStdioTransport` that reads from `stdin` and writes to `stdout`
**When** the proxy starts with `listen.transport = "stdio"` in the config
**Then** the transport layer reads MCP protocol messages from `stdin` and writes responses to `stdout`

**Given** the stdio transport is active
**When** an MCP message arrives on `stdin`
**Then** it is decoded using the `rmcp` library and passed to the proxy session layer as a typed MCP request

**Given** the stdio transport is active and the proxy is in stdio agent mode
**When** the audit writer task is initialized
**Then** it is configured to write JSON-Lines to `stderr` (not stdout), preserving stdout exclusively for the MCP protocol channel (FR22)

**Given** the upstream connection returns an MCP response
**When** the response is forwarded to the agent
**Then** it is serialized by `rmcp` and written to `stdout` with no additional framing added by the transport

**Given** the agent closes its end of the stdio connection (EOF on stdin)
**When** the transport detects EOF
**Then** it cancels its child `CancellationToken`, triggering graceful shutdown of the associated session

---

### Story 2.4: Stdio Upstream Transport

As the proxy system,
I want to connect to an upstream MCP server by spawning it as a subprocess and communicating over its stdio,
So that the proxy can front local MCP tool servers without any network stack (FR12, NFR-R2).

**Acceptance Criteria:**

**Given** `transport/upstream_stdio.rs` implements an `UpstreamStdioTransport` that spawns a configured process via `tokio::process::Command`
**When** the proxy starts with `upstream.type = "stdio"` and `upstream.command` specified
**Then** the subprocess is spawned with its `stdin`/`stdout` piped to the proxy

**Given** the subprocess is running
**When** the proxy sends an MCP request upstream
**Then** it is written to the subprocess `stdin` using `rmcp` framing

**Given** the subprocess is running
**When** the subprocess writes an MCP response to its `stdout`
**Then** the proxy reads and decodes it using `rmcp` and passes it to the session layer

**Given** the upstream subprocess exits unexpectedly or writes a malformed message
**When** the transport layer detects the error
**Then** it logs the error to `stderr` (not audit log), closes the affected session, and does NOT panic or terminate the proxy process (NFR-R2)

**Given** the proxy receives a shutdown signal while communicating with the subprocess
**When** the shutdown drain runs
**Then** the subprocess receives SIGTERM (or is killed after timeout) and the transport task exits cleanly

---

### Story 2.5: Proxy Session Orchestration with Policy Enforcement

As the proxy system,
I want a session layer that wires agent transport, upstream transport, policy engine, and audit logger together,
So that every MCP message is correctly forwarded, filtered, or blocked according to the configured allowlist — with every decision audited (FR1–FR4, FR6–FR9, FR16–FR20).

**Acceptance Criteria:**

**Given** an agent connects and sends a `tools/list` request
**When** the session layer processes the request
**Then** it forwards the request upstream, receives the full tool list, passes it through `filter_tools_list(&config.policy.allow)`, returns only the intersection to the agent, and sends a `LogEvent::ToolsList` audit entry (FR6, FR17, NFR-C3)

**Given** an agent sends a `tools/call` request for a tool in the allowlist
**When** the session layer processes the request
**Then** it forwards the call upstream, returns the upstream response to the agent, and sends a `LogEvent::ToolCall { allowed: true }` audit entry (FR7, FR16)

**Given** an agent sends a `tools/call` request for a tool NOT in the allowlist
**When** the session layer processes the request
**Then** it does NOT forward the call upstream, returns an MCP error response to the agent, and sends a `LogEvent::ToolCall { allowed: false }` audit entry (FR7, FR16, NFR-R3)

**Given** the configured allowlist is empty (`allow = []`)
**When** any `tools/call` arrives
**Then** it is blocked and audited — `is_tool_allowed` returns `false` for all tools (FR8)

**Given** the agent asserts an identifier at connection time (FR20)
**When** audit entries are constructed
**Then** the agent's identifier is included in every `LogEntry` as the `session_id` field, sourced from the per-session `AtomicU64` counter as the fallback

**Given** the proxy is running and accepts multiple concurrent agent connections (FR2)
**When** two agents connect simultaneously and each sends a `tools/call`
**Then** both sessions are served concurrently, each with independent policy enforcement and separate audit entries

**Given** a non-`tools/list` and non-`tools/call` MCP message arrives (e.g., `resources/list`, `initialize`)
**When** the session layer receives it
**Then** it is forwarded transparently to the upstream and the response is returned to the agent without policy filtering (FR1)

**Given** the upstream returns an MCP protocol version that `rmcp` does not support
**When** the `initialize` handshake runs
**Then** the session is terminated with an appropriate error and the agent receives an MCP error response (FR4)

---

### Story 2.6: End-to-End Proxy Integration, Diagnostics, and Exit Codes

As an operator,
I want `mcp-protector proxy --config <path>` to start the fully wired proxy with correct startup diagnostics, and exit with the right code on any shutdown or error condition,
So that the binary is production-ready for stdio-to-stdio deployments (FR28, FR29, FR22).

**Acceptance Criteria:**

**Given** a valid config file
**When** `mcp-protector proxy --config path/to/config.toml` is run
**Then** it logs a startup confirmation to `stderr` (e.g., `mcp-protector started — transport: stdio, upstream: stdio`) and begins accepting agent connections (FR22)

**Given** the proxy starts and runs without errors, then receives SIGTERM
**When** the graceful drain completes
**Then** the process exits with code **0** (FR29)

**Given** the config file at the specified path fails validation at startup
**When** `mcp-protector proxy --config bad.toml` is run
**Then** all field-level errors are printed to `stderr` and the process exits with code **1** (FR29, FR25, FR26)

**Given** a runtime error occurs that prevents the proxy from continuing (e.g., the upstream transport fails unrecoverably, a required resource is unavailable)
**When** the error is detected
**Then** a descriptive error message is written to `stderr` and the process exits with code **2** (FR29, FR22)

**Given** the proxy is running in stdio-to-stdio mode with a valid upstream
**When** an end-to-end integration test sends a `tools/list` request followed by an allowed `tools/call` and a blocked `tools/call`
**Then** the agent receives the filtered tools list, the allowed call returns a result, the blocked call returns an MCP error, and three audit entries appear on `stderr` with correct `allowed` fields

**Given** the proxy subcommand is wired in `main.rs` via `clap`
**When** `mcp-protector --help` is run
**Then** both `proxy` and `validate-config` subcommands are listed with their `--config` flags

---

## Epic 3: HTTP/HTTPS Transports & Authenticated Upstreams

Operators can deploy mcp-protector as a long-running HTTP service that connects to hosted MCP servers over HTTPS with bearer token authentication — suitable for container and enterprise deployment.

### Story 3.1: HTTP Agent Transport and Health Endpoint

As an AI agent,
I want to connect to mcp-protector over HTTP,
So that I can use the proxy as a network service without spawning it as a subprocess (FR11, FR21).

**Acceptance Criteria:**

**Given** `transport/agent_http.rs` implements an HTTP listener that accepts MCP-over-HTTP connections on the configured `listen.port`
**When** the proxy starts with `listen.transport = "http"` and `listen.port = 3000`
**Then** it binds to `0.0.0.0:3000` and the startup diagnostic on `stderr` includes the bound address

**Given** the HTTP transport is active
**When** an MCP client sends a valid HTTP request to the proxy
**Then** the request is decoded via `rmcp`'s HTTP transport framing and handed to the proxy session layer

**Given** the proxy is running in HTTP mode and ready to accept connections
**When** `GET /health` is requested
**Then** it returns HTTP `200 OK` with body `{"status":"ok"}` and `Content-Type: application/json` (FR21)

**Given** the proxy is starting up but the upstream connection has not yet been established
**When** `GET /health` is requested
**Then** it returns HTTP `503 Service Unavailable` until the upstream handshake succeeds

**Given** the upstream connection returns an MCP response
**When** the response is forwarded to an HTTP-connected agent
**Then** it is serialized via `rmcp` and written as the HTTP response body with the appropriate MCP content type

**Given** the proxy is running in HTTP agent mode
**When** the audit writer task is initialized
**Then** it writes JSON-Lines to **stdout** (FR18, FR22) — stdout is not the MCP protocol channel in HTTP mode

---

### Story 3.2: HTTPS Upstream Transport with rustls

As the proxy system,
I want to connect to an upstream MCP server over HTTPS using `rustls` with system certificate roots,
So that the proxy secures all upstream traffic and works with corporate CAs out of the box (FR13, NFR-S1, NFR-S5, Architecture Decision 9).

**Acceptance Criteria:**

**Given** `transport/upstream_https.rs` initializes a `rustls::ClientConfig` using `rustls_native_certs::load_native_certs()` at startup
**When** the proxy starts with `upstream.url = "https://..."` in the config
**Then** the system certificate store is loaded and no hard-coded or bundled root CAs are used (Architecture Decision 9)

**Given** the upstream server presents a certificate signed by a CA in the system trust store
**When** the TLS handshake runs
**Then** it succeeds and the connection is established

**Given** the upstream server presents a self-signed certificate and no explicit override is configured
**When** the TLS handshake runs
**Then** it fails with a TLS error logged to `stderr`, the session is closed, and the proxy does NOT fall back to accepting the certificate (NFR-S5)

**Given** the `rustls` configuration is built
**When** a connection is established
**Then** TLS version negotiation results in TLS 1.2 or TLS 1.3; any server that only offers TLS 1.0 or 1.1 fails the handshake (NFR-S1)

**Given** the upstream connection is established over TLS
**When** MCP requests are sent
**Then** they are transmitted over the encrypted channel with no plaintext fallback path in `upstream_https.rs`

**Given** `upstream_https.rs` is inspected
**When** `cargo grep -n "unsafe"` is run against it
**Then** zero matches are found (NFR-S3 applies to all enforcement paths)

---

### Story 3.3: Bearer Token Authentication for Upstream HTTPS

As an operator,
I want to configure a bearer token that the proxy attaches to all outbound requests to the upstream HTTPS server,
So that the proxy can authenticate to hosted MCP services without exposing the token anywhere in logs or error output (FR14, FR15, NFR-S2, Architecture Decision 5).

**Acceptance Criteria:**

**Given** `upstream.auth = { type = "bearer", token = "my-secret-token" }` in the config
**When** `config::load(path)` parses the config
**Then** the token is stored as `secrecy::Secret<String>` with `zeroize`-on-drop; `format!("{:?}", config.upstream.auth)` does not contain `"my-secret-token"` (Architecture Decision 5)

**Given** the bearer token is configured
**When** the upstream HTTPS transport sends any request
**Then** `expose_secret()` is called exactly once per request at the injection point in `upstream_https.rs` to construct the `Authorization: Bearer <token>` header, and `expose_secret()` is not called from any other module

**Given** an upstream request is constructed with the bearer token header
**When** the request fails (e.g., 401 Unauthorized from the upstream)
**Then** the error logged to `stderr` contains the HTTP status code and upstream URL but NOT the bearer token value (NFR-S2)

**Given** a `tracing::debug!` or `tracing::error!` event is emitted during an upstream request
**When** the event fields are inspected
**Then** no field contains the raw bearer token string — token values are never passed as event fields or log arguments (NFR-S2)

**Given** no auth section is present in the config (`upstream.auth` is absent)
**When** the proxy connects to the upstream
**Then** requests are sent without an `Authorization` header and no error is produced — unauthenticated upstream is a valid configuration

---

### Story 3.4: Structured Tracing and Diagnostic Output

As an operator,
I want all proxy diagnostic output formatted as structured `tracing` events filtered by `RUST_LOG`,
So that I can control log verbosity in production and integrate proxy logs with standard log aggregation tooling (FR22).

**Acceptance Criteria:**

**Given** `tracing_subscriber::fmt` is initialized in `main.rs` before any other component starts
**When** the proxy runs without `RUST_LOG` set
**Then** it emits `INFO`-level and above events to `stderr` in human-readable format

**Given** `RUST_LOG=mcp_protector=debug` is set in the environment
**When** the proxy runs
**Then** `DEBUG`-level span events (session start, tool call decision, upstream connection lifecycle) are emitted to `stderr`

**Given** `RUST_LOG=mcp_protector=warn` is set in the environment
**When** the proxy runs normally with no errors
**Then** no diagnostic lines appear on `stderr`

**Given** a session starts (agent connects)
**When** the session span is entered
**Then** a `tracing::info!` event is emitted with fields: `transport`, `session_id`, `upstream`

**Given** the proxy shuts down
**When** the shutdown sequence completes
**Then** a final `tracing::info!` event is emitted to `stderr` with `event = "shutdown"` and the total session count (FR22)

**Given** tracing output is written
**When** the output stream is inspected
**Then** all tracing events go to `stderr`; the tracing subscriber is never configured to write to stdout (FR22 — stdout is reserved for audit log in HTTP mode)

---

### Story 3.5: HTTP/HTTPS End-to-End Integration and Concurrent Session Safety

As an operator,
I want the HTTP/HTTPS proxy mode validated end-to-end with concurrent agent connections,
So that the proxy is confirmed correct, safe, and performant before distribution (NFR-P3, NFR-S3).

**Acceptance Criteria:**

**Given** the proxy is running in HTTP agent mode with HTTPS upstream and bearer token configured
**When** an end-to-end integration test sends `tools/list`, an allowed `tools/call`, and a blocked `tools/call`
**Then** the agent receives the filtered tool list, the allowed call returns an upstream result, the blocked call returns an MCP error, and three audit entries appear on `stdout` with correct JSON structure

**Given** three concurrent agent sessions connect via HTTP
**When** each sends a simultaneous `tools/call` request (one allowed, one blocked, one for a non-existent tool)
**Then** all three sessions receive correct independent responses and three distinct audit log entries are written — no entries are interleaved or missing (NFR-P3, NFR-R4)

**Given** `policy.rs` with its complete test suite
**When** `cargo grep -rn "unsafe"` is run against `policy.rs`
**Then** zero matches are found (NFR-S3)

**Given** the upstream HTTPS server is unreachable (connection refused) at proxy startup
**When** the proxy attempts to connect
**Then** `GET /health` returns `503`, a descriptive error is logged to `stderr`, and the proxy does not panic

**Given** the proxy is running and the upstream HTTPS server drops the connection mid-request
**When** the transport detects the broken connection
**Then** the affected session is closed with an error logged to `stderr`, the audit entry for the interrupted request records the error, and other sessions are unaffected (NFR-R2)

---

## Epic 4: Cross-Platform Distribution

Anyone can download a pre-compiled mcp-protector binary for their platform from GitHub Releases and start using it immediately.

### Story 4.1: Cross-Platform Release Pipeline

As an operator,
I want pre-compiled mcp-protector binaries available on GitHub Releases for Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64),
So that I can install and run the proxy without a Rust toolchain (FR30).

**Acceptance Criteria:**

**Given** `.github/workflows/release.yml` exists and a semver tag (e.g., `v1.0.0`) is pushed to main
**When** the release pipeline triggers
**Then** it builds five targets in a matrix: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` — each producing a release binary

**Given** each matrix job builds its target binary
**When** the build completes
**Then** `cargo audit` is run against `Cargo.lock` and the job fails if any known vulnerability is present (NFR-S4)

**Given** all five matrix jobs succeed
**When** the pipeline uploads artifacts
**Then** a GitHub Release is created with the tag name, and each binary is attached as a release asset named `mcp-protector-<target>[.exe]`

**Given** the Linux aarch64 build runs on an x86_64 runner
**When** cross-compilation runs
**Then** the binary is produced via cross-compilation toolchain without requiring an aarch64 runner

**Given** the release workflow completes
**When** the GitHub Release page is viewed
**Then** each asset is downloadable and the release notes include the version and a link to `CHANGELOG.md`

---

### Story 4.2: Config Schema Documentation

As an operator,
I want `docs/config-schema.md` documenting every TOML config field with type, required/optional status, default value, and a valid example,
So that I can write a correct config file without reading source code (NFR-M4).

**Acceptance Criteria:**

**Given** `docs/config-schema.md` does not yet exist
**When** this story is completed
**Then** `docs/config-schema.md` exists and documents all fields in `[upstream]`, `[listen]`, and `[policy]` sections

**Given** a field is marked as required in `docs/config-schema.md`
**When** that field is omitted from a real config file and validated with `mcp-protector validate-config`
**Then** it produces a `ConfigError::InvalidField` for that field — confirming the schema doc matches the implementation (NFR-M4)

**Given** `upstream.auth.token` is documented in the schema
**When** the example value in `docs/config-schema.md` is inspected
**Then** the example uses a placeholder string (e.g., `"YOUR_TOKEN_HERE"`) and a note states the token is stored with `secrecy` and never logged (NFR-S2)

**Given** the config schema version is `1` (first stable release)
**When** `docs/config-schema.md` is read
**Then** it declares the schema version and states that backwards-incompatible changes require a major version bump (NFR-M4)

**Given** `config/example.toml` was created in Story 1.1
**When** `docs/config-schema.md` is completed
**Then** `config/example.toml` is updated to match the full schema (all sections, all optional fields with comments) and is validated by `mcp-protector validate-config` without error

---

### Story 4.3: Dependency Audit and Final Release Readiness

As a maintainer,
I want all direct Cargo dependencies to have an inline justification comment, and a final pre-release audit to confirm zero known vulnerabilities,
So that the dependency tree is intentional, reviewable, and clean at the point of first public release (NFR-M1, NFR-S4).

**Acceptance Criteria:**

**Given** `Cargo.toml` at the time of v1.0.0 tag creation
**When** every direct dependency entry is inspected
**Then** each has an inline comment stating its purpose (e.g., `# MCP protocol library`, `# async runtime`); no dependency is present without justification (NFR-M1)

**Given** `Cargo.lock` is up to date for the release commit
**When** `cargo audit` is run
**Then** it exits 0 with zero advisories at the `error` severity level (NFR-S4)

**Given** the release tag is created and the release pipeline completes
**When** the GitHub Release assets are downloaded on Linux x86_64, macOS aarch64, and Windows x86_64
**Then** on each platform, `mcp-protector --version` prints the correct semver version and `mcp-protector validate-config --config config/example.toml` exits 0

**Given** the README.md exists (created in Story 1.1)
**When** this story is completed
**Then** `README.md` contains: project description, installation instructions (binary download link), quickstart config example, and links to `docs/config-schema.md` and `docs/audit-log-schema.md`

