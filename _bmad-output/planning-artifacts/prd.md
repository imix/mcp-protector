---
stepsCompleted: ['step-01-init', 'step-02-discovery', 'step-02b-vision', 'step-02c-executive-summary', 'step-03-success', 'step-04-journeys', 'step-05-domain', 'step-06-innovation', 'step-07-project-type', 'step-08-scoping', 'step-09-functional', 'step-10-nonfunctional', 'step-11-polish']
inputDocuments: ['_bmad-output/planning-artifacts/product-brief-mcp-protector-2026-02-19.md']
workflowType: 'prd'
classification:
  projectType: 'cli_tool + security_proxy'
  domain: 'developer_security_tooling'
  complexity: 'medium-high'
  projectContext: 'greenfield'
---

# Product Requirements Document - mcp-protector

**Author:** Master
**Date:** 2026-02-19

## Executive Summary

mcp-protector is an open-source, Rust-native security proxy for the Model Context
Protocol (MCP). It sits transparently between AI agents and MCP servers, enforcing
a statically configured tool whitelist and audit logging. Agents
connect via stdio or HTTP; mcp-protector connects upstream via stdio or HTTPS with
bearer token authentication. From the agent's perspective, it is communicating
directly with the MCP server — only the permitted tool surface is visible.

**Problem:** MCP has no access control primitives. An agent connecting to an MCP
server can call any tool the server exposes. This creates three concrete risks:
(1) runaway or prompt-injection-manipulated agents executing destructive tools,
(2) malicious or compromised MCP servers advertising tools designed to subvert
agent behaviour, and (3) no audit trail for enterprise compliance or incident
response.

**Target users:** Primary — solo developers using AI coding assistants (Claude Code,
Cursor, Codex) who want to connect third-party MCP servers safely without deep
security expertise. Secondary — platform and security engineers at enterprises
deploying AI agents at scale, who require policy enforcement, OAuth2 integration,
and compliance-grade audit logging.

**MVP scope:** Tool whitelisting (deterministic name-pattern matching, zero false
positives/negatives), agent-side stdio and HTTP transports, upstream stdio and
HTTPS with bearer token auth, local audit logging, single upstream server per
instance. Binary distribution for Linux, macOS, Windows. No schema inspection,
no config generator, no rate limiting, no OAuth2 upstream auth in MVP.

### What Makes This Special

No purpose-built MCP security proxy exists. mcp-protector is a category-defining
tool entering an ecosystem gap, not a crowded market.

**Transparency:** The proxy is invisible to the agent. No SDK changes, no agent
modifications, no new abstractions — drop the binary between agent and server,
write a config, done.

**Correctness by design:** Whitelist enforcement is deterministic exact-name
matching. There is no probabilistic component, no fuzzy logic, no exceptions.
A tool is either on the list or it is blocked. This property is testable,
auditable, and provable.

**Rust:** Not a marketing choice. Memory safety eliminates an entire class of
vulnerabilities at the proxy enforcement boundary. The codebase is minimal and
auditable — the community can verify the security guarantees.

**Zero-trust by default:** The secure posture requires no configuration. An
unconfigured instance blocks everything. Permissions are additive, not
subtractive.

**Timing:** The MCP ecosystem is in its formative phase. Tools and conventions
established now become defaults. A correct, minimal, well-published tool released
today can become the baseline assumption for responsible MCP integration before
alternatives consolidate.

## Success Criteria

### User Success

| Criterion | Target |
|---|---|
| **Onboarding speed** | Developer reaches first protected agent session within 5 minutes of downloading the binary, using a hand-written config file |
| **Whitelist correctness** | Zero false positives (whitelisted tool blocked); zero false negatives (blocked tool callable). Enforcement is exact name-pattern matching — binary and deterministic |
| **Config iteration** | Adding or removing a tool requires one config change and a proxy restart; achievable in under 30 seconds |
| **Audit legibility** | Every tool call — allowed or blocked — is recorded with: tool name, agent identifier, allow/block decision, timestamp. Sufficient to reconstruct any incident |
| **Transparent integration** | Agent configuration change is limited to replacing the upstream MCP server URL with the mcp-protector endpoint. No agent-side code changes required |

### Business Success

As an open-source project, business success is community adoption and ecosystem
integration:

- **Ecosystem presence:** mcp-protector is referenced or recommended in the
  documentation of 5+ independent MCP server projects within 6 months of launch.
  This is the primary adoption signal.
- **Download velocity:** Hundreds of binary downloads per day across distribution
  channels within 3 months of launch.
- **Community positioning:** Recognised and recommended in AI developer communities
  (Hacker News, relevant Discord/Slack servers, Reddit) as the default approach to
  responsible MCP integration.
- **Long-term:** Referenced in official MCP specification or tooling documentation
  as a recommended security companion.

### Technical Success

- **Policy correctness rate:** 0% — no unintended tool calls pass through; no
  legitimate whitelisted calls are blocked. This is a hard requirement, not a target.
- **Test coverage:** 100% of policy enforcement paths covered by automated tests
  before any release. CI must be green across all target platforms.
- **Latency overhead:** Proxy adds ≤10ms latency (p99) to tool calls — it must not
  become the bottleneck in any agent workflow. See NFR-P1.
- **Memory safety:** Rust implementation eliminates memory-unsafety vulnerabilities
  at the enforcement boundary. No CVEs attributable to memory corruption.
- **Binary availability:** Cross-compiled binaries available for Linux (x86_64,
  aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64) on every release.

### Measurable Outcomes

| Outcome | Measurement Method | Target |
|---|---|---|
| Whitelist correctness | Automated integration tests with allow/deny scenarios | 100% pass rate, all releases |
| Onboarding time | User testing with fresh install + manual config | ≤ 5 minutes |
| Ecosystem adoption | GitHub references, dependent repos | 5+ repos within 6 months |
| Download velocity | GitHub releases + package manager download counts | 100s/day within 3 months |
| CI health | All tests green across Linux, macOS, Windows | 100% before any release tag |

## Product Scope

### MVP — Minimum Viable Product

**Core proxy engine:**
- MCP protocol parsing and transparent proxying
- Agent-side transports: stdio, HTTP
- Upstream transports: stdio, HTTPS with bearer token authentication
- One upstream MCP server per instance (blast radius isolation)

**Policy enforcement:**
- Static TOML/YAML config file
- Tool whitelist: exact name-pattern matching
- Default-deny: all tools blocked unless explicitly listed
- Applied to both `tools/list` responses (advertisement) and `tools/call`
  requests (execution)

**Audit logging:**
- Structured log output (local file or stdout)
- Per-call entries: timestamp, tool name, agent identifier, decision (allow/block)

**Distribution:**
- Pre-compiled binaries: Linux (x86_64, aarch64), macOS (x86_64, arm64),
  Windows (x86_64)
- GitHub Releases as primary distribution channel

**Out of scope for MVP:** schema/argument inspection, interactive config generator,
OAuth2 upstream auth, rate limiting, remote log forwarding, agent plugin integrations,
multi-server aggregation. See Project Scoping & Phased Development for the full
post-MVP roadmap.

## User Journeys

### Journey 1: Alex — First Contact (Primary User, Success Path)

**Opening Scene:** Alex is setting up a Supabase MCP server for a side project.
The agent is Claude Code. Alex pastes the Supabase MCP URL into `~/.claude/mcp.json`,
restarts Claude Code, and immediately feels uneasy: the agent now has access to
`execute_sql`, `delete_table`, `create_user`, and 23 other tools. Alex doesn't want
the agent anywhere near write operations but has no way to say so.

**Rising Action:** Alex finds mcp-protector on GitHub. The README tagline lands
immediately: "Zero-trust firewall for MCP — your agent only sees what you allow."
Alex downloads the Linux binary, skims the config example in the README, and writes
a 12-line TOML file:

```toml
[upstream]
url = "https://supabase-mcp.example.com/mcp"
auth = { type = "bearer", token = "$SUPABASE_TOKEN" }

[listen]
transport = "http"
port = 8080

[policy]
allow = ["select_data", "list_tables", "get_schema"]
```

Alex updates `mcp.json` to point at `http://localhost:8080` instead of the Supabase
endpoint. Restarts Claude Code. Total time: 4 minutes.

**Climax:** The agent tries to call `execute_sql` to run a migration. The call never
reaches Supabase. Alex opens the audit log: `BLOCKED | execute_sql | agent=claude-code
| 2026-02-19T14:32:01Z`. The whitelist worked. The agent did exactly what Alex feared
it might — and mcp-protector stopped it silently.

**Resolution:** Alex adds `execute_sql` to the whitelist when migration work actually
begins. Config change, restart, done in 20 seconds. The audit log is now Alex's
incident history. Every agent session is recorded. Alex's new default for every MCP
server: proxy it first.

**Requirements revealed:** config file parsing, bearer token upstream auth, HTTP
agent transport, stdio upstream transport, `tools/list` filtering, `tools/call`
blocking, structured local audit log.

---

### Journey 2: Alex — Debugging a Broken Workflow (Primary User, Edge Case)

**Opening Scene:** Alex's CI pipeline uses an agent to run database queries via the
Supabase MCP server through mcp-protector. The pipeline starts failing silently —
the agent reports tool calls succeeding, but no data is coming back. Alex suspects
the agent is calling a tool that got renamed in a Supabase update.

**Rising Action:** Alex tails the mcp-protector audit log. Immediately visible:
`BLOCKED | query_rows | agent=ci-agent | 2026-02-19T09:17:44Z`. The upstream MCP
server renamed `select_data` to `query_rows` in its latest release. The whitelist
still references the old name. mcp-protector is blocking the new tool name —
correctly, because it's not whitelisted.

**Climax:** Alex updates the config: removes `select_data`, adds `query_rows`.
Restart. The pipeline passes. The audit log shows `ALLOW | query_rows` on the
next run.

**Resolution:** What could have been an hours-long debugging session took 3 minutes
with the audit log. Alex files an issue against the Supabase MCP package asking
them to maintain stable tool names. The audit log surfaced a real upstream change
that would have been invisible without it.

**Requirements revealed:** blocked-call log entries with sufficient detail to
diagnose mismatches, exact tool name matching (no fuzzy/partial), easy config
update cycle.

---

### Journey 3: Dana — Enterprise Rollout (Secondary User, Operations Path)

**Opening Scene:** Dana's team at a fintech company has approved a pilot: three
development squads will use AI coding assistants connected to internal MCP servers
(code analysis, ticket lookup, read-only DB query). Security requires: no write
operations, full audit trail, agents cannot call tools outside the approved list.
Dana is responsible for the deployment.

**Rising Action:** Dana reviews the mcp-protector README and architecture. The
single-instance-per-upstream model maps cleanly to the security requirement: one
proxy per MCP server, each with its own policy file and isolated blast radius.
Dana writes three config files — one per MCP server — each with explicit tool
allowlists. The proxies are deployed as Kubernetes sidecars alongside each MCP
server pod. Audit logs go to stdout, captured by the cluster's log aggregation
stack.

Dana configures the agent-side HTTP endpoints in each squad's agent config. No
squad member needs to understand mcp-protector internals — they just point their
agent at the approved endpoint.

**Climax:** Two weeks into the pilot, a security review requires evidence that no
agent called a write tool. Dana queries the log aggregation system for `BLOCKED`
entries on write-category tools. Result: 14 blocked attempts across the three
squads, all `BLOCKED`, none reaching the upstream servers. The report writes itself.

**Resolution:** The pilot passes security review. Dana proposes expanding to all
squads. The config files are version-controlled in the infrastructure repo. Policy
changes go through the normal PR review process — same as any other security config.

**Requirements revealed:** HTTP agent transport (for central deployment), structured
log output compatible with log aggregation pipelines, per-instance config files,
stable binary for containerised deployment, default-deny enforced at `tools/list`
and `tools/call`.

---

### Journey 4: Dana — Incident Investigation (Support/Troubleshooting Path)

**Opening Scene:** A squad lead reports that their agent "stopped working" after a
routine infrastructure update. The agent is returning errors when trying to call
the ticket-lookup MCP server.

**Rising Action:** Dana checks the mcp-protector audit log for the ticket-lookup
proxy instance. The log shows `ALLOW` entries up until the infrastructure update
timestamp, then nothing — no entries at all. Not blocked, not allowed: silence.
The proxy isn't receiving calls. Dana checks the agent's config: the infrastructure
update changed the internal service hostname. The agent's config still references
the old hostname, so it's not connecting to the proxy at all.

**Climax:** Dana updates the agent config to use the new hostname. Immediately,
`ALLOW | get_ticket | agent=squad-b-agent` entries appear in the log. The agent
is working.

**Resolution:** The audit log's gap in entries — not a block, not an allow, just
silence — was the key diagnostic signal. Dana adds a monitoring alert: if a proxy
instance receives zero calls for more than 10 minutes during business hours, page
the on-call engineer. The log becomes an operational health signal, not just a
security record.

**Requirements revealed:** Continuous log output (not just on-error), log entries
with enough context to establish baseline and detect anomalies, stable and
predictable log format for monitoring integration.

---

### Journey Requirements Summary

| Capability | Revealed By |
|---|---|
| Config file parsing (TOML/YAML) | Journey 1 |
| Bearer token upstream auth | Journey 1 |
| HTTP agent-side transport | Journeys 1, 3, 4 |
| Stdio agent-side transport | All journeys (implied) |
| Stdio + HTTPS upstream transport | All journeys |
| `tools/list` response filtering | Journeys 1, 3 |
| `tools/call` request blocking | Journeys 1, 2, 3 |
| Structured local audit log (ALLOW + BLOCKED) | All journeys |
| Exact tool-name matching | Journeys 1, 2 |
| Default-deny policy | Journeys 1, 3 |
| Per-instance config isolation | Journey 3 |
| Stable binary for container deployment | Journey 3 |
| Log output to stdout (aggregation-compatible) | Journeys 3, 4 |
| Continuous log output (not just on-error) | Journey 4 |

## Domain-Specific Requirements

### Security Correctness Constraints

- **Policy enforcement must be provably correct.** Whitelist checking is not
  "best effort" — 100% of enforcement paths must be covered by automated tests.
  A single bypass is a product failure, not a bug.
- **Fail closed, never fail open.** An empty, missing, or malformed config must
  block all tool calls. The secure state is the default state. mcp-protector must
  never start in a permissive mode due to a config error.
- **Protocol edge case resistance.** Tool name matching must handle MCP protocol
  edge cases that could be used to bypass the whitelist: Unicode normalisation,
  case sensitivity, whitespace padding, null bytes. The matching algorithm must
  be defined explicitly and tested against known bypass patterns.

### Trust Boundary Constraints

- **Upstream is untrusted.** The proxy sits at a security boundary between the
  agent and an external system. A malicious or compromised MCP server could send
  crafted `tools/list` responses. All upstream responses must be filtered — the
  agent never receives raw upstream output.
- **Agent identity is unverified in MVP.** mcp-protector does not authenticate
  agents in the MVP. Agent identifiers in audit logs are asserted by the connecting
  agent and should be treated as advisory, not authoritative. This limitation must
  be documented clearly in the README and considered for post-MVP design.
- **Config is the only trust root.** The policy enforced is exactly what is in
  the config file — no dynamic updates, no remote overrides, no runtime mutation.
  This is a deliberate security property.

### Auditability Constraints

- **Blocked calls are always logged.** No agent or upstream behaviour can suppress
  a log entry for a blocked call. The log is append-only from mcp-protector's
  perspective — once written, entries are not modified or deleted.
- **Log format stability.** The structured log format is a public contract, versioned
  with the binary. Breaking changes to log format require a major version bump.
  Downstream monitoring pipelines depend on field names and structure being stable.
- **Log completeness.** Every `tools/call` request and every `tools/list` request
  must produce a log entry — not just policy violations. Silence in the log means
  no calls were received, not that calls were suppressed.

### Supply Chain Constraints

- **Minimal dependency surface.** The Cargo dependency tree must be kept small and
  auditable. Each new dependency requires justification. Security-critical crates
  (TLS, cryptography) must be well-established crates with active maintenance.
- **Reproducible builds.** Releases must publish SHA-256 checksums alongside
  binaries. Reproducible builds are a goal for future releases.
- **Cargo.lock committed.** The lock file is committed to the repository and updated
  deliberately — not auto-updated on build. This ensures dependency versions are
  explicit and auditable.

## Innovation & Novel Patterns

### Detected Innovation Areas

**1. Category Creation — The First MCP Security Proxy**

mcp-protector does not compete in an existing market. No purpose-built security
proxy for the Model Context Protocol exists at the time of writing. This is not an
incremental improvement to a known tool category — it is the first instance of the
category. The innovation is the category itself.

This carries both opportunity and responsibility: the design decisions made in
mcp-protector's first release will likely influence how the broader ecosystem
thinks about MCP security. Being first means being the reference implementation.

**2. Zero-Trust Applied to AI Agent Tool Access**

Zero-trust network architecture is a well-established paradigm in infrastructure
security. mcp-protector is the first application of zero-trust principles
specifically to AI agent tool access: default-deny, explicit allowlist, every
call logged, no implicit trust of any party (not the agent, not the upstream server).

The innovation is not inventing zero-trust — it is recognising that AI agent tool
access is a trust boundary that needs the same treatment as network boundaries,
and being the first to build the enforcement point.

**3. Transparent Security Layer Without Agent Modification**

Existing approaches to constraining agent behaviour (system prompt instructions,
agent-side guardrails, MCP server self-restriction) all require modifying either
the agent or the server. mcp-protector introduces a third option: a transparent
proxy layer that enforces policy without touching either end. This is architecturally
novel in the AI agent security space.

**4. Timing: Becoming the Default Before Alternatives Consolidate**

The MCP ecosystem is in a formative phase. Conventions and tools established now
become defaults. A minimal, correct, well-published tool released early has
disproportionate influence on how the ecosystem evolves. The innovation here is
not technical alone — it is strategic: building the right thing at the right moment
to shape ecosystem norms.

### Market Context & Competitive Landscape

The MCP protocol was introduced by Anthropic in late 2024 and has seen rapid
adoption across AI coding assistants (Claude Code, Cursor, Codex) and third-party
server providers (Supabase, GitHub, Notion, and many others) through 2025.

As of early 2026:
- No dedicated MCP security layer exists in the ecosystem
- Security-conscious developers resort to: not connecting risky servers, hoping
  agents behave, or writing custom wrappers around individual MCP servers
- The MCP specification itself has no access control primitives
- Enterprise AI agent adoption is accelerating demand for audit trails and policy
  enforcement

The window to establish mcp-protector as the default is open now. It narrows as
the ecosystem matures and alternatives emerge.

### Validation Approach

**Correctness validation:**
- Automated integration tests against a mock MCP server covering all allow/block
  scenarios, protocol edge cases, and transport combinations
- Fuzz testing of the MCP protocol parser and tool name matcher
- Community audit: open source the codebase and invite security researchers to
  find bypasses (responsible disclosure policy in README)

**Adoption validation:**
- Measure: is mcp-protector referenced in MCP server READMEs within 3 months?
- Measure: are developers recommending it in AI dev communities?
- Qualitative: does the README's one-sentence value proposition land immediately?

**Ecosystem influence validation:**
- Does the MCP specification eventually reference access control patterns
  established by mcp-protector?
- Do competing tools adopt the same default-deny, exact-match paradigm?

### Risk Mitigation

| Innovation Risk | Mitigation |
|---|---|
| **Protocol changes invalidate the proxy** | Track MCP spec releases; maintain a compatibility matrix; design the protocol layer as a replaceable component |
| **Anthropic or a major player builds an official MCP security layer** | Open source positioning means mcp-protector can be adopted as the community standard or merged upstream; the goal is ecosystem security, not ownership |
| **False sense of security** | README must clearly document what mcp-protector does NOT protect against (agent identity, prompt injection in tool arguments, etc.) to prevent misuse |
| **Ecosystem fragmentation** | Publish a clear config format spec so compatible implementations can emerge; avoid proprietary lock-in |

## CLI Tool & Security Proxy — Specific Requirements

### Project-Type Overview

mcp-protector is distributed and operated as a compiled binary with a subcommand
CLI structure. It functions as a long-running security proxy process. The CLI
surface covers both runtime operation and operational tooling (config generation,
validation). The proxy itself has no interactive UI — all configuration is
file-based or network-delivered.

### Command Structure

Subcommand-based CLI:

```
mcp-protector <subcommand> [options]
```

**MVP subcommands:**

| Subcommand | Description |
|---|---|
| `mcp-protector proxy --config <path>` | Start the proxy with the specified config file. Validates config on startup; exits with error if invalid. |
| `mcp-protector validate-config --config <path>` | Parse and validate config file, print errors, exit. Does not start the proxy. Useful for CI and pre-deploy checks. |

**Post-MVP subcommands:**

| Subcommand | Description |
|---|---|
| `mcp-protector init <upstream-url>` | Interactive config generator: connects to upstream, enumerates tools, writes config file |

### Config Schema

**Bootstrap config (MVP):**

A single TOML file. Validated on startup before any network connections are
attempted. Invalid config = non-zero exit with a human-readable error message
pointing to the offending field.

Minimum required fields:
```toml
[upstream]
url = "https://example.com/mcp"        # or "stdio" for local process
auth = { type = "bearer", token = "…" } # or omit for unauthenticated

[listen]
transport = "http"   # or "stdio"
port = 8080          # required for http transport

[policy]
allow = ["tool_a", "tool_b"]  # exact tool names; empty list = block all
```

**Enterprise config delivery (post-MVP):**

In enterprise deployments, the full policy config is pushed to the proxy via a
secured network connection. The local config file is reduced to a minimal bootstrap
config containing only the information needed to establish the config delivery
channel (e.g., mTLS certificates, config server URL, instance identity). The proxy
starts with bootstrap config, establishes the config channel, and receives its full
policy config before opening agent-side connections.

This enables centralised policy management without distributing full policy files
to each proxy instance. Design is deferred to post-MVP; the bootstrap/full-config
separation should be kept in mind when designing the config schema to avoid
breaking changes.

### Output Formats

**Audit log (structured, append-only):**

One JSON-Lines entry per tool call:
```json
{"ts":"2026-02-19T14:32:01Z","decision":"BLOCK","tool":"execute_sql","agent":"claude-code","transport":"http"}
{"ts":"2026-02-19T14:32:02Z","decision":"ALLOW","tool":"select_data","agent":"claude-code","transport":"http"}
```

Written to stdout by default; redirectable to file via shell. Log format is a
versioned public contract — field names and structure are stable across patch and
minor releases; breaking changes require a major version bump.

**Diagnostic output (stderr):**

Startup messages, config validation errors, and shutdown messages go to stderr.
This keeps stdout clean for log pipeline consumption.

**Config validation output:**

Human-readable errors to stderr:
```
Error: invalid config at 'listen.port': value 99999 exceeds maximum port 65535
Error: invalid config at 'upstream.auth.type': unknown value 'basic' (expected: bearer)
```

### Scripting & Automation Support

mcp-protector is designed to be run unattended in CI, containers, and service
managers (systemd, Kubernetes).

**Exit codes:**

| Code | Condition |
|---|---|
| `0` | Clean shutdown (SIGTERM received and handled) |
| `1` | Config parse/validation error on startup |
| `2` | Runtime fatal error (unrecoverable proxy failure) |
| Non-zero | Panic or unexpected termination |

**Signal handling:**
- `SIGTERM`: graceful shutdown — drain in-flight requests, flush audit log, exit 0
- `SIGINT`: same as SIGTERM (for interactive dev use)

**Healthcheck:** An HTTP transport instance exposes `GET /health` returning `200 OK`
when the proxy is ready. Useful for Kubernetes readiness probes.

### MCP Protocol Version Support

mcp-protector uses **rmcp** as its MCP protocol library. Version negotiation and
compatibility enforcement follow rmcp's behaviour: unknown or unsupported MCP
protocol versions are rejected at the connection level. mcp-protector does not
implement custom version negotiation on top of rmcp — it inherits rmcp's
compatibility matrix.

MCP protocol versions are date-strings (e.g., `2024-11-05`). The supported
version range is determined by the rmcp version pinned in `Cargo.lock`. This is
documented in the release notes for each mcp-protector release.

### Implementation Considerations

- **Fail early:** Config is validated completely before any upstream or agent
  connections are attempted. A proxy that starts with a bad config and silently
  fails later is worse than one that refuses to start.
- **Shell completion:** Deferred to post-MVP. The subcommand structure should be
  designed to be compatible with clap's `generate` completion support for future
  addition without CLI breaking changes.
- **Single responsibility:** Each binary invocation does one thing. No background
  daemons, no auto-reload of config — explicit restarts for config changes keep
  the operational model simple and auditable.

## Project Scoping & Phased Development

### MVP Strategy & Philosophy

**MVP Approach:** Problem-solving MVP — prove the core security guarantee works
correctly and reliably. No polish, no advanced features. A developer should be
able to download the binary, write a config file, and have a working zero-trust
MCP proxy in under 5 minutes. If the whitelist is correct and the audit log is
clear, the MVP has succeeded.

**Resource profile:** Achievable by a single developer. Minimal dependency surface
reduces both implementation effort and ongoing maintenance. rmcp handles MCP
protocol complexity; the proxy logic itself is focused policy enforcement and
transport bridging.

### MVP Feature Set (Phase 1)

**Core user journeys supported:**
- Journey 1: Alex — First Contact (success path)
- Journey 2: Alex — Debugging a Broken Workflow (edge case)
- Journey 3: Dana — Enterprise Rollout (operations path, minus OAuth2 and
  config push which are post-MVP)

**Must-have capabilities:**

| Capability | Justification |
|---|---|
| Tool whitelist enforcement (exact name matching) | The entire product value proposition |
| Default-deny policy | Core security property; without it the proxy is not zero-trust |
| Filter `tools/list` responses | Agent must not see blocked tools |
| Block `tools/call` requests | Blocked tools must not be callable |
| Agent stdio transport | Required for Claude Code / Cursor integration |
| Agent HTTP transport | Required for container/enterprise deployment |
| Upstream stdio transport | Required for local MCP server processes |
| Upstream HTTPS + bearer token auth | Required for hosted MCP servers (Supabase, etc.) |
| Single upstream per instance | Blast radius isolation — by design, not limitation |
| Local audit log to stdout (JSON-Lines) | Core traceability requirement |
| Config validation on startup (fail early) | Operational correctness |
| `validate-config` subcommand | CI/pre-deploy safety |
| SIGTERM/SIGINT graceful shutdown | Required for container and service manager operation |
| `GET /health` endpoint (HTTP mode) | Required for Kubernetes readiness probes |
| Cross-platform binaries (Linux, macOS, Windows) | Primary distribution channel |
| 100% policy enforcement test coverage | Non-negotiable quality gate |

**Explicitly excluded from MVP:**

| Feature | Phase |
|---|---|
| Interactive config generator (`mcp-protector init`) | Phase 2 |
| Rate limiting | Phase 2 |
| OAuth2 upstream authentication | Phase 2 |
| Schema / argument content inspection | Phase 2 |
| Agent plugin integrations | Phase 2 |
| Remote audit log forwarding | Phase 2 |
| Shell completion | Phase 2 |
| Enterprise config push via network | Phase 3 |
| Remote Policy Decision Point | Phase 3 |
| Multi-server aggregation | Out of scope by design |

### Post-MVP Features

**Phase 2 — Growth (priority order):**

1. **Config generator** (`mcp-protector init <url>`) — eliminates the manual
   config authoring step; targets Alex's onboarding friction directly
2. **Rate limiting** — per-agent call limits (sliding window); defends against
   runaway agents and injection-amplified abuse
3. **OAuth2 upstream auth** — full OAuth2 client for upstream MCP servers;
   required for enterprise-grade upstream connections
4. **Schema / argument inspection** — content-level filtering on tool inputs
   and outputs against declared JSON schemas
5. **Agent plugin integrations** — native integrations for Claude Code, Cursor,
   Codex; each built individually per platform plugin model
6. **Remote audit log forwarding** — structured log shipping (syslog, HTTP
   webhook, SIEM connectors)
7. **Shell completion** — zsh, bash, fish via clap generate

**Phase 3 — Expansion:**

- **Enterprise config push** — minimal bootstrap config + network-delivered
  policy config via mTLS-secured channel
- **Remote Policy Decision Point** — centralised policy management for
  multi-instance enterprise deployments
- **A2A protection** — security controls for agent-to-agent communication
- **Prompt sanitisation** — injection detection in agent inputs/outputs
- **Audit analytics** — compliance reporting, anomaly detection

### Risk Mitigation Strategy

**Technical risks:**

| Risk | Mitigation |
|---|---|
| Whitelist bypass via protocol edge cases | Fuzz test the MCP parser and name matcher; explicitly test Unicode, case, whitespace, and null-byte inputs |
| MCP protocol implementation bugs | Delegate to rmcp; pin rmcp version in Cargo.lock; update deliberately with regression tests |
| TLS misconfiguration on upstream HTTPS | Use rustls (memory-safe TLS); no custom cert validation logic |
| Dependency vulnerability introduced | Minimal Cargo.toml; run `cargo audit` in CI on every PR |

**Market risks:**

| Risk | Mitigation |
|---|---|
| Official MCP security layer from Anthropic | Open source positioning means mcp-protector can be adopted upstream or remain as the community standard; goal is ecosystem security, not ownership |
| Low adoption due to setup friction | Invest in README quality and config examples before Phase 2 tooling; one-sentence value prop must land immediately |
| Niche tool with limited reach | Proactively reach out to popular MCP server maintainers (Supabase, GitHub) to request README references |

**Resource risks:**

| Risk | Mitigation |
|---|---|
| Solo developer bandwidth | MVP scope is tight; rmcp and Rust ecosystem handle the heavy lifting; no custom protocol or crypto |
| Scope creep before MVP | This PRD is the scope boundary; new ideas go to Phase 2 backlog, not MVP |

## Functional Requirements

### Proxy Core

- **FR1:** The proxy can forward MCP protocol messages transparently between a
  connected agent and the configured upstream MCP server without requiring any
  modification to the agent
- **FR2:** The proxy can accept multiple concurrent agent connections on a single
  listener
- **FR3:** The proxy can restrict each running instance to exactly one upstream
  MCP server
- **FR4:** The proxy can reject agent connections using MCP protocol versions not
  supported by the rmcp library version in use

### Policy Enforcement

- **FR5:** Operators can define a tool allowlist as a list of exact tool name
  strings in the config file
- **FR6:** The proxy can filter `tools/list` responses from upstream, returning
  only tools whose names exactly match an entry in the allowlist and that exist
  on the upstream server (intersection of allowlist and upstream's actual tools)
- **FR7:** The proxy can block `tools/call` requests for any tool name that does
  not exactly match an entry in the allowlist
- **FR8:** The proxy can deny all tool calls when no allowlist entries are
  configured
- **FR9:** The proxy can deny all tool calls when the config file is absent,
  empty, or unparseable (fail closed — no permissive fallback)

### Transport & Connectivity

- **FR10:** Agents can connect to the proxy via stdio
- **FR11:** Agents can connect to the proxy via HTTP
- **FR12:** The proxy can connect to an upstream MCP server by spawning and
  communicating with a local process via stdio
- **FR13:** The proxy can connect to an upstream MCP server via HTTPS

### Upstream Authentication

- **FR14:** Operators can configure a bearer token for authenticating outbound
  upstream HTTPS connections in the config file
- **FR15:** The proxy can attach the configured bearer token to all outbound
  requests sent to the upstream MCP server

### Audit Logging

- **FR16:** The proxy can emit a structured log entry for every `tools/call`
  request, recording: tool name, agent identifier, ALLOW or BLOCK decision,
  and timestamp
- **FR17:** The proxy can emit a structured log entry for every `tools/list`
  request, recording: agent identifier and timestamp
- **FR18:** The proxy can write all audit log entries to stdout in JSON-Lines
  format (one JSON object per line)
- **FR19:** The proxy can write audit log entries for blocked calls regardless
  of how many times the agent retries the same call (entries are never suppressed)
- **FR20:** Agents can identify themselves to the proxy via an identifier
  asserted at connection time, which the proxy records in audit log entries

### Observability & Operations

- **FR21:** The proxy can expose a `GET /health` endpoint returning HTTP 200
  when operating in HTTP transport mode and ready to accept agent connections
- **FR22:** The proxy can write all diagnostic output (startup confirmation,
  shutdown notice, errors) to stderr, keeping stdout reserved for audit log
  entries
- **FR23:** The proxy can perform a graceful shutdown when it receives SIGTERM
  or SIGINT, completing in-flight requests before exiting

### Configuration Management

- **FR24:** Operators can specify the path to the config file via a CLI flag on
  the `proxy` subcommand
- **FR25:** The proxy can validate the complete config file before establishing
  any agent-side or upstream connections
- **FR26:** The proxy can emit a human-readable error message to stderr
  identifying each invalid config field and the reason it is invalid
- **FR27:** Operators can validate a config file and receive any errors without
  starting the proxy, using the `validate-config` subcommand

### CLI & Distribution

- **FR28:** Operators can start the proxy using the `mcp-protector proxy`
  subcommand
- **FR29:** The proxy can exit with code `0` on clean shutdown, `1` on config
  validation failure at startup, and `2` on unrecoverable runtime error
- **FR30:** Operators can obtain a pre-compiled binary for Linux (x86_64,
  aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64) from the
  project's GitHub Releases page

## Non-Functional Requirements

### Performance

- **NFR-P1:** The proxy must add no more than 10ms of latency (p99) to a
  tool call round-trip under normal operating conditions (single concurrent
  connection, local network). The proxy must never be the bottleneck in a
  tool call workflow.
- **NFR-P2:** Audit log writes must not block tool call processing. Log
  entries may be written asynchronously provided they are guaranteed to
  be flushed before graceful shutdown completes.
- **NFR-P3:** The proxy must sustain correct policy enforcement under
  concurrent agent connections without degradation. Enterprise scale is
  achieved by running multiple instances (one per upstream); each instance
  is not required to support unbounded concurrency.

### Security

- **NFR-S1:** All upstream HTTPS connections must use TLS 1.2 or higher,
  enforced via rustls. The proxy must not support TLS 1.0 or 1.1 and must
  not implement custom certificate validation logic.
- **NFR-S2:** Bearer tokens, credentials, and authentication material must
  never appear in audit log output, diagnostic output, or error messages.
- **NFR-S3:** Any use of Rust `unsafe` code must be restricted to well-known
  safe abstractions (e.g., FFI wrappers for OS APIs). The policy enforcement
  layer — tool name matching, allowlist lookup, and log writing — must contain
  no `unsafe` blocks.
- **NFR-S4:** The binary must be built from a `Cargo.lock` that passes
  `cargo audit` with zero known vulnerabilities at the time of each release.
  `cargo audit` must run on every CI build.
- **NFR-S5:** The proxy must not accept self-signed certificates from upstream
  servers unless explicitly configured to do so. Default behaviour is strict
  certificate validation.

### Reliability

- **NFR-R1:** The proxy must not lose any in-flight audit log entries during
  graceful shutdown. All entries buffered at the time SIGTERM is received must
  be flushed to stdout before the process exits.
- **NFR-R2:** The proxy must not crash on receipt of a malformed, unexpected,
  or protocol-violating message from the upstream MCP server. Such conditions
  must be logged to stderr and result in closure of the affected session, not
  process termination.
- **NFR-R3:** The proxy must never enter a permissive state as a result of a
  runtime error. Any condition that prevents the policy from being evaluated
  must result in the tool call being blocked, not allowed.
- **NFR-R4:** The proxy must not silently drop tool call requests. Every
  received `tools/call` request must produce either an ALLOW or BLOCK audit
  log entry, or a logged error entry explaining why neither was produced.

### Correctness

- **NFR-C1:** Tool name matching must be case-sensitive exact string comparison
  with no normalisation (no Unicode normalisation, no whitespace trimming, no
  case folding). A tool name matches the allowlist entry if and only if the
  strings are byte-for-byte identical.
- **NFR-C2:** Policy enforcement must produce identical results for identical
  inputs across all supported platforms (Linux, macOS, Windows). No
  platform-specific code paths may exist in the policy enforcement layer.
- **NFR-C3:** The `tools/list` filtered response must contain only tools that
  are both present in the upstream server's actual tool list AND in the
  allowlist. A tool listed in the allowlist but not offered by the upstream
  must not appear in the filtered response.

### Maintainability

- **NFR-M1:** The Cargo dependency tree must be kept to the minimum required
  for the implemented functionality. Each direct dependency must be justified
  in a comment in `Cargo.toml`. Dependencies must be widely adopted,
  actively maintained crates.
- **NFR-M2:** The policy enforcement module (allowlist lookup and tool call
  filtering) must have 100% branch coverage in automated tests. Coverage
  is enforced as a CI quality gate — builds failing coverage do not produce
  release binaries.
- **NFR-M3:** The audit log JSON-Lines format is a versioned public contract.
  Any change to field names, field types, or the set of required fields is a
  breaking change requiring a major version bump and documented migration path.
- **NFR-M4:** The config file schema is a versioned public contract. Backwards-
  incompatible changes require a major version bump. New optional fields may be
  added in minor releases.
