# Security Review: mcp-protector

**Date:** 2026-02-20
**Reviewer:** Internal
**Status:** Complete — fixes applied for HIGH-1, MEDIUM-1, MEDIUM-2, MEDIUM-3, LOW-2

## Context

This review covers the config loading path and dependency surface of the project
as it stands before any network-connected code is wired in. The proxy does not yet
handle live traffic; however, several findings in the config loading path become
directly exploitable the moment the binary is deployed, and one dependency decision
creates hardening debt that must be resolved before the HTTPS transport is added.

**Scope:** `src/main.rs`, `src/config.rs`, `src/policy.rs`, `Cargo.toml`
**Out of scope:** Stub modules (`proxy.rs`, `transport/`, `audit.rs`, `shutdown.rs`)
and all roadmap items not yet implemented.

---

## Findings Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| HIGH-1 | High | Arbitrary file read via unsanitized config path | **Fixed** |
| MEDIUM-1 | Medium | URL validation accepts structurally invalid HTTPS URLs | **Fixed** |
| MEDIUM-2 | Medium | Bearer token accepts empty or whitespace-only value | **Fixed** |
| MEDIUM-3 | Medium | TLS 1.2 enabled before HTTPS transport exists | **Fixed** |
| LOW-1 | Low | Config file permissions not checked | Documented — deferred |
| LOW-2 | Low | Port 0 accepted as valid listen port | **Fixed** |
| LOW-3 | Low | `build_config` invariants rely on `expect()`, not type enforcement | Documented — deferred |
| INFO-1 | Info | `tokio = { features = ["full"] }` includes unused subsystems | Documented — deferred |
| INFO-2 | Info | `upstream.command` executable not validated at config time | Documented — deferred |

---

## Detailed Findings

### HIGH-1 — Arbitrary file read via unsanitized config path ✅ Fixed

**Files:** `src/main.rs:67,81` → `src/config.rs::load`

**Issue:** `--config <PATH>` was passed as a raw `PathBuf` directly to
`std::fs::read_to_string`, which follows symlinks silently. Any file readable by
the process owner could be targeted:

```
mcp-protector validate-config --config /proc/self/environ
mcp-protector validate-config --config /etc/hostname
```

TOML parse errors include line/column context, potentially leaking content
fragments from the targeted file to stderr.

**Fix applied in `src/config.rs::load`:**

1. `std::fs::symlink_metadata(path)` is called before `read_to_string`. If the
   path is a symlink, `ConfigError::ReadFailed` is returned immediately with the
   message `"config path must not be a symlink"`.
2. `std::path::absolute(path)` and `std::fs::canonicalize(path)` are compared; if
   they differ (parent directories traverse symlinks), a `tracing::warn!` is
   emitted.

**Residual risk:** There is an inherent TOCTOU window between the symlink check
and `read_to_string`. This is acceptable — the guard eliminates the most practical
attack vectors and is consistent with defence-in-depth; the binary should also be
run with minimal OS privileges (see operational guidance below).

**Tests added:** `symlink_config_path_exits_one_with_error` (`#[cfg(unix)]`) in
`tests/config_validation.rs`.

---

### MEDIUM-1 — URL validation accepts structurally invalid HTTPS URLs ✅ Fixed

**File:** `src/config.rs::validate`

**Issue:** The previous check `raw.upstream.url.starts_with("https://")` accepted
`https://` (empty host), `https:// ` (whitespace), `https://]broken`, etc. When
the HTTPS transport is wired in (Story 2.x), malformed inputs cause opaque runtime
errors and could enable SSRF in some HTTP client implementations.

**Fix applied:** `url::Url::parse` is used to parse any value that starts with
`https://`. Validation enforces:
- Parse succeeds
- `host()` is non-`None` (non-empty host)
- `username()` is empty and `password()` is `None` (no userinfo component)

The `url` crate (`v2.5`) is added as a runtime dependency.

**Tests added:** `empty_host_https_url_reports_upstream_url_error` in
`tests/config_validation.rs`.

---

### MEDIUM-2 — Bearer token accepts empty or whitespace-only value ✅ Fixed

**File:** `src/config.rs::validate`

**Issue:** `auth.token.is_none()` checked only presence, not content. `token = ""`
or `token = "   "` passed validation and was wrapped in `SecretBox`. The proxy
would silently start with an empty credential.

**Fix applied:** After the `is_none()` check, the token is briefly exposed via
`expose_secret()` to verify it is non-empty and non-whitespace. A comment marks
this as the only sanctioned `expose_secret()` call in `config.rs`.

```rust
// This is the only sanctioned expose_secret() call in config.rs —
// used solely to validate that the credential is non-empty.
let token = auth.token.as_ref().expect("token is Some — checked above");
if token.expose_secret().trim().is_empty() {
    errors.push(ConfigError::InvalidField { ... });
}
```

**Tests added:** `empty_bearer_token_reports_auth_token_error` in
`tests/config_validation.rs`.

---

### MEDIUM-3 — TLS 1.2 enabled before HTTPS transport exists ✅ Fixed

**File:** `Cargo.toml`

**Issue:** Both `rustls` and `tokio-rustls` included the `"tls12"` feature. TLS 1.2
is deprecated (RFC 8996) and susceptible to downgrade attacks. The feature was
included before any HTTPS transport code existed, creating silent hardening debt.

**Fix applied:** `"tls12"` removed from both feature lists:

```toml
# Before
rustls = { ..., features = ["std", "tls12", "ring", "logging"] }
tokio-rustls = { ..., features = ["tls12", "ring", "logging"] }

# After
rustls = { ..., features = ["std", "ring", "logging"] }
tokio-rustls = { ..., features = ["ring", "logging"] }
```

If a future upstream server requires TLS 1.2, re-add with a
`# justification: required for <server>` comment.

**Verification:** `cargo tree | grep tls12` → no output.

---

### LOW-1 — Config file permissions not checked ⚠️ Deferred

**File:** `src/config.rs::load`

**Issue:** A world-readable config file (mode `0644`) exposes the bearer token to
any local user. Operators commonly create files with default permissions.

**Recommended fix:** After `read_to_string` succeeds, on `#[cfg(unix)]`, call
`std::fs::metadata(path)` and check `mode & 0o044 != 0`. If true, emit
`tracing::warn!` recommending `chmod 600`. Warn rather than error, to avoid
breaking read-only container image deployments.

**Deferred because:** This is a warning-only hardening measure. Track for
implementation at the start of Story 2.x before the first deployment.

---

### LOW-2 — Port 0 accepted as valid listen port ✅ Fixed

**File:** `src/config.rs::validate`

**Issue:** Validation enforced `port ≤ 65535` but not `port ≥ 1`. Port 0 triggers
OS-assigned ephemeral port assignment — the proxy binds to an unpredictable port,
making it unreachable without inspecting the process's file descriptors.

**Fix applied:** Range check changed from `port > u16::MAX` to
`!(1..=u32::from(u16::MAX)).contains(&port)`:

```rust
if !(1..=u32::from(u16::MAX)).contains(&port) {
    errors.push(ConfigError::InvalidField {
        field: "listen.port".to_owned(),
        reason: format!("{port} is not a valid port number (must be 1–65535)"),
    });
}
```

**Tests added:** `port_zero_reports_listen_port_error` in
`tests/config_validation.rs`.

---

### LOW-3 — `build_config` invariants rely on `expect()`, not type enforcement ⚠️ Deferred

**File:** `src/config.rs::build_config`

**Issue:** `build_config` uses `.expect("validated above")` to assert invariants
that `validate()` is responsible for enforcing. Nothing in the type system prevents
`build_config` from being called with an unvalidated `RawConfig`. As the codebase
grows, these panics become reachable.

**Recommended fix:** Introduce a `ValidatedRawConfig(RawConfig)` newtype
constructable only from inside `validate()` when it returns zero errors. Change
`build_config` to accept `ValidatedRawConfig`. The `expect()` calls become
unnecessary.

**Deferred because:** This is an architectural refactor. Track as a follow-up once
the config module stabilises in Epic 2.

---

### INFO-1 — `tokio = { features = ["full"] }` includes unused subsystems ℹ️ Deferred

**File:** `Cargo.toml`

**Issue:** `"full"` enables `fs`, `process`, `net`, `signal`, and several other
features not yet used. Increases compiled binary size and attack surface marginally.

**Recommended fix:** Enumerate exact required features at the end of Story 2.x when
the full set is known.

---

### INFO-2 — `upstream.command` executable not validated at config time ℹ️ Deferred

**File:** `src/config.rs::validate`

**Issue:** Non-empty presence of `command` is checked but the executable path is
not verified to exist or be executable. `validate-config` reports success for
`command = ["/nonexistent"]`.

**Recommended fix:** Add a `#[cfg(unix)]` check using `std::fs::metadata(&command[0])`
and `permissions().mode() & 0o111 != 0`. Emit `tracing::warn!` (not error) to
avoid breaking environments where the binary may not be present at
config-validation time (e.g., CI).

**Deferred because:** Low priority ahead of the stdio upstream transport story.
Implement at the start of Story 2.2 (stdio upstream transport).

---

## Strengths — No Action Needed

- **`policy.rs`** — correct, pure, fail-closed. No findings.
- **`SecretBox<String>` usage** — token protected from deserialization onward;
  debug redaction verified by a dedicated test (`bearer_token_stored_as_secret_not_visible_in_debug`).
- **Collect-all-errors validation** — reports every invalid field in one pass
  rather than stopping at the first.
- **`unsafe_code = "forbid"` + clippy pedantic** — enforced at the compiler level;
  no exceptions in the current tree.
- **rustls with ring backend** — no C crypto, no OpenSSL, auditable Rust stack.

---

## Operational Guidance (Pre-Deployment Checklist)

These items are outside the scope of code fixes but should be verified before the
first deployment:

1. **Run with a dedicated low-privilege user** — the process must not run as root.
   This limits the blast radius of the TOCTOU window in HIGH-1.
2. **`chmod 600 <config-file>`** — restrict config file permissions to the owner
   only (see LOW-1 above).
3. **Mount config as read-only in containers** — use `--read-only` volume mounts
   or Kubernetes `readOnly: true` volume mounts for config directories.
4. **Verify `cargo tree | grep tls12` returns nothing** before each release to
   confirm TLS 1.2 has not been re-introduced transitively.

---

## Verification Checklist

All items below should pass after applying this review's fixes:

- [x] `cargo test` — 46 tests pass (22 unit + 24 integration)
- [x] `cargo clippy` — zero warnings/errors
- [x] `validate-config --config /proc/self/environ` → exit 1, stderr contains
  "symlink" or "failed to read"
- [x] `upstream.url = "https://"` → exit 1, stderr contains "upstream.url"
- [x] `upstream.auth.token = ""` → exit 1, stderr contains "upstream.auth.token"
- [x] `listen.port = 0` → exit 1, stderr contains "listen.port"
- [x] `cargo tree | grep tls12` → no output
