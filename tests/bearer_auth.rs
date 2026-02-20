//! Integration tests for bearer token agent authentication (Epic 5, Story 5.4).
//!
//! These tests verify that the proxy correctly enforces the `Authorization:
//! Bearer` requirement when `[listen.auth]` is configured, while keeping
//! `GET /health` accessible without credentials.
//!
//! The upstream is `sleep 30` — a valid executable that never produces MCP
//! output — which means the upstream handshake never completes.  This is
//! sufficient to test the auth middleware because auth enforcement happens
//! at the TCP→HTTP layer, before the session factory is invoked.

mod common;

use std::net::TcpListener;
use std::time::Duration;

use common::ConfigFixture;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Bind a TCP listener on `127.0.0.1:0` and return the ephemeral port number.
/// The listener is immediately dropped so the proxy can claim the port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Spawn a proxy process with the given TOML config and return the child
/// process handle.  Stdout and stderr are suppressed to keep test output clean.
fn spawn_proxy(toml: &str) -> (std::process::Child, ConfigFixture) {
    let fixture = ConfigFixture::new("config.toml", toml);
    let bin = assert_cmd::cargo_bin!("mcp-protector");
    let child = std::process::Command::new(bin)
        .args(["proxy", "--config", fixture.path.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn mcp-protector");
    (child, fixture)
}

/// Poll a URL with `ureq::get` until a non-connection-refused response is
/// received or the deadline expires.  Returns `true` once the server is ready.
#[cfg(unix)]
fn wait_for_port(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        // Any response — even 503 — means the server is listening.
        match ureq::get(&url).call() {
            Ok(_) | Err(ureq::Error::StatusCode(_)) => return true,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    false
}

// ── Story 5.4 tests ───────────────────────────────────────────────────────────

/// Verify that `/health` is reachable without credentials when bearer auth is
/// configured — container readiness probes must not require a token.
#[test]
#[cfg(unix)]
fn health_endpoint_accessible_without_token_when_bearer_auth_configured() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "bearer"
token = "test-secret-token"

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    // Wait for the HTTP listener to bind.
    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    // /health must return without needing a token.
    let health_url = format!("http://127.0.0.1:{port}/health");
    let status: u16 = match ureq::get(&health_url).call() {
        Ok(resp) => resp.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(e) => panic!("unexpected error from /health: {e}"),
    };

    let _ = child.kill();
    let _ = child.wait();

    // 200 (upstream ready) or 503 (still starting) — both are fine; the
    // important thing is that it did NOT return 401.
    assert!(
        status != 401,
        "/health must not require authentication; got {status}"
    );
}

/// Verify that a request to `/mcp` without an `Authorization` header is
/// rejected with 401 and includes a `WWW-Authenticate: Bearer` header.
#[test]
#[cfg(unix)]
fn mcp_request_without_token_returns_401() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "bearer"
token = "test-secret-token"

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    let mcp_url = format!("http://127.0.0.1:{port}/mcp");
    let result = ureq::get(&mcp_url).call();

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Err(ureq::Error::StatusCode(401)) => {
            // Expected: 401 Unauthorized
        }
        Ok(resp) => panic!("expected 401 but got {}", resp.status()),
        Err(ureq::Error::StatusCode(code)) => panic!("expected 401 but got {code}"),
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

/// Verify that a request to `/mcp` with an incorrect token is rejected with 401.
#[test]
#[cfg(unix)]
fn mcp_request_with_wrong_token_returns_401() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "bearer"
token = "correct-secret-token"

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    let mcp_url = format!("http://127.0.0.1:{port}/mcp");
    let result = ureq::get(&mcp_url)
        .header("Authorization", "Bearer wrong-token")
        .call();

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Err(ureq::Error::StatusCode(401)) => {
            // Expected: 401 Unauthorized
        }
        Ok(resp) => panic!("expected 401 but got {}", resp.status()),
        Err(ureq::Error::StatusCode(code)) => panic!("expected 401 but got {code}"),
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

/// Verify that a request to `/mcp` with the correct token is NOT rejected
/// with 401.  The upstream (`sleep 30`) never completes the MCP handshake, so
/// the session factory returns an error, but that error is NOT a 401 —
/// it is a server-side 500 or 503.  The auth middleware has passed.
#[test]
#[cfg(unix)]
fn mcp_request_with_correct_token_passes_auth_check() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "bearer"
token = "correct-secret-token"

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    let mcp_url = format!("http://127.0.0.1:{port}/mcp");
    let result = ureq::get(&mcp_url)
        .header("Authorization", "Bearer correct-secret-token")
        .call();

    let _ = child.kill();
    let _ = child.wait();

    match result {
        // Any non-401 response means auth passed.
        Ok(resp) => assert_ne!(resp.status(), 401, "auth should have passed"),
        Err(ureq::Error::StatusCode(401)) => {
            panic!("correct token must not return 401")
        }
        Err(ureq::Error::StatusCode(code)) => {
            // 500, 503, etc. are acceptable — auth passed, upstream just isn't ready.
            assert_ne!(code, 401, "correct token must not return 401");
        }
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

/// Verify that the constant-time comparison does not short-circuit on the
/// first differing byte.  This is a unit-level property test of `subtle`.
///
/// We verify that two tokens that share a long common prefix but differ in
/// the last byte are both rejected in the same way as tokens that differ
/// immediately.  (This does not measure timing — it just confirms the
/// comparison works correctly.)
#[test]
fn constant_time_comparison_rejects_prefix_match() {
    use subtle::ConstantTimeEq as _;

    let expected = b"correct-token-value";
    let prefix_match = b"correct-token-valuf"; // differs only in last byte
    let empty = b"";
    let totally_different = b"x";

    // All wrong tokens must compare as not-equal.
    let r1: bool = expected.ct_eq(prefix_match).into();
    let r2: bool = expected.ct_eq(empty).into();
    let r3: bool = expected.ct_eq(totally_different).into();
    let r4: bool = expected.ct_eq(expected).into(); // correct token matches

    assert!(!r1, "prefix match must not pass constant-time eq");
    assert!(!r2, "empty must not match");
    assert!(!r3, "totally different must not match");
    assert!(r4, "exact match must pass constant-time eq");
}
