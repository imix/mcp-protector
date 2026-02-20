//! Integration tests for IP allowlist agent authentication (Epic 6, Story 6.3).
//!
//! These tests verify that the proxy correctly enforces source-IP restrictions
//! when `[listen.auth] type = "ip_allowlist"` is configured.  All test
//! connections originate from 127.0.0.1 (loopback), so:
//!
//! - Tests that allow loopback (`127.0.0.1/32` or `127.0.0.0/8`) expect the
//!   request to pass through (non-403).
//! - Tests that use a range that does NOT include loopback expect 403.
//!
//! `GET /health` is intentionally outside the auth layer and must always
//! return a non-403 response regardless of IP configuration.

mod common;

use std::net::TcpListener;
use std::time::Duration;

use common::ConfigFixture;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

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

#[cfg(unix)]
fn wait_for_port(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match ureq::get(&url).call() {
            Ok(_) | Err(ureq::Error::StatusCode(_)) => return true,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    false
}

// ── Story 6.3 tests ───────────────────────────────────────────────────────────

/// Verify that `/health` is accessible without IP restrictions — it is on a
/// separate router and intentionally bypasses all auth layers.
#[test]
#[cfg(unix)]
fn health_accessible_regardless_of_ip_allowlist() {
    let port = free_port();
    // Allowlist does NOT include loopback — but health must still work.
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "ip_allowlist"
allow = ["10.0.0.0/8"]

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    let health_url = format!("http://127.0.0.1:{port}/health");
    let status: u16 = match ureq::get(&health_url).call() {
        Ok(resp) => resp.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(e) => panic!("unexpected error from /health: {e}"),
    };

    let _ = child.kill();
    let _ = child.wait();

    assert_ne!(status, 403, "/health must bypass IP allowlist; got {status}");
}

/// Verify that `/mcp` is accessible when the source IP is in the allowlist.
/// Loopback (`127.0.0.1`) is in `127.0.0.0/8`, so the request must pass auth
/// and reach the MCP service (which returns non-403).
#[test]
#[cfg(unix)]
fn mcp_request_from_allowed_ip_passes() {
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
type = "ip_allowlist"
allow = ["127.0.0.0/8"]

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
        Ok(resp) => assert_ne!(
            resp.status().as_u16(),
            403,
            "loopback in allowlist must not return 403"
        ),
        Err(ureq::Error::StatusCode(403)) => panic!("loopback in allowlist must not return 403"),
        Err(ureq::Error::StatusCode(_)) => { /* non-403 error is fine — auth passed */ }
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

/// Verify that `/mcp` returns 403 when the source IP is NOT in the allowlist.
/// Loopback (`127.0.0.1`) is not in `10.0.0.0/8`, so the request is blocked.
#[test]
#[cfg(unix)]
fn mcp_request_from_blocked_ip_returns_403() {
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
type = "ip_allowlist"
allow = ["10.0.0.0/8"]

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
        Err(ureq::Error::StatusCode(403)) => { /* expected */ }
        Ok(resp) => panic!("expected 403 but got {}", resp.status()),
        Err(ureq::Error::StatusCode(code)) => panic!("expected 403 but got {code}"),
        Err(e) => panic!("unexpected transport error: {e}"),
    }
}

/// Verify that a /32 CIDR (single-host) allows the exact loopback address.
#[test]
#[cfg(unix)]
fn mcp_request_allowed_by_host_cidr() {
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
type = "ip_allowlist"
allow = ["127.0.0.1/32"]

[policy]
allow = []
"#
    );

    let (mut child, _fixture) = spawn_proxy(&toml);

    let ready = wait_for_port(port);
    assert!(ready, "proxy did not bind port in time");

    let result = ureq::get(&format!("http://127.0.0.1:{port}/mcp")).call();

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Err(ureq::Error::StatusCode(403)) => panic!("127.0.0.1/32 must allow loopback"),
        Ok(_) | Err(ureq::Error::StatusCode(_)) => { /* auth passed */ }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ── Config validation unit tests (no proxy needed) ────────────────────────────

/// Empty allowlist must be rejected at config validation time.
#[test]
fn empty_ip_allowlist_rejected_by_validate_config() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "ip_allowlist"
allow = []

[policy]
allow = []
"#
    );
    let fixture = ConfigFixture::new("config.toml", &toml);

    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("listen.auth.allow"));
}

/// Invalid CIDR entries must be rejected at config validation time.
#[test]
fn invalid_cidr_in_ip_allowlist_rejected_by_validate_config() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "http"
port = {port}

[listen.auth]
type = "ip_allowlist"
allow = ["not-a-cidr"]

[policy]
allow = []
"#
    );
    let fixture = ConfigFixture::new("config.toml", &toml);

    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("listen.auth.allow[0]"));
}
