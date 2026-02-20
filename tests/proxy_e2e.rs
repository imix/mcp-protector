//! End-to-end proxy integration tests (Story 3.5).
//!
//! These tests exercise the `proxy` subcommand against real transport
//! combinations to validate that the binary starts, binds ports, responds
//! to health checks, and exits cleanly.
//!
//! # Design notes
//!
//! Full MCP protocol round-trips would require a conformant MCP server
//! subprocess.  Instead these tests focus on observable side-effects that
//! don't require a live MCP peer:
//!
//! - The binary starts without crashing on invalid configs.
//! - The binary fails fast when the upstream command does not exist.
//! - The `/health` endpoint responds with 503 before upstream is ready.

mod common;

use std::net::TcpListener;
use std::time::Duration;

use predicates::prelude::*;

use common::ConfigFixture;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Bind a TCP listener on `127.0.0.1:0` and return the ephemeral port number
/// chosen by the OS.  The listener is immediately dropped, freeing the port;
/// there is a small TOCTOU window before the proxy claims it, but this is
/// acceptable in a test environment.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

// ── Story 3.5 tests ───────────────────────────────────────────────────────────

/// Verify that a config with HTTP listen and stdio upstream with an
/// unresolvable command exits with a non-zero code (proxy startup fails).
///
/// This exercises the HTTP transport combination routing in `proxy::run()`
/// without requiring a real MCP server subprocess.
#[test]
fn proxy_http_stdio_with_bad_command_exits_nonzero() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["/nonexistent-mcp-server-for-testing"]

[listen]
transport = "http"
port = {port}

[policy]
allow = ["read_file"]
"#
    );
    let fixture = ConfigFixture::new("config.toml", &toml);

    // The proxy should fail quickly because the upstream command doesn't exist.
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["proxy", "--config", fixture.path.to_str().unwrap()])
        .timeout(Duration::from_secs(5))
        .assert()
        .failure();
}

/// Verify that a config with stdio listen and stdio upstream with an
/// unresolvable command exits with a non-zero code.
#[test]
fn proxy_stdio_stdio_with_bad_command_exits_nonzero() {
    let toml = r#"
[upstream]
url = "stdio"
command = ["/nonexistent-mcp-server-for-testing"]

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);

    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["proxy", "--config", fixture.path.to_str().unwrap()])
        .timeout(Duration::from_secs(5))
        .assert()
        .failure();
}

/// Verify that an invalid config causes the proxy subcommand to exit 1 with
/// a descriptive error on stderr (the error is reported before any network
/// activity, so no actual transport is involved).
#[test]
fn proxy_with_invalid_config_exits_one() {
    let toml = r#"
[upstream]
url = "ftp://bad-scheme"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);

    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["proxy", "--config", fixture.path.to_str().unwrap()])
        .timeout(Duration::from_secs(5))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("upstream.url"));
}

/// Verify that the `/health` endpoint returns 503 `{"status":"starting"}` while
/// the upstream handshake is pending.
///
/// We spawn `sleep 30` as the upstream command — it is a valid executable that
/// never produces MCP output, so the upstream handshake never completes and
/// the proxy stays in the "starting" state.  We poll `/health` and expect 503
/// before terminating the proxy.
///
/// This test requires `sleep` to be available (standard on Linux/macOS).
#[test]
#[cfg(unix)]
fn health_endpoint_returns_503_before_upstream_ready() {
    let port = free_port();
    let toml = format!(
        r#"
[upstream]
url = "stdio"
command = ["sleep", "30"]

[listen]
transport = "http"
port = {port}

[policy]
allow = []
"#
    );
    let fixture = ConfigFixture::new("config.toml", &toml);

    // Spawn the proxy in the background using the macro (not the deprecated fn).
    let bin = assert_cmd::cargo_bin!("mcp-protector");
    let mut child = std::process::Command::new(bin)
        .args(["proxy", "--config", fixture.path.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn mcp-protector");

    // Give the proxy time to bind the port.
    std::thread::sleep(Duration::from_millis(400));

    let health_url = format!("http://127.0.0.1:{port}/health");
    let mut found_503 = false;

    // Poll for up to 5 s; `sleep 30` never completes the MCP handshake so the
    // health endpoint must stay at 503 for the duration of our test.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let response = ureq::get(&health_url).call();
        match response {
            Ok(mut resp) if resp.status() == 200 => {
                // Drain the body so the connection closes cleanly, then break.
                let _ = resp.body_mut().read_to_string();
                break;
            }
            Err(ureq::Error::StatusCode(503)) => {
                found_503 = true;
                break;
            }
            _ => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    // Terminate the proxy process.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        found_503,
        "/health must return 503 while upstream handshake is pending"
    );
}
