//! Integration tests for config loading and field-level validation.
//!
//! These tests exercise the binary directly via `validate-config` and verify
//! field-level error messages and exit codes (Stories 1.2, 1.3, FR24–FR27).

mod common;

use assert_cmd::Command;
use predicates::prelude::*;

use common::ConfigFixture;

// ── Story 1.2: Config file parsing (valid configs accepted) ──────────────────

#[test]
fn valid_stdio_config_exits_zero() {
    let fixture = ConfigFixture::new("config.toml", common::VALID_STDIO);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn valid_https_config_exits_zero() {
    let fixture = ConfigFixture::new("config.toml", common::VALID_HTTPS);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn valid_config_with_bearer_token_exits_zero() {
    let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "bearer"
token = "mytoken"

[listen]
transport = "stdio"

[policy]
allow = ["read_file"]
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn empty_allowlist_is_valid() {
    let toml = r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success();
}

// ── Story 1.3: Validation errors reported to stderr ──────────────────────────

#[test]
fn http_transport_without_port_reports_listen_port_error() {
    let toml = r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "http"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("listen.port"))
        .stderr(predicate::str::contains("required when transport is 'http'"));
}

#[test]
fn unknown_auth_type_reports_field_error() {
    let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "basic"
token = "u:p"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("upstream.auth.type"))
        .stderr(predicate::str::contains("unknown value 'basic'"));
}

#[test]
fn port_exceeding_max_reports_field_error() {
    let toml = r#"
[upstream]
url = "https://example.com/mcp"

[listen]
transport = "http"
port = 99999

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("listen.port"))
        .stderr(predicate::str::contains("valid port number"));
}

#[test]
fn multiple_invalid_fields_all_reported_on_stderr() {
    // invalid upstream.url + missing listen.port → 2+ errors
    let toml = r#"
[upstream]
url = "ftp://wrong"
command = ["/bin/srv"]

[listen]
transport = "http"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    let output = Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Both error fields must appear in stderr
    assert!(
        stderr.contains("upstream.url"),
        "upstream.url error missing from stderr: {stderr}"
    );
    assert!(
        stderr.contains("listen.port"),
        "listen.port error missing from stderr: {stderr}"
    );
}

#[test]
fn missing_config_file_reports_path_on_stderr() {
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", "/nonexistent-mcp-test.toml"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("nonexistent-mcp-test.toml"));
}

// ── Security fixes ────────────────────────────────────────────────────────────

/// HIGH-1: config path that is a symlink must be rejected (arbitrary file read guard).
#[cfg(unix)]
#[test]
fn symlink_config_path_exits_one_with_error() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.toml");
    std::fs::write(&real, common::VALID_STDIO).unwrap();
    let link = dir.path().join("link.toml");
    symlink(&real, &link).unwrap();

    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", link.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("symlink").or(predicate::str::contains("failed to read")));
}

/// MEDIUM-1: structurally invalid HTTPS URL (empty host) must be rejected.
#[test]
fn empty_host_https_url_reports_upstream_url_error() {
    let toml = r#"
[upstream]
url = "https://"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("upstream.url"));
}

/// MEDIUM-2: empty bearer token must be rejected.
#[test]
fn empty_bearer_token_reports_auth_token_error() {
    let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "bearer"
token = ""

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("upstream.auth.token"));
}

/// LOW-2: port 0 triggers OS-assigned ephemeral port — must be rejected.
#[test]
fn port_zero_reports_listen_port_error() {
    let toml = r#"
[upstream]
url = "https://example.com/mcp"

[listen]
transport = "http"
port = 0

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("listen.port"));
}

#[test]
fn valid_config_produces_nothing_on_stdout() {
    let fixture = ConfigFixture::new("config.toml", common::VALID_STDIO);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}
