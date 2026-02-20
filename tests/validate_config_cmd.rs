//! Integration tests for the `validate-config` CLI subcommand (Story 1.4).
//!
//! Covers FR27 (validate-config subcommand) and FR29 (exit codes).

mod common;

use predicates::prelude::*;

use common::ConfigFixture;

// ── Story 1.4: validate-config subcommand behaviour ──────────────────────────

#[test]
fn valid_config_exits_zero_and_prints_confirmation_to_stderr() {
    let fixture = ConfigFixture::new("config.toml", common::VALID_STDIO);
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success()
        .code(0)
        .stderr(predicate::str::contains("Config is valid."));
}

#[test]
fn invalid_config_exits_one() {
    let toml = r#"
[upstream]
url = "ftp://bad"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn invalid_config_prints_errors_to_stderr() {
    let toml = r#"
[upstream]
url = "ftp://bad"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("upstream.url"));
}

#[test]
fn validate_config_writes_nothing_to_stdout_on_success() {
    let fixture = ConfigFixture::new("config.toml", common::VALID_HTTPS);
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn validate_config_writes_nothing_to_stdout_on_failure() {
    let toml = r#"
[upstream]
url = "bad"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = []
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty());
}

#[test]
fn missing_config_file_exits_one_and_reports_path() {
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .args(["validate-config", "--config", "/nonexistent-mcp-protector.toml"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("nonexistent-mcp-protector.toml"));
}

#[test]
fn help_lists_both_subcommands() {
    assert_cmd::cargo_bin_cmd!("mcp-protector")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("proxy"))
        .stdout(predicate::str::contains("validate-config"));
}
