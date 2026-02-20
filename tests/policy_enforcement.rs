//! Integration tests for policy enforcement (Story 1.5, FR5–FR9).
//!
//! The core policy logic (is_tool_allowed, filter_tools_list) is covered with
//! 100% branch coverage by the inline `#[cfg(test)]` module in `src/policy.rs`.
//!
//! End-to-end policy enforcement through the proxy session loop will be tested
//! in `proxy_e2e.rs` once Story 2.x (proxy session orchestration) is complete.
//!
//! This file validates policy-related config acceptance criteria that are
//! observable through the `validate-config` CLI surface:
//!
//! - FR8: empty allowlist is valid config (not an error)
//! - FR5: operators can define a tool allowlist in the config file

mod common;

use assert_cmd::Command;
use predicates::prelude::*;

use common::ConfigFixture;

// FR8: empty allowlist is a valid configuration (not a config error)
#[test]
fn empty_allowlist_is_accepted_by_validate_config() {
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
        .success()
        .code(0);
}

// FR5: operators can define a non-empty allowlist
#[test]
fn non_empty_allowlist_is_accepted_by_validate_config() {
    let toml = r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = ["read_file", "list_dir", "get_schema"]
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success()
        .code(0)
        .stderr(predicate::str::contains("Config is valid."));
}

// NFR-C1: tool names are exact strings — validate-config accepts any string
#[test]
fn allowlist_with_mixed_case_tool_names_is_accepted() {
    let toml = r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "stdio"

[policy]
allow = ["Read_File", "WRITE_FILE", "execute_SQL"]
"#;
    let fixture = ConfigFixture::new("config.toml", toml);
    Command::from(assert_cmd::cargo_bin_cmd!("mcp-protector"))
        .args(["validate-config", "--config", fixture.path.to_str().unwrap()])
        .assert()
        .success();
}
