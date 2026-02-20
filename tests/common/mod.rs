//! Shared helpers for integration tests.

use std::path::PathBuf;

use tempfile::TempDir;

/// A temporary directory that owns a set of config fixture files.
///
/// The [`TempDir`] is kept alive for the lifetime of this struct; dropping it
/// removes all files.
pub struct ConfigFixture {
    _dir: TempDir,
    pub path: PathBuf,
}

impl ConfigFixture {
    /// Write `content` to a file named `filename` in a fresh temporary
    /// directory and return a fixture pointing at that file.
    pub fn new(filename: &str, content: &str) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join(filename);
        std::fs::write(&path, content).expect("write fixture file");
        Self { _dir: dir, path }
    }
}

/// Minimal valid stdio-to-stdio config TOML.
// Used across integration test binaries; each binary compiles common independently,
// so the constant may be unused in any single binary — not a real dead_code issue.
#[allow(dead_code)]
pub const VALID_STDIO: &str = r#"
[upstream]
url = "stdio"
command = ["/usr/local/bin/mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["read_file", "list_dir"]
"#;

/// Minimal valid HTTPS config TOML with HTTP listener.
// Used across integration test binaries; see VALID_STDIO comment above.
#[allow(dead_code)]
pub const VALID_HTTPS: &str = r#"
[upstream]
url = "https://example.com/mcp"

[listen]
transport = "http"
port = 3000

[policy]
allow = ["read_file"]
"#;
