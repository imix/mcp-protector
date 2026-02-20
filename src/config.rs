//! Configuration loading and validation.
//!
//! Reads a TOML file from the path supplied via the CLI `--config` flag, fully
//! validates all fields, and returns a typed [`Config`] value.  The proxy must
//! never open any network connection before this module returns successfully.
//!
//! # Config file structure
//!
//! ```toml
//! [upstream]
//! url = "stdio"                  # or "https://..." for HTTPS upstream
//! command = ["/path/to/server"] # required when url = "stdio"
//!
//! [upstream.auth]               # optional; only valid for HTTPS upstreams
//! type = "bearer"
//! token = "YOUR_TOKEN_HERE"
//!
//! [listen]
//! transport = "stdio"           # or "http"
//! port = 3000                   # required when transport = "http"
//!
//! [policy]
//! allow = ["read_file"]         # exact tool names to permit; empty blocks all
//! ```


use std::collections::HashSet;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretBox};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

// ── Public error type ─────────────────────────────────────────────────────────

/// Errors returned by [`load`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config file '{path}': {source}")]
    ReadFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The config file could not be parsed as valid TOML.
    #[error("failed to parse config file '{path}': {source}")]
    ParseFailed {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// A specific config field has an invalid value.
    #[error("invalid config field '{field}': {reason}")]
    InvalidField { field: String, reason: String },
}

// ── Public typed config structs ───────────────────────────────────────────────

/// Fully validated, typed configuration for one proxy instance.
#[derive(Debug)]
pub struct Config {
    /// How to connect to the upstream MCP server.
    pub upstream: UpstreamConfig,
    /// How to accept agent connections.
    pub listen: ListenConfig,
    /// Which tools agents are permitted to call.
    pub policy: PolicyConfig,
}

/// Upstream MCP server connection method.
#[derive(Debug)]
pub enum UpstreamConfig {
    /// Spawn a local subprocess and communicate via its stdio.
    Stdio {
        /// Argv for the subprocess.  The first element is the executable path.
        command: Vec<String>,
    },
    /// Connect to a remote server over HTTPS.
    ///
    /// `url` and `auth` are consumed by `transport/upstream_https.rs` (Epic 3).
    Https {
        /// Full `https://` URL of the upstream MCP endpoint.
        // Used in Epic 3 (upstream_https.rs); field exists today so the enum
        // variant compiles and the proxy.rs match arm returns an error.
        #[allow(dead_code)]
        url: String,
        /// Optional bearer token authentication.
        // Used in Epic 3 (upstream_https.rs).
        #[allow(dead_code)]
        auth: Option<UpstreamAuth>,
    },
}

/// Bearer token authentication for an HTTPS upstream.
///
/// The token is stored as a [`SecretBox<String>`] so that it never appears in
/// `{:?}` debug output or tracing spans (NFR-S2).
#[derive(Debug)]
pub struct UpstreamAuth {
    /// The bearer token value.  Call `.expose_secret()` only at the HTTP
    /// request injection point in `transport/upstream_https.rs` (Epic 3).
    // Read by upstream_https.rs in Epic 3.
    #[allow(dead_code)]
    pub bearer_token: SecretBox<String>,
}

/// Agent-side listener configuration.
#[derive(Debug)]
pub enum ListenConfig {
    /// Accept a single agent connection via the process's own stdio.
    Stdio,
    /// Accept HTTP agent connections on the given TCP port.
    Http {
        /// TCP port to bind (1–65535).
        ///
        /// Consumed by `transport/agent_http.rs` (Epic 3).
        // Read by agent_http.rs in Epic 3.
        #[allow(dead_code)]
        port: u16,
    },
}

/// Tool allowlist policy.
#[derive(Debug)]
pub struct PolicyConfig {
    /// Exact tool names that agents are permitted to call.
    ///
    /// An empty set means *all* tool calls are blocked (FR8, fail-closed).
    pub allow: HashSet<String>,
}

// ── Raw TOML deserialization structs (private) ────────────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    upstream: RawUpstreamConfig,
    listen: RawListenConfig,
    policy: RawPolicyConfig,
}

#[derive(Deserialize)]
struct RawUpstreamConfig {
    url: String,
    command: Option<Vec<String>>,
    auth: Option<RawAuth>,
}

#[derive(Deserialize)]
struct RawAuth {
    #[serde(rename = "type")]
    auth_type: String,
    token: Option<SecretBox<String>>,
}

#[derive(Deserialize)]
struct RawListenConfig {
    transport: String,
    /// Stored as u32 so we can detect values that exceed `u16::MAX` and report a
    /// human-readable validation error rather than a TOML parse error.
    port: Option<u32>,
}

#[derive(Deserialize)]
struct RawPolicyConfig {
    allow: Vec<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load and validate the configuration file at `path`.
///
/// Returns a fully-typed [`Config`] on success, or one or more [`ConfigError`]
/// values describing every invalid field found.
///
/// # Errors
///
/// - [`ConfigError::ReadFailed`] if the file cannot be read.
/// - [`ConfigError::ParseFailed`] if the file is not valid TOML.
/// - One or more [`ConfigError::InvalidField`] if individual fields are invalid.
///   All invalid fields are reported at once rather than stopping at the first.
pub fn load(path: &Path) -> Result<Config, Vec<ConfigError>> {
    // Guard: reject symlinks to prevent arbitrary file reads via symlink planting.
    // Note: there is an inherent TOCTOU window between this check and read_to_string;
    // the guard still eliminates the most practical attack vectors.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(vec![ConfigError::ReadFailed {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "config path must not be a symlink",
                ),
            }]);
        }
        _ => {}
    }

    // Warn if parent directories traverse symlinks (path confusion vector).
    if let Ok(abs) = std::path::absolute(path) {
        if let Ok(canonical) = std::fs::canonicalize(path) {
            if abs != canonical {
                tracing::warn!(
                    input = %abs.display(),
                    resolved = %canonical.display(),
                    "config path traverses symbolic links in parent directories"
                );
            }
        }
    }

    let content = std::fs::read_to_string(path).map_err(|source| {
        vec![ConfigError::ReadFailed {
            path: path.to_path_buf(),
            source,
        }]
    })?;

    let raw: RawConfig = toml::from_str(&content).map_err(|source| {
        vec![ConfigError::ParseFailed {
            path: path.to_path_buf(),
            source,
        }]
    })?;

    let errors = validate(&raw);
    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(build_config(raw))
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validate all fields in `raw` and collect every error found.
///
/// Returns an empty `Vec` when the config is fully valid.
fn validate(raw: &RawConfig) -> Vec<ConfigError> {
    let mut errors = Vec::new();

    // ── upstream.url ──────────────────────────────────────────────────────────
    let url_is_stdio = raw.upstream.url == "stdio";
    // For HTTPS URLs, use url::Url::parse to enforce structural validity:
    // non-empty host, no userinfo component (prevents SSRF via malformed URLs).
    if !url_is_stdio {
        if raw.upstream.url.starts_with("https://") {
            match Url::parse(&raw.upstream.url) {
                Ok(parsed)
                    if parsed.host().is_some()
                        && parsed.username().is_empty()
                        && parsed.password().is_none() => {}
                _ => {
                    errors.push(ConfigError::InvalidField {
                        field: "upstream.url".to_owned(),
                        reason: format!(
                            "'{}' is not a valid HTTPS URL (must have a non-empty host and no userinfo)",
                            raw.upstream.url
                        ),
                    });
                }
            }
        } else {
            errors.push(ConfigError::InvalidField {
                field: "upstream.url".to_owned(),
                reason: format!(
                    "expected 'stdio' or an 'https://' URL, got '{}'",
                    raw.upstream.url
                ),
            });
        }
    }

    // ── upstream.command ──────────────────────────────────────────────────────
    if url_is_stdio {
        let command_missing = raw
            .upstream
            .command
            .as_ref()
            .is_none_or(Vec::is_empty);
        if command_missing {
            errors.push(ConfigError::InvalidField {
                field: "upstream.command".to_owned(),
                reason: "required when upstream.url is 'stdio'".to_owned(),
            });
        }
    }

    // ── upstream.auth ─────────────────────────────────────────────────────────
    if let Some(auth) = &raw.upstream.auth {
        if auth.auth_type != "bearer" {
            errors.push(ConfigError::InvalidField {
                field: "upstream.auth.type".to_owned(),
                reason: format!(
                    "unknown value '{}'; expected 'bearer'",
                    auth.auth_type
                ),
            });
        } else if auth.token.is_none() {
            errors.push(ConfigError::InvalidField {
                field: "upstream.auth.token".to_owned(),
                reason: "required when upstream.auth.type is 'bearer'".to_owned(),
            });
        } else {
            // This is the only sanctioned expose_secret() call in config.rs —
            // used solely to validate that the credential is non-empty.
            let token = auth.token.as_ref().expect("token is Some — checked above");
            if token.expose_secret().trim().is_empty() {
                errors.push(ConfigError::InvalidField {
                    field: "upstream.auth.token".to_owned(),
                    reason: "must not be empty or whitespace".to_owned(),
                });
            }
        }
    }

    // ── listen.transport ──────────────────────────────────────────────────────
    let transport_is_http = raw.listen.transport == "http";
    let transport_is_stdio = raw.listen.transport == "stdio";
    if !transport_is_http && !transport_is_stdio {
        errors.push(ConfigError::InvalidField {
            field: "listen.transport".to_owned(),
            reason: format!(
                "unknown value '{}'; expected 'stdio' or 'http'",
                raw.listen.transport
            ),
        });
    }

    // ── listen.port ───────────────────────────────────────────────────────────
    if transport_is_http && raw.listen.port.is_none() {
        errors.push(ConfigError::InvalidField {
            field: "listen.port".to_owned(),
            reason: "required when transport is 'http'".to_owned(),
        });
    }
    if let Some(port) = raw.listen.port {
        if !(1..=u32::from(u16::MAX)).contains(&port) {
            errors.push(ConfigError::InvalidField {
                field: "listen.port".to_owned(),
                reason: format!("{port} is not a valid port number (must be 1–65535)"),
            });
        }
    }

    errors
}

// ── Config builder ────────────────────────────────────────────────────────────

/// Convert a validated [`RawConfig`] into the public [`Config`] type.
///
/// # Panics
///
/// Panics if called on an un-validated `RawConfig` that fails invariants the
/// validator is responsible for enforcing.  This cannot happen when `load` is
/// used as the entry point.
fn build_config(raw: RawConfig) -> Config {
    let upstream = if raw.upstream.url == "stdio" {
        UpstreamConfig::Stdio {
            command: raw
                .upstream
                .command
                .unwrap_or_default(),
        }
    } else {
        let auth = raw.upstream.auth.map(|a| UpstreamAuth {
            // INVARIANT: token is Some when auth_type == "bearer"; enforced by validate()
            bearer_token: a
                .token
                .expect("bearer token present — validated in validate()"),
        });
        UpstreamConfig::Https {
            url: raw.upstream.url,
            auth,
        }
    };

    let listen = if raw.listen.transport == "http" {
        // INVARIANT: port is Some and ≤ 65535; enforced by validate()
        let port = u16::try_from(
            raw.listen
                .port
                .expect("port present for http transport — validated in validate()"),
        )
        .expect("port ≤ 65535 — validated in validate()");
        ListenConfig::Http { port }
    } else {
        ListenConfig::Stdio
    };

    let policy = PolicyConfig {
        allow: raw.policy.allow.into_iter().collect(),
    };

    Config {
        upstream,
        listen,
        policy,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp_config(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    const VALID_STDIO_CONFIG: &str = r#"
[upstream]
url = "stdio"
command = ["/usr/local/bin/mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["read_file", "list_dir"]
"#;

    const VALID_HTTPS_CONFIG: &str = r#"
[upstream]
url = "https://example.com/mcp"

[listen]
transport = "http"
port = 3000

[policy]
allow = ["read_file"]
"#;

    // ── Story 1.2: Config file parsing ────────────────────────────────────────

    #[test]
    fn load_valid_stdio_config_returns_ok() {
        let (_f, path) = write_temp_config(VALID_STDIO_CONFIG);
        assert!(load(&path).is_ok());
    }

    #[test]
    fn stdio_url_produces_stdio_variant() {
        let (_f, path) = write_temp_config(VALID_STDIO_CONFIG);
        let config = load(&path).unwrap();
        assert!(matches!(config.upstream, UpstreamConfig::Stdio { .. }));
    }

    #[test]
    fn https_url_produces_https_variant() {
        let (_f, path) = write_temp_config(VALID_HTTPS_CONFIG);
        let config = load(&path).unwrap();
        assert!(matches!(config.upstream, UpstreamConfig::Https { .. }));
    }

    #[test]
    fn https_url_preserved_exactly() {
        let (_f, path) = write_temp_config(VALID_HTTPS_CONFIG);
        let config = load(&path).unwrap();
        let UpstreamConfig::Https { url, .. } = config.upstream else {
            panic!("expected Https variant");
        };
        assert_eq!(url, "https://example.com/mcp");
    }

    #[test]
    fn allowlist_parsed_as_hashset() {
        let (_f, path) = write_temp_config(VALID_STDIO_CONFIG);
        let config = load(&path).unwrap();
        assert_eq!(config.policy.allow.len(), 2);
        assert!(config.policy.allow.contains("read_file"));
        assert!(config.policy.allow.contains("list_dir"));
    }

    #[test]
    fn bearer_token_stored_as_secret_not_visible_in_debug() {
        let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "bearer"
token = "s3cr3t"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let config = load(&path).unwrap();
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("s3cr3t"), "token must not appear in debug output");
    }

    #[test]
    fn bearer_token_auth_variant_is_some() {
        let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "bearer"
token = "mytoken"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let config = load(&path).unwrap();
        let UpstreamConfig::Https { auth, .. } = config.upstream else {
            panic!("expected Https variant");
        };
        assert!(auth.is_some());
    }

    // ── Story 1.3: Validation with field-level errors ─────────────────────────

    #[test]
    fn missing_port_for_http_transport_reports_error() {
        let toml = r#"
[upstream]
url = "stdio"
command = ["/bin/srv"]

[listen]
transport = "http"

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let errors = load(&path).unwrap_err();
        let field_error = errors.iter().find(|e| {
            matches!(e, ConfigError::InvalidField { field, .. } if field == "listen.port")
        });
        assert!(
            field_error.is_some(),
            "expected error for listen.port, got: {errors:?}"
        );
        let ConfigError::InvalidField { reason, .. } = field_error.unwrap() else {
            unreachable!()
        };
        assert!(
            reason.contains("required when transport is 'http'"),
            "unexpected reason: {reason}"
        );
    }

    #[test]
    fn unsupported_auth_type_reports_error() {
        let toml = r#"
[upstream]
url = "https://example.com/mcp"

[upstream.auth]
type = "basic"
token = "user:pass"

[listen]
transport = "stdio"

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let errors = load(&path).unwrap_err();
        let field_error = errors.iter().find(|e| {
            matches!(e, ConfigError::InvalidField { field, .. } if field == "upstream.auth.type")
        });
        assert!(
            field_error.is_some(),
            "expected error for upstream.auth.type, got: {errors:?}"
        );
        let ConfigError::InvalidField { reason, .. } = field_error.unwrap() else {
            unreachable!()
        };
        assert!(
            reason.contains("unknown value 'basic'"),
            "unexpected reason: {reason}"
        );
    }

    #[test]
    fn port_exceeding_max_reports_error() {
        let toml = r#"
[upstream]
url = "https://example.com/mcp"

[listen]
transport = "http"
port = 99999

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let errors = load(&path).unwrap_err();
        let field_error = errors.iter().find(|e| {
            matches!(e, ConfigError::InvalidField { field, reason, .. }
                if field == "listen.port" && reason.contains("valid port number"))
        });
        assert!(
            field_error.is_some(),
            "expected listen.port 'valid port number' error, got: {errors:?}"
        );
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
        let (_f, path) = write_temp_config(toml);
        assert!(load(&path).is_ok(), "empty allowlist must be valid");
    }

    #[test]
    fn multiple_invalid_fields_each_produce_error() {
        // Both listen.port missing (http) AND upstream.url invalid
        let toml = r#"
[upstream]
url = "ftp://bad"
command = ["/bin/srv"]

[listen]
transport = "http"

[policy]
allow = []
"#;
        let (_f, path) = write_temp_config(toml);
        let errors = load(&path).unwrap_err();
        assert!(
            errors.len() >= 2,
            "expected ≥2 errors for two invalid fields, got: {errors:?}"
        );
    }

    #[test]
    fn missing_config_file_returns_read_failed() {
        let path = PathBuf::from("/nonexistent-mcp-protector-test-file.toml");
        let errors = load(&path).unwrap_err();
        assert!(
            matches!(errors[0], ConfigError::ReadFailed { .. }),
            "expected ReadFailed, got: {:?}",
            errors[0]
        );
    }
}
