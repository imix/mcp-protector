# mcp-protector

[![CI](https://github.com/imix/mcp-protector/actions/workflows/ci.yml/badge.svg)](https://github.com/imix/mcp-protector/actions/workflows/ci.yml)

An open-source security proxy for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) written in Rust.

mcp-protector sits between AI agents and MCP servers, enforcing a tool allowlist so that agents can only call the tools you explicitly permit.

## Installation

### Pre-compiled binary (recommended)

Download the latest release for your platform from the [GitHub Releases page](https://github.com/imix/mcp-protector/releases), extract the archive, and place the binary on your `$PATH`:

| Platform | Archive |
|---|---|
| Linux x86\_64 | `mcp-protector-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `mcp-protector-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `mcp-protector-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `mcp-protector-aarch64-apple-darwin.tar.gz` |
| Windows x86\_64 | `mcp-protector-x86_64-pc-windows-msvc.zip` |

### From source

Clone the repository and build with Cargo:

```bash
cargo build --release
```

Then install the binary:

```bash
cargo install --path .
```

The resulting binary is `mcp-protector`.

## Quickstart

### 1. Write a configuration file

Create a TOML file describing your upstream MCP server and the tools you want to allow. Here's a minimal example for a local subprocess:

```toml
[upstream]
url = "stdio"
command = ["/path/to/mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["read_file", "list_dir"]
```

Save this as `config.toml`.

### 2. Validate the configuration

Run the validate-config subcommand to check for errors:

```bash
mcp-protector validate-config --config config.toml
```

Output: `Config is valid.` (on stderr) if successful.

### 3. Start the proxy

Launch the proxy to begin forwarding MCP traffic:

```bash
mcp-protector proxy --config config.toml
```

The proxy listens on stdio (in this example) and forwards requests to the upstream server, filtering tool calls and listings according to your allowlist. Audit log entries are written to stderr.

## Configuration

See [`docs/config-schema.md`](docs/config-schema.md) for the complete TOML configuration schema, including all supported fields, types, and constraints.

A commented example configuration is available at [`config/example.toml`](config/example.toml).

## Audit Logging

Every tool call and tools listing request is recorded in JSON-Lines format. See [`docs/audit-log-schema.md`](docs/audit-log-schema.md) for the complete audit event schema, field descriptions, and examples.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success — clean shutdown or `validate-config` passed |
| 1    | Configuration error — all field-level errors are printed to stderr before exit |
| 2    | Runtime error — proxy failed after startup; details are in the tracing output |

Automation scripts and health-check wrappers can rely on these codes to distinguish misconfiguration from runtime failure.

## Agent Integration

Ready to integrate mcp-protector with your AI agent? See [`docs/agent-integration.md`](docs/agent-integration.md) for setup instructions for Claude Code, VS Code, Cursor, Windsurf, Continue, and generic SDK patterns.

## Logging

mcp-protector uses the `RUST_LOG` environment variable to control log verbosity. All tracing output goes to stderr (safe in both stdio and HTTP modes):

```bash
# Debug-level output for mcp-protector
RUST_LOG=mcp_protector=debug mcp-protector proxy --config config.toml

# Quiet (warnings only)
RUST_LOG=warn mcp-protector proxy --config config.toml
```

See [`docs/debugging.md`](docs/debugging.md) for more examples and troubleshooting tips.

## Security

mcp-protector enforces a **fail-closed** security model:

- **Allowlist semantics**: Only tools explicitly listed in the `allow` configuration field can be called. Matching is case-sensitive and byte-for-byte exact.
- **Empty allowlist blocks all**: If the allowlist is empty, all tool calls are rejected.
- **No credentials in config**: Bearer tokens and other sensitive values are stored in memory with automatic zeroization on drop, never written to logs or debug output.
- **HTTPS support**: When configured with an upstream HTTPS URL, the proxy validates the server certificate using the system's native certificate store.

## License

MIT OR Apache-2.0
