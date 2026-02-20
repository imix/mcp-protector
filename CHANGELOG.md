# Changelog

All notable changes to mcp-protector are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-02-20

### Added

- Configuration system with TOML file format and field-level validation
- `validate-config` subcommand for checking configuration syntax and correctness
- `proxy` subcommand for starting the security proxy
- Stdio transport for both agent and upstream connections (local subprocess mode)
- HTTP agent transport: accepts MCP connections on a configurable TCP port (`listen.transport = "http"`)
- HTTPS upstream transport: connects to remote MCP servers over TLS using system certificate store (`upstream.url = "https://..."`)
- Bearer token authentication for HTTPS upstreams (`upstream.auth.type = "bearer"`)
- `GET /health` endpoint returning `{"status":"ok"}` when running in HTTP transport mode
- Tool allowlist policy engine with fail-closed semantics
- JSON-Lines audit logging of all tool calls and tools list requests (stderr in stdio mode, stdout in HTTP mode)
- Graceful shutdown with signal handling (SIGTERM, SIGINT)
- `RUST_LOG` environment variable support for controlling log verbosity
- Pre-compiled binaries for Linux (x86\_64, aarch64), macOS (x86\_64, Apple Silicon), and Windows (x86\_64) published on GitHub Releases
