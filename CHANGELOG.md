# Changelog

All notable changes to mcp-protector are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Configuration system with TOML file format and field-level validation
- `validate-config` subcommand for checking configuration syntax and correctness
- `proxy` subcommand for starting the security proxy
- Stdio transport for both agent and upstream connections (local subprocess mode)
- Tool allowlist policy engine with fail-closed semantics
- JSON-Lines audit logging of all tool calls and tools list requests
- Graceful shutdown with signal handling (SIGTERM, SIGINT)

### Notes

- Only the stdio-to-stdio transport combination is implemented. HTTP agent and HTTPS upstream transports are planned for Epic 3.
- Binary releases will be published on GitHub Releases starting with version v1.0.0.
