# mcp-protector

[![CI](https://github.com/imix/mcp-protector/actions/workflows/ci.yml/badge.svg)](https://github.com/imix/mcp-protector/actions/workflows/ci.yml)

An open-source security proxy for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) written in Rust.

mcp-protector sits between AI agents and MCP servers, enforcing a tool allowlist so that agents can only call the tools you explicitly permit.

## Status

Under active development. See the planning artifacts in `_bmad-output/planning-artifacts/` for the full specification.

## Usage

```bash
mcp-protector proxy --config config/my-config.toml
mcp-protector validate-config --config config/my-config.toml
```

## Configuration

See [`config/example.toml`](config/example.toml) for an annotated example configuration.

## License

MIT OR Apache-2.0
