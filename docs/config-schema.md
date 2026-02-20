# Configuration Schema

Schema version: **1**

All mcp-protector configuration is specified in a single TOML file, supplied via the `--config` flag. Backwards-incompatible schema changes require a major version number bump.

## Sections

The configuration file consists of three required sections: `[upstream]`, `[listen]`, and `[policy]`.

### `[upstream]` — Upstream MCP Server

Specifies how to connect to the upstream MCP server.

#### `url` (string, required)

The upstream server location. Must be one of:

- `"stdio"` — Local subprocess communication via standard input/output.
- `"https://..."` — Remote HTTPS server. Must be a valid HTTPS URL with a non-empty host and no userinfo component (no credentials embedded in the URL).

#### `command` (array of strings, required when url = "stdio")

The command to spawn as the upstream subprocess. The first element is the executable path, followed by any arguments.

Example:
```toml
command = ["/usr/local/bin/my-mcp-server", "--flag", "value"]
```

This field is ignored when `url` is an HTTPS URL.

#### `[upstream.auth]` (table, optional)

Authentication credentials for HTTPS upstreams. Only valid when `url` is an `https://` URL.

##### `type` (string, required when auth is present)

Authentication method. Currently only `"bearer"` is supported.

##### `token` (string, required when type = "bearer")

The bearer token value. Stored securely in memory with zeroization-on-drop. Never written to logs or debug output.

Example:
```toml
[upstream.auth]
type = "bearer"
token = "YOUR_TOKEN_HERE"
```

### `[listen]` — Agent Listener

Specifies how the proxy accepts connections from agents.

#### `transport` (string, required)

The transport protocol. Must be one of:

- `"stdio"` — Accept a single agent connection via the process's own standard input/output.
- `"http"` — Accept HTTP agent connections on a TCP port.

#### `port` (integer, required when transport = "http")

TCP port to listen on. Valid range: 1–65535.

Example:
```toml
[listen]
transport = "http"
port = 3000
```

This field is ignored when `transport` is `"stdio"`.

### `[policy]` — Tool Allowlist

Specifies which tools agents are permitted to call.

#### `allow` (array of strings, required)

List of tool names to permit. The proxy will:

- Allow only tools explicitly listed in this array.
- Apply case-sensitive, byte-for-byte exact matching against tool names.
- Block all tool calls if the array is empty (fail-closed).
- Return only the intersection of upstream tools and this allowlist in `tools/list` responses.

Example:
```toml
[policy]
allow = ["read_file", "list_dir", "get_time"]
```

## Complete annotated example

```toml
# mcp-protector configuration

[upstream]
# How to reach the upstream MCP server.
# Use "stdio" for a local subprocess, or "https://..." for a remote server.
url = "stdio"

# Command to run as the subprocess (required when url = "stdio").
# First element is the executable path; remaining elements are arguments.
command = ["/usr/local/bin/my-mcp-server", "--debug"]

# Optional: bearer token for HTTPS upstreams (only valid with https:// urls).
# The token is stored securely and never logged.
# [upstream.auth]
# type = "bearer"
# token = "sk-your-token-here"

[listen]
# How the proxy accepts agent connections.
# Either "stdio" (single agent via process stdio) or "http" (multiple agents via TCP).
transport = "stdio"

# TCP port (required when transport = "http").
# port = 3000

[policy]
# Tool allowlist: only these tools can be called by agents.
# Matching is case-sensitive and byte-for-byte exact.
# An empty list blocks all tools.
allow = ["read_file", "list_dir"]
```

## Validation

Validate your configuration file without starting the proxy:

```bash
mcp-protector validate-config --config config.toml
```

The command exits with code 0 and prints `Config is valid.` to stderr if successful. Otherwise it prints one or more field-level error messages and exits with code 1.

## Field validation rules

| Field | Requirement |
|-------|------------|
| `upstream.url` | One of `"stdio"` or a valid `https://...` URL. No userinfo allowed. |
| `upstream.command` | Non-empty array when `url = "stdio"`. |
| `upstream.auth.type` | Must be `"bearer"` if present. |
| `upstream.auth.token` | Non-empty string when `type = "bearer"`. |
| `listen.transport` | One of `"stdio"` or `"http"`. |
| `listen.port` | Integer in range 1–65535, required when `transport = "http"`. |
| `policy.allow` | Array of strings (may be empty). |
