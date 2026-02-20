# Debugging Guide

mcp-protector uses the [`tracing`](https://docs.rs/tracing) crate for structured diagnostics. All tracing output goes to **stderr**, regardless of transport mode — so it never interferes with the MCP protocol channel (stdout in stdio mode) or the audit log (stdout in HTTP mode).

## Controlling log verbosity with `RUST_LOG`

Set the `RUST_LOG` environment variable before starting the proxy. The variable accepts a comma-separated list of `target=level` directives. Valid levels are `error`, `warn`, `info`, `debug`, and `trace`.

### Common examples

**Default (info level — recommended for production):**

```bash
mcp-protector proxy --config config.toml
```

**Debug-level output for mcp-protector only:**

```bash
RUST_LOG=mcp_protector=debug mcp-protector proxy --config config.toml
```

**Warn-only output (quieter logs):**

```bash
RUST_LOG=warn mcp-protector proxy --config config.toml
```

**Full trace output including dependencies (very verbose):**

```bash
RUST_LOG=trace mcp-protector proxy --config config.toml
```

**Mix: debug for mcp-protector, warn for everything else:**

```bash
RUST_LOG=warn,mcp_protector=debug mcp-protector proxy --config config.toml
```

> **Note:** The crate name for filter purposes is `mcp_protector` (underscore, not hyphen).

## What each level shows

| Level | Examples |
|-------|---------|
| `error` | Unrecoverable runtime errors |
| `warn` | Upstream process failures, blocked connections, dropped audit entries |
| `info` | Proxy started, transport selected, graceful shutdown initiated (default) |
| `debug` | Upstream process exit status, TLS certificate store summary, session lifecycle |
| `trace` | Internal message routing (rarely needed) |

## Validating configuration

Before starting the proxy, check the config file for errors:

```bash
mcp-protector validate-config --config config.toml
```

Exits 0 and prints `Config is valid.` if successful. Exits 1 and prints all field-level errors if not.

## Checking audit log output

In stdio mode, audit logs appear on stderr interleaved with tracing output. Redirect stderr to a file to separate them:

```bash
mcp-protector proxy --config config.toml 2>proxy.log
```

In HTTP mode, audit logs appear on stdout as JSON-Lines. Pipe stdout to `jq` for pretty-printing during development:

```bash
mcp-protector proxy --config config.toml | jq .
```

See [`audit-log-schema.md`](audit-log-schema.md) for the full schema.

## Common issues

**"no native root certificates could be loaded"**

The proxy could not load any TLS certificates from the system's native CA store. Run with `RUST_LOG=mcp_protector=debug` to see individual certificate load errors. Ensure the system certificate store is installed (e.g. `ca-certificates` on Debian/Ubuntu).

**"upstream MCP handshake failed"**

The upstream server started but did not complete the MCP `initialize` handshake. Verify the upstream command is a valid MCP server by running it manually.

**Audit entries not appearing**

In stdio mode, ensure you are reading stderr, not stdout. In HTTP mode, ensure you are reading stdout. The audit channel holds up to 4 096 entries; if the consumer is too slow, entries may be dropped with a `warn` log.
