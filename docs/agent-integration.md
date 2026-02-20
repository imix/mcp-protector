# Using mcp-protector with AI Agents

mcp-protector sits between your AI agent and your MCP servers, enforcing a tool allowlist so agents can only call the tools you explicitly permit. This guide shows you how to integrate mcp-protector with popular AI coding agents by configuring them to connect to mcp-protector instead of the real MCP server.

## How it works

mcp-protector supports two transport patterns:

**Stdio mode**: The agent spawns mcp-protector as a subprocess (exactly as it would spawn a regular MCP server), and mcp-protector in turn spawns the real upstream server. Audit logs go to stderr.

**HTTP mode**: mcp-protector runs as a long-lived service on a TCP port. The agent connects via HTTP. Audit logs go to stdout.

Simple architecture:

```
STDIO MODE:
Agent --> [mcp-protector subprocess] --> [real MCP server subprocess]

HTTP MODE:
Agent --> [HTTP request] --> [mcp-protector service on :port] --> [real server]
```

In both modes, mcp-protector filters tool calls and tool listings based on your `config.toml` allowlist.

## Claude Code

Claude Code connects to MCP servers via the `claude mcp add` command. To use mcp-protector as a wrapper, add it as a stdio server pointing to your `config.toml`.

**For a local upstream MCP server:**

```bash
claude mcp add --transport stdio mcp-protector-wrapped \
  -- /path/to/mcp-protector proxy --config /path/to/config.toml
```

Your `config.toml` should specify the upstream server and allowlist:

```toml
[upstream]
url = "stdio"
command = ["/path/to/real-mcp-server", "--arg1"]

[listen]
transport = "stdio"

[policy]
allow = ["tool1", "tool2", "tool3"]
```

**For a remote HTTP upstream:**

```bash
claude mcp add --transport stdio mcp-protector-wrapped \
  -- /path/to/mcp-protector proxy --config /path/to/config.toml
```

With `config.toml`:

```toml
[upstream]
url = "https://api.example.com/mcp"

[upstream.auth]
type = "bearer"
token = "YOUR_TOKEN_HERE"

[listen]
transport = "stdio"

[policy]
allow = ["search", "fetch_url"]
```

After adding the server, you can use the `/mcp` command in Claude Code to view configured tools and manage authentication.

## VS Code (GitHub Copilot Chat)

VS Code with GitHub Copilot Chat configures MCP servers in `.vscode/mcp.json` (project-level) or in VS Code settings.

Add mcp-protector as a stdio server in `.vscode/mcp.json`:

```json
{
  "servers": {
    "mcp-protector": {
      "command": "/path/to/mcp-protector",
      "args": ["proxy", "--config", "/path/to/config.toml"]
    }
  }
}
```

Your `config.toml` (referenced in the args above):

```toml
[upstream]
url = "stdio"
command = ["/path/to/real-mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["list_files", "read_file", "write_file"]
```

Save the file and restart VS Code. The MCP tools from mcp-protector's filtered allowlist will appear in Copilot Chat.

<!-- NOTE: VS Code MCP configuration format may have changed; verify at https://docs.github.com/copilot/customizing-copilot/using-model-context-protocol/extending-copilot-chat-with-mcp -->

## Cursor

Cursor stores MCP configurations in `.cursor/mcp.json` (project-level) or `~/.cursor/mcp.json` (global).

Add mcp-protector in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "mcp-protector": {
      "command": "/path/to/mcp-protector",
      "args": ["proxy", "--config", "/path/to/config.toml"],
      "env": {}
    }
  }
}
```

Create your `config.toml`:

```toml
[upstream]
url = "stdio"
command = ["/path/to/real-mcp-server", "--option", "value"]

[listen]
transport = "stdio"

[policy]
allow = ["browse_code", "edit_file", "search_codebase"]
```

Restart Cursor. Open the Command Palette (Ctrl/Cmd + Shift + P), search for "View: Open MCP Settings" to see the connected servers and available tools.

## Windsurf

Windsurf's Cascade AI agent reads MCP configurations from `~/.codeium/windsurf/mcp_config.json`.

Add mcp-protector:

```json
{
  "mcpServers": {
    "mcp-protector": {
      "command": "/path/to/mcp-protector",
      "args": ["proxy", "--config", "/path/to/config.toml"],
      "env": {}
    }
  }
}
```

Your `config.toml`:

```toml
[upstream]
url = "stdio"
command = ["/path/to/real-mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["get_code_context", "apply_edits"]
```

Restart Windsurf and click the MCPs icon in the Cascade panel to see available tools.

## Continue

Continue uses YAML configuration in `config.yaml`. Place MCP server configs in `.continue/mcpServers/` or define them inline.

Create `.continue/mcpServers/mcp-protector.yaml`:

```yaml
name: mcp-protector
command: /path/to/mcp-protector
args:
  - proxy
  - --config
  - /path/to/config.toml
```

Or add inline to your `config.yaml`:

```yaml
mcpServers:
  - name: mcp-protector
    command: /path/to/mcp-protector
    args:
      - proxy
      - --config
      - /path/to/config.toml
```

Your `config.toml`:

```toml
[upstream]
url = "stdio"
command = ["/path/to/real-mcp-server"]

[listen]
transport = "stdio"

[policy]
allow = ["code_search", "code_edit"]
```

Restart Continue. In agent mode, the allowed tools will be available for use.

## Generic integration

### Stdio subprocess pattern

Any agent that supports spawning MCP servers as subprocesses can wrap mcp-protector. The agent spawns mcp-protector with `proxy --config <path>`, and mcp-protector handles the JSON-RPC protocol over stdin/stdout.

Agent pseudo-code:

```python
import subprocess
import json

# Start mcp-protector as subprocess
process = subprocess.Popen(
    ["/path/to/mcp-protector", "proxy", "--config", "/path/to/config.toml"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Send JSON-RPC initialize request
init_request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "my-agent",
            "version": "1.0"
        }
    }
}

process.stdin.write(json.dumps(init_request) + "\n")
process.stdin.flush()

# Read response
response = json.loads(process.stdout.readline())
```

mcp-protector logs audit events to stderr in JSON-Lines format (one JSON object per line). Your agent should parse stderr separately.

### HTTP service pattern

For production deployments or shared services, run mcp-protector in HTTP mode and have agents connect via HTTP.

Start mcp-protector:

```bash
/path/to/mcp-protector proxy --config /path/to/config.toml
```

With `config.toml`:

```toml
[upstream]
url = "https://real-server.example.com/mcp"

[upstream.auth]
type = "bearer"
token = "YOUR_TOKEN"

[listen]
transport = "http"
port = 3000

[policy]
allow = ["search", "execute_tool"]
```

Agent connects via HTTP:

```python
import requests

# Initialize the MCP session
init_payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "my-agent",
            "version": "1.0"
        }
    }
}

response = requests.post(
    "http://localhost:3000/mcp",
    json=init_payload
)

result = response.json()
```

mcp-protector writes audit logs to stdout in HTTP mode. Monitor stdout for JSON-Lines audit events.

## Health Checks

In HTTP mode, mcp-protector exposes a `GET /health` endpoint suitable for use in container readiness probes and orchestrator health checks.

| State | Status code | Body |
|-------|-------------|------|
| Upstream connected and ready | 200 OK | `{"status":"ok"}` |
| Upstream handshake in progress | 503 Service Unavailable | `{"status":"starting"}` |

Example systemd or Kubernetes readiness probe:

```bash
curl -sf http://localhost:3000/health
```

The endpoint returns 200 only once the full MCP handshake with the upstream server has succeeded. During the startup window (or if the upstream connection fails) it returns 503. When the upstream connection fails permanently, the proxy exits — so a 503 that persists beyond your expected startup window should be treated as a failure.

## Error Behavior

Understanding what mcp-protector does in each failure mode helps you design reliable integrations:

| Failure mode | Behavior |
|---|---|
| Upstream stdio process exits | Proxy exits — the agent receives a disconnect |
| Upstream HTTPS server unreachable | Proxy exits with exit code 2 |
| Agent disconnects (HTTP mode) | Session is cleaned up; proxy continues serving other agents |
| Config validation failure | Exit code 1; all errors printed to stderr; no connection attempted |
| Tool call blocked by policy | MCP error returned to agent (`METHOD_NOT_FOUND`); proxy continues |
| Audit log channel full | Entry dropped; single `WARN` log emitted; proxy continues |

In stdio mode, the proxy is tied to a single agent connection. When the agent or upstream disconnects, the proxy process exits cleanly.

## Troubleshooting

**Agent cannot connect to mcp-protector**

- Verify mcp-protector binary path is correct and executable.
- For stdio mode, run `mcp-protector proxy --config config.toml` manually in a terminal to check for startup errors.
- For HTTP mode, check that the port is not already in use and that firewall rules allow the connection.

**Tools not appearing in agent**

- Run `mcp-protector validate-config --config config.toml` to check config syntax.
- Verify the `allow` list in the policy section is non-empty and contains valid tool names.
- Check mcp-protector logs (stderr for stdio mode, stdout for HTTP mode) for filtering or protocol errors.

**Upstream connection fails**

- For stdio upstream, verify the command and path are correct and the server starts without errors.
- For HTTP upstream, verify the URL is reachable, the certificate is valid (for HTTPS), and any authentication token is correct.
- Check logs from mcp-protector for connection errors.

**Tools are filtered unexpectedly**

- Verify tool names in the `allow` list match exactly (case-sensitive, byte-for-byte).
- Use audit logs to see which tool names are being requested and compare against your config.

For more details, see the [config schema](config-schema.md) and [audit log schema](audit-log-schema.md).
