# Audit Log Schema

mcp-protector emits one JSON-Lines record per `tools/call` and `tools/list`
request to the audit output stream (stderr in stdio transport mode; stdout in
HTTP transport mode).  Each record is a single line of valid JSON followed by a
newline character (`\n`).

## Format

```
{schema-version-fields},{event-type-fields}\n
```

## Schema version

The current schema version is **2**.  The `version` field will be incremented
when breaking changes are made to the schema contract.

**Version history:**
- **2** — Added `agent_auth_rejected` and `agent_connected` events (Epic 5,
  bearer token agent authentication).
- **1** — Initial schema (`tool_call`, `tools_list` events).

## Common fields

Every record contains these fields regardless of event type.

| Field        | Type   | Description                                                                            |
|--------------|--------|----------------------------------------------------------------------------------------|
| `version`    | number | Schema version (currently `2`).                                                        |
| `timestamp`  | string | ISO 8601 / RFC 3339 UTC timestamp, e.g. `"2026-02-19T16:00:00.000Z"`.                 |
| `event`      | string | Event type discriminator — see event types below.                                      |
| `session_id` | string | Monotonically increasing decimal-string identifying this proxy session (e.g. `"1"`). `"0"` is used for pre-session events such as auth rejections. |
| `upstream`   | string | Display name of the upstream MCP server (basename of the command executable).         |

## Event: `tool_call`

Emitted for every `tools/call` request received from the agent.

| Field       | Type    | Description                                            |
|-------------|---------|--------------------------------------------------------|
| `tool_name` | string  | Name of the tool requested by the agent.               |
| `allowed`   | boolean | `true` if the tool is in the allowlist; `false` otherwise. |

### Example

```json
{"version":2,"timestamp":"2026-02-19T16:00:00.000Z","event":"tool_call","session_id":"42","upstream":"my-server","tool_name":"read_file","allowed":true}
```

```json
{"version":2,"timestamp":"2026-02-19T16:00:01.123Z","event":"tool_call","session_id":"42","upstream":"my-server","tool_name":"delete_all","allowed":false}
```

## Event: `tools_list`

Emitted for every `tools/list` request received from the agent.

| Field            | Type   | Description                                                   |
|------------------|--------|---------------------------------------------------------------|
| `tools_upstream` | number | Number of tools returned by the upstream MCP server.          |
| `tools_returned` | number | Number of tools returned to the agent after policy filtering. |

### Example

```json
{"version":2,"timestamp":"2026-02-19T16:00:00.000Z","event":"tools_list","session_id":"42","upstream":"my-server","tools_upstream":10,"tools_returned":3}
```

## Event: `agent_auth_rejected`

Emitted when an incoming HTTP agent connection is rejected due to a failed
authentication check (missing or incorrect bearer token).

| Field    | Type   | Description |
|----------|--------|-------------|
| `method` | string | Authentication method that was attempted (`"bearer"`). |
| `reason` | string | Human-readable reason for rejection. Never contains secret material. |

`session_id` is `"0"` for these events — no session has been established yet.

### Example

```json
{"version":2,"timestamp":"2026-02-19T16:00:00.000Z","event":"agent_auth_rejected","session_id":"0","upstream":"my-server","method":"bearer","reason":"missing Authorization header"}
```

## Event: `agent_connected`

Emitted when a new agent session is successfully established.

| Field      | Type            | Description |
|------------|-----------------|-------------|
| `method`   | string          | Authentication method used (`"bearer"`, `"none"`). |
| `identity` | string or null  | Agent identity when available (populated by mTLS/OIDC in future epics; `null` for bearer-token and unauthenticated sessions). |

### Example

```json
{"version":2,"timestamp":"2026-02-19T16:00:01.000Z","event":"agent_connected","session_id":"1","upstream":"my-server","method":"bearer","identity":null}
```

## Notes

- Field order within each JSON object is not guaranteed.
- Consumers must not rely on field order; use key-based access.
- The `session_id` counter starts at 1 and increments atomically per process
  invocation.  It is not persisted across restarts.  The value `"0"` is
  reserved for pre-session events (auth rejections).
- Timestamps use `chrono::Utc::now()` and are serialised in the format
  `YYYY-MM-DDTHH:MM:SS.sssZ` (millisecond precision).
- All string values are UTF-8.
- Number values fit in a 32-bit unsigned integer.
