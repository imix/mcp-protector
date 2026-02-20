"""
Stdio proxy e2e tests (Epic 9, Story 9.3).

Architecture:
    Python mcp SDK (stdio_client)
        ↓ spawns as subprocess
    mcp-protector proxy  [stdio listen, stdio upstream]
        ↓ spawns as subprocess
    @modelcontextprotocol/server-everything

Policy: allow = ["echo", "get-sum"]
Blocked tool: "get-env"
Audit log: captured from proxy stderr (stdio mode writes audit to stderr)

Neither the upstream nor the client shares code with mcp-protector, so these
tests validate actual protocol interoperability, not just self-consistency.
"""

import json

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from conftest import UPSTREAM_COMMAND


def _proxy_params(proxy_bin, config_path: str) -> StdioServerParameters:
    """Launch mcp-protector as the MCP server process."""
    return StdioServerParameters(
        command=str(proxy_bin),
        args=["proxy", "--config", config_path],
    )


def _make_stdio_config(make_config) -> str:
    """Write the standard stdio-to-stdio config and return its path."""
    return make_config(
        f"""
[upstream]
url = "stdio"
command = {json.dumps(UPSTREAM_COMMAND)}

[listen]
transport = "stdio"

[policy]
allow = ["echo", "get-sum"]
"""
    )


# ── Test 9.3.1 ────────────────────────────────────────────────────────────────


async def test_tools_list_returns_only_allowed_tools(proxy_bin, make_config):
    """
    tools/list must return exactly the tools in the allowlist that are also
    offered by server-everything.

    With allow = ["echo", "get-sum"], only those two must appear.  The server
    provides many others (longRunningOperation, get-env, sampleLLM, …) which
    must all be absent from the filtered response.
    """
    config_path = _make_stdio_config(make_config)
    params = _proxy_params(proxy_bin, config_path)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()

    tool_names = {t.name for t in result.tools}
    assert tool_names == {"echo", "get-sum"}, (
        f"Expected exactly {{echo, get-sum}}, got {tool_names}"
    )


# ── Test 9.3.2 ────────────────────────────────────────────────────────────────


async def test_echo_tool_returns_correct_result(proxy_bin, make_config):
    """
    Calling the allowed 'echo' tool must return the message we sent.

    server-everything's echo tool returns "Echo: {message}" in the first
    content item.
    """
    config_path = _make_stdio_config(make_config)
    params = _proxy_params(proxy_bin, config_path)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("echo", {"message": "hello-from-test"})

    assert not result.isError, f"echo returned an error: {result}"
    assert len(result.content) >= 1, "Expected at least one content item"
    text = result.content[0].text
    assert "hello-from-test" in text, (
        f"Expected echoed message in response, got: {text!r}"
    )


# ── Test 9.3.3 ────────────────────────────────────────────────────────────────


async def test_add_tool_returns_correct_result(proxy_bin, make_config):
    """
    Calling the allowed 'add' tool with a=3, b=4 must return a result
    containing '7'.

    server-everything returns "The sum of 3 and 4 is 7." in the content.
    """
    config_path = _make_stdio_config(make_config)
    params = _proxy_params(proxy_bin, config_path)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-sum", {"a": 3, "b": 4})

    assert not result.isError, f"get-sum returned an error: {result}"
    assert len(result.content) >= 1, "Expected at least one content item"
    text = result.content[0].text
    assert "7" in text, f"Expected '7' in add result, got: {text!r}"


# ── Test 9.3.4 ────────────────────────────────────────────────────────────────


async def test_blocked_tool_call_returns_error(proxy_bin, make_config):
    """
    Calling a tool that is NOT in the allowlist must result in an error.

    The proxy returns ErrorCode.METHOD_NOT_FOUND for blocked calls.  The
    Python SDK may surface this either as:
      - A CallToolResult with isError=True (tool-level error), or
      - An McpError exception (protocol-level JSON-RPC error).

    Either outcome is acceptable — the important invariant is that the call
    does not succeed with normal content.  We accept both representations.

    'get-env' is offered by server-everything but blocked by our policy.
    """
    config_path = _make_stdio_config(make_config)
    params = _proxy_params(proxy_bin, config_path)

    blocked_call_errored = False

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("get-env", {})
                # If call_tool returns (rather than raising), it must be an error result.
                if result.isError:
                    blocked_call_errored = True
                else:
                    # Unexpected success — let the assertion below fail.
                    pass
    except Exception:
        # The SDK raised an exception for the blocked call (protocol-level error).
        blocked_call_errored = True

    assert blocked_call_errored, (
        "Expected blocked tool 'get-env' to result in an error "
        "(isError=True or an exception), but the call succeeded unexpectedly."
    )


# ── Test 9.3.5 ────────────────────────────────────────────────────────────────


async def test_audit_log_records_decisions(proxy_bin, make_config, tmp_path):
    """
    The proxy must emit JSON-Lines audit entries to stderr (stdio mode).

    We perform:
      - tools/list (produces a 'tools_list' event)
      - call blocked tool 'get-env' (produces tool_call with allowed=False)
      - call allowed tool 'echo' (produces tool_call with allowed=True)

    Then we parse stderr and assert the expected entries are present.

    io.StringIO() cannot be used as errlog because anyio.open_process passes
    it to asyncio.create_subprocess_exec as the stderr fd — which requires a
    real file descriptor (fileno()).  We use a real temp file instead.
    """
    config_path = _make_stdio_config(make_config)
    params = _proxy_params(proxy_bin, config_path)

    stderr_file = tmp_path / "proxy_stderr.log"

    with open(stderr_file, "wb") as errlog:
        try:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    await session.list_tools()
                    try:
                        await session.call_tool("get-env", {})
                    except Exception:
                        pass  # Protocol-level error for blocked tool is also acceptable
                    await session.call_tool("echo", {"message": "audit-test"})
        except Exception:
            pass  # Session teardown errors are non-fatal for this test
    # File is closed here; subprocess has exited so all output is flushed.

    content = stderr_file.read_text(errors="replace")

    # Parse all JSON-Lines from stderr; ignore non-JSON lines (tracing output)
    audit_lines = []
    for raw_line in content.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
            if "event" in entry:
                audit_lines.append(entry)
        except json.JSONDecodeError:
            pass  # Tracing diagnostics are not JSON

    events = {e["event"] for e in audit_lines}

    assert "tools_list" in events, (
        f"Expected a 'tools_list' audit entry in stderr; "
        f"events found: {events}\n"
        f"Full stderr:\n{content[:2000]}"
    )

    tool_call_entries = [e for e in audit_lines if e["event"] == "tool_call"]
    blocked = [e for e in tool_call_entries if not e.get("allowed", True)]
    allowed_entries = [e for e in tool_call_entries if e.get("allowed", False)]

    assert any(e.get("tool_name") == "get-env" for e in blocked), (
        f"Expected a blocked 'get-env' audit entry; blocked entries: {blocked}"
    )
    assert any(e.get("tool_name") == "echo" for e in allowed_entries), (
        f"Expected an allowed 'echo' audit entry; allowed entries: {allowed_entries}"
    )
