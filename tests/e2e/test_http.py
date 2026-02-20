"""
HTTP proxy e2e tests (Epic 9, Story 9.4).

Architecture:
    Python mcp SDK (streamable_http_client → localhost:PORT)
    mcp-protector proxy  [HTTP listen, stdio upstream]
        ↓ spawns as subprocess
    @modelcontextprotocol/server-everything

Policy: allow = ["echo", "get-sum"]
Blocked tool: "get-env"
Audit log: captured from proxy stdout (HTTP mode writes audit to stdout)

The http_proxy fixture (from conftest.py) manages the proxy process lifetime.
The audit test manages its own proxy process directly so it can terminate the
proxy and read stdout before making assertions.
"""

import asyncio
import json

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from conftest import UPSTREAM_COMMAND, wait_for_http_port


def _mcp_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/mcp"


# ── Test 9.4.1 ────────────────────────────────────────────────────────────────


async def test_tools_list_returns_only_allowed_tools(http_proxy):
    """
    tools/list over HTTP must return exactly {echo, add}.

    The proxy filters the full server-everything tool list down to the
    configured allowlist.
    """
    url = _mcp_url(http_proxy["port"])

    async with httpx.AsyncClient() as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()

    tool_names = {t.name for t in result.tools}
    assert tool_names == {"echo", "get-sum"}, (
        f"Expected exactly {{echo, add}}, got {tool_names}"
    )


# ── Test 9.4.2 ────────────────────────────────────────────────────────────────


async def test_echo_tool_returns_correct_result(http_proxy):
    """
    Calling 'echo' over HTTP must return the echoed message.
    """
    url = _mcp_url(http_proxy["port"])

    async with httpx.AsyncClient() as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("echo", {"message": "http-echo-test"})

    assert not result.isError, f"echo returned an error: {result}"
    assert len(result.content) >= 1, "Expected at least one content item"
    text = result.content[0].text
    assert "http-echo-test" in text, (
        f"Expected echoed message in response, got: {text!r}"
    )


# ── Test 9.4.3 ────────────────────────────────────────────────────────────────


async def test_add_tool_returns_correct_result(http_proxy):
    """
    Calling 'add' with a=10, b=32 over HTTP must return a result containing '42'.
    """
    url = _mcp_url(http_proxy["port"])

    async with httpx.AsyncClient() as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("get-sum", {"a": 10, "b": 32})

    assert not result.isError, f"get-sum returned an error: {result}"
    assert len(result.content) >= 1, "Expected at least one content item"
    text = result.content[0].text
    assert "42" in text, f"Expected '42' in add result, got: {text!r}"


# ── Test 9.4.4 ────────────────────────────────────────────────────────────────


async def test_blocked_tool_call_returns_error(http_proxy):
    """
    Calling 'get-env' (not in allowlist) over HTTP must result in an error.

    The proxy returns ErrorCode.METHOD_NOT_FOUND for blocked calls.  The
    Python SDK surfaces this either as isError=True or as an exception —
    both are acceptable.
    """
    url = _mcp_url(http_proxy["port"])

    blocked_call_errored = False

    try:
        async with httpx.AsyncClient() as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("get-env", {})
                    if result.isError:
                        blocked_call_errored = True
    except Exception:
        blocked_call_errored = True

    assert blocked_call_errored, (
        "Expected blocked tool 'get-env' to result in an error "
        "(isError=True or an exception), but the call succeeded."
    )


# ── Test 9.4.5 ────────────────────────────────────────────────────────────────


async def test_audit_log_records_decisions(proxy_bin, free_port, make_config):
    """
    Audit entries in HTTP mode are written to proxy stdout.

    This test manages the proxy process directly (rather than via the
    http_proxy fixture) so it can terminate the proxy and drain stdout
    before making assertions.  The http_proxy fixture populates stdout only
    after the test function returns — too late for in-test assertions.
    """
    config_path = make_config(
        f"""
[upstream]
url = "stdio"
command = {json.dumps(UPSTREAM_COMMAND)}

[listen]
transport = "http"
port = {free_port}

[policy]
allow = ["echo", "get-sum"]
"""
    )

    proc = await asyncio.create_subprocess_exec(
        str(proxy_bin),
        "proxy",
        "--config",
        config_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        await wait_for_http_port(free_port)
        url = _mcp_url(free_port)

        async with httpx.AsyncClient() as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    await session.list_tools()
                    try:
                        await session.call_tool("get-env", {})
                    except Exception:
                        pass  # Protocol-level error is also acceptable
                    await session.call_tool("echo", {"message": "audit-http"})
    finally:
        proc.terminate()
        stdout, _ = await proc.communicate()

    raw_stdout = stdout.decode("utf-8", errors="replace")

    audit_lines = []
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if "event" in entry:
                audit_lines.append(entry)
        except json.JSONDecodeError:
            pass

    events = {e["event"] for e in audit_lines}

    assert "tools_list" in events, (
        f"Expected 'tools_list' audit entry in stdout; events: {events}\n"
        f"Full stdout:\n{raw_stdout[:2000]}"
    )

    tool_calls = [e for e in audit_lines if e["event"] == "tool_call"]
    blocked = [e for e in tool_calls if not e.get("allowed", True)]
    allowed_entries = [e for e in tool_calls if e.get("allowed", False)]

    assert any(e.get("tool_name") == "get-env" for e in blocked), (
        f"Expected blocked 'get-env' audit entry; blocked: {blocked}"
    )
    assert any(e.get("tool_name") == "echo" for e in allowed_entries), (
        f"Expected allowed 'echo' audit entry; allowed: {allowed_entries}"
    )
