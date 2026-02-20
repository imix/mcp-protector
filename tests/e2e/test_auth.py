"""
Authentication e2e tests (Epic 9, Story 9.5).

These tests verify that bearer token and IP allowlist enforcement work
end-to-end at the MCP protocol level — not just at the HTTP layer as
tested by the existing Rust bearer_auth.rs and ip_allowlist.rs tests.

A failing auth check must prevent the MCP session from being established.
The proxy rejects unauthenticated connections at the HTTP middleware layer
(before any MCP framing).  The Python SDK surfaces these rejections as
httpx.HTTPStatusError, but anyio's task group wraps it in a BaseExceptionGroup.
_assert_http_status() handles both forms.

Bearer token:
  - Correct token  → MCP session succeeds; tools/list returns filtered list
  - Wrong token    → 401 (direct or wrapped in BaseExceptionGroup)
  - No token       → 401

IP allowlist:
  - Loopback in 127.0.0.0/8    → session succeeds; tools visible
  - Loopback not in 10.0.0.0/8 → 403
"""

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

CORRECT_TOKEN = "test-token-secret"
WRONG_TOKEN = "definitely-not-the-right-token"


def _mcp_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/mcp"


def _extract_http_status_error(exc: BaseException) -> httpx.HTTPStatusError | None:
    """
    Return the first httpx.HTTPStatusError found in ``exc``.

    anyio's TaskGroup wraps exceptions raised inside task coroutines in a
    BaseExceptionGroup.  This helper recurses into the group so callers can
    work with the underlying HTTP error directly.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _extract_http_status_error(sub)
            if found is not None:
                return found
    return None


def _assert_http_status(exc: BaseException, expected_status: int) -> None:
    """
    Assert that ``exc`` (or a wrapped sub-exception) is an
    httpx.HTTPStatusError with the given status code.
    """
    http_err = _extract_http_status_error(exc)
    assert http_err is not None, (
        f"Expected httpx.HTTPStatusError (status {expected_status}) "
        f"but got: {type(exc).__name__}: {exc}"
    )
    assert http_err.response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, "
        f"got {http_err.response.status_code}"
    )


# ── Bearer token tests ─────────────────────────────────────────────────────────


async def test_bearer_correct_token_allows_session(http_proxy_with_bearer):
    """
    Presenting the correct bearer token must allow the MCP session to be
    established and tools/list to succeed, returning the filtered tool list.
    """
    url = _mcp_url(http_proxy_with_bearer["port"])

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {CORRECT_TOKEN}"}
    ) as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()

    tool_names = {t.name for t in result.tools}
    assert "echo" in tool_names and "get-sum" in tool_names, (
        f"Expected echo and get-sum in tool list after correct-token auth, "
        f"got: {tool_names}"
    )


async def test_bearer_wrong_token_raises(http_proxy_with_bearer):
    """
    Presenting an incorrect bearer token must result in HTTP 401.

    The proxy's bearer middleware returns 401 before the MCP handshake,
    so the error surfaces in the transport layer.  anyio wraps it in a
    BaseExceptionGroup; _assert_http_status unpacks it.
    """
    url = _mcp_url(http_proxy_with_bearer["port"])

    caught: BaseException | None = None
    try:
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {WRONG_TOKEN}"}
        ) as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    except BaseException as exc:
        caught = exc

    assert caught is not None, "Expected an exception for wrong bearer token"
    _assert_http_status(caught, 401)


async def test_bearer_no_token_raises(http_proxy_with_bearer):
    """
    Making a request with no Authorization header must result in HTTP 401.
    """
    url = _mcp_url(http_proxy_with_bearer["port"])

    caught: BaseException | None = None
    try:
        async with httpx.AsyncClient() as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    except BaseException as exc:
        caught = exc

    assert caught is not None, "Expected an exception for missing bearer token"
    _assert_http_status(caught, 401)


# ── IP allowlist tests ─────────────────────────────────────────────────────────


async def test_ip_allowlist_loopback_allowed(http_proxy_ip_allowlist_loopback):
    """
    When the allowlist includes 127.0.0.0/8, connections from 127.0.0.1 must
    be permitted and the MCP session must succeed.
    """
    url = _mcp_url(http_proxy_ip_allowlist_loopback["port"])

    async with httpx.AsyncClient() as client:
        async with streamable_http_client(url, http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()

    tool_names = {t.name for t in result.tools}
    assert "echo" in tool_names, (
        f"Expected 'echo' in tool list after IP-allowed session, "
        f"got: {tool_names}"
    )


async def test_ip_allowlist_blocked_ip_rejected(http_proxy_ip_allowlist_no_loopback):
    """
    When the allowlist only includes 10.0.0.0/8, connections from 127.0.0.1
    must be rejected with HTTP 403.
    """
    url = _mcp_url(http_proxy_ip_allowlist_no_loopback["port"])

    caught: BaseException | None = None
    try:
        async with httpx.AsyncClient() as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    except BaseException as exc:
        caught = exc

    assert caught is not None, "Expected an exception for blocked IP"
    _assert_http_status(caught, 403)
