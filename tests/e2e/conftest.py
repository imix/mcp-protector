"""
Shared fixtures for the mcp-protector external e2e test suite (Epic 9).

Upstream: @modelcontextprotocol/server-everything (via npx)
Client:   Python mcp SDK (ClientSession)

Neither side shares code with mcp-protector, so a passing suite proves the
proxy is genuinely MCP-conformant, not merely self-consistent.
"""

import asyncio
import json
import os
import socket
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

# ── Upstream server command ────────────────────────────────────────────────────

# The official reference MCP server.  -y suppresses the npx install prompt.
# In CI, the package is pre-installed globally so npx finds it immediately.
UPSTREAM_COMMAND = ["npx", "-y", "@modelcontextprotocol/server-everything"]

# ── Binary location ────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def proxy_bin() -> Path:
    """
    Return the path to the compiled mcp-protector binary.

    Defaults to ``target/debug/mcp-protector`` relative to the repository
    root (two directories above ``tests/e2e/``).  Override via the
    ``MCP_PROTECTOR_BIN`` environment variable — CI sets this after
    ``cargo build``.
    """
    env_override = os.environ.get("MCP_PROTECTOR_BIN")
    if env_override:
        p = Path(env_override)
        if not p.is_file():
            raise FileNotFoundError(
                f"MCP_PROTECTOR_BIN={env_override!r} does not exist"
            )
        return p

    # tests/e2e/ -> tests/ -> repo root
    repo_root = Path(__file__).parent.parent.parent
    default = repo_root / "target" / "debug" / "mcp-protector"
    if not default.is_file():
        raise FileNotFoundError(
            f"Binary not found at {default}. "
            "Run `cargo build` first, or set MCP_PROTECTOR_BIN."
        )
    return default


# ── Port allocation ────────────────────────────────────────────────────────────


@pytest.fixture
def free_port() -> int:
    """
    Bind an ephemeral TCP port on loopback, release it, and return the number.

    There is a small TOCTOU window before the proxy claims the port, but
    this is acceptable for a local test environment.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── Config file factory ────────────────────────────────────────────────────────


@pytest.fixture
def make_config(tmp_path: Path):
    """
    Return a callable that writes TOML content to a temp file and returns the
    absolute path as a string.

    Usage::

        config_path = make_config(\"\"\"
            [upstream]
            url = "stdio"
            command = [...]
            ...
        \"\"\")
    """

    def _make(toml_content: str) -> str:
        # Use json.dumps for the upstream command list so we get valid TOML.
        config_file = tmp_path / "config.toml"
        config_file.write_text(toml_content)
        return str(config_file)

    return _make


# ── HTTP port readiness helper ─────────────────────────────────────────────────


async def wait_for_http_port(port: int, timeout: float = 30.0) -> None:
    """
    Poll ``GET http://127.0.0.1:{port}/health`` until it returns HTTP 200
    (meaning the upstream MCP handshake has completed) or the timeout expires.

    We wait for 200 specifically, not just any response:
    - 503 ``{"status":"starting"}`` means the port is bound but the upstream
      subprocess hasn't finished its MCP handshake yet.  Connecting to /mcp
      while the proxy is in this state returns 500 (session factory has no
      upstream peer yet), so we must keep polling.
    - 200 ``{"status":"ok"}`` means the upstream is ready for MCP sessions.

    /health is always outside the auth middleware so it is reachable
    regardless of which auth mode is configured (bearer, IP allowlist, or none).

    Raises ``TimeoutError`` if 200 is not observed within ``timeout`` seconds.
    """
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + timeout

    while True:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=1.0)
                if resp.status_code == 200:
                    return  # Upstream MCP handshake complete, proxy is ready
                # 503 = still starting; fall through to sleep and retry
        except (httpx.ConnectError, httpx.TimeoutException):
            pass  # Port not yet bound; keep polling

        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Proxy /health did not return 200 within {timeout}s "
                f"(port {port}) — upstream MCP handshake may have failed"
            )
        await asyncio.sleep(0.2)


# ── HTTP proxy fixtures ────────────────────────────────────────────────────────


def _upstream_command_toml() -> str:
    """Return a TOML-safe representation of the upstream command array."""
    return json.dumps(UPSTREAM_COMMAND)


@pytest_asyncio.fixture
async def http_proxy(proxy_bin: Path, free_port: int, make_config):
    """
    Spawn mcp-protector in HTTP mode with server-everything as upstream.
    Policy: allow = ["echo", "get-sum"].

    Yields a dict with keys ``port``, ``stdout``, ``stderr``.
    ``stdout`` and ``stderr`` are populated (as ``bytes``) only after the
    fixture tears down — read them after the ``async with`` block that
    uses the session.
    """
    config_path = make_config(
        f"""
[upstream]
url = "stdio"
command = {_upstream_command_toml()}

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

    state: dict = {"port": free_port, "stdout": b"", "stderr": b""}

    try:
        await wait_for_http_port(free_port)
        yield state
    finally:
        proc.terminate()
        stdout, stderr = await proc.communicate()
        state["stdout"] = stdout
        state["stderr"] = stderr


@pytest_asyncio.fixture
async def http_proxy_with_bearer(proxy_bin: Path, free_port: int, make_config):
    """
    HTTP proxy with bearer token auth configured.
    Token: ``"test-token-secret"``.
    Policy: allow = ["echo", "get-sum"].
    """
    config_path = make_config(
        f"""
[upstream]
url = "stdio"
command = {_upstream_command_toml()}

[listen]
transport = "http"
port = {free_port}

[listen.auth]
type = "bearer"
token = "test-token-secret"

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

    state: dict = {"port": free_port, "stdout": b"", "stderr": b""}

    try:
        await wait_for_http_port(free_port)
        yield state
    finally:
        proc.terminate()
        stdout, stderr = await proc.communicate()
        state["stdout"] = stdout
        state["stderr"] = stderr


@pytest_asyncio.fixture
async def http_proxy_ip_allowlist_loopback(proxy_bin: Path, free_port: int, make_config):
    """
    HTTP proxy with IP allowlist that permits loopback (127.0.0.0/8).
    Policy: allow = ["echo", "get-sum"].
    """
    config_path = make_config(
        f"""
[upstream]
url = "stdio"
command = {_upstream_command_toml()}

[listen]
transport = "http"
port = {free_port}

[listen.auth]
type = "ip_allowlist"
allow = ["127.0.0.0/8"]

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

    state: dict = {"port": free_port, "stdout": b"", "stderr": b""}

    try:
        await wait_for_http_port(free_port)
        yield state
    finally:
        proc.terminate()
        stdout, stderr = await proc.communicate()
        state["stdout"] = stdout
        state["stderr"] = stderr


@pytest_asyncio.fixture
async def http_proxy_ip_allowlist_no_loopback(proxy_bin: Path, free_port: int, make_config):
    """
    HTTP proxy with IP allowlist that does NOT include loopback.
    All connections from 127.0.0.1 to /mcp will be rejected with 403.

    Note: /health is outside the auth middleware, so wait_for_http_port
    succeeds even though /mcp rejects the test client.
    """
    config_path = make_config(
        f"""
[upstream]
url = "stdio"
command = {_upstream_command_toml()}

[listen]
transport = "http"
port = {free_port}

[listen.auth]
type = "ip_allowlist"
allow = ["10.0.0.0/8"]

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

    state: dict = {"port": free_port, "stdout": b"", "stderr": b""}

    try:
        await wait_for_http_port(free_port)
        yield state
    finally:
        proc.terminate()
        stdout, stderr = await proc.communicate()
        state["stdout"] = stdout
        state["stderr"] = stderr
