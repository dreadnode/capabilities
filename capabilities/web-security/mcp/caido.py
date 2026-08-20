#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "caido-sdk-client>=0.3.0",
# ]
# ///
"""Caido proxy tools — wraps the caido-sdk-client for host interaction.

Requires caido-sdk-client >= 0.3.0. Earlier releases hardcode the pre-0.57
replay schema (they select `collection`/`activeEntry` on ReplaySession and omit
`ReplaySessionKind`), so `caido_replay_request` and `caido_replay_sessions`
fail against Caido >= 0.57 with "Unknown field collection on type
ReplaySession". 0.3.0 added the versioned transport split (transport/latest vs
transport/v0_56) and negotiates the right schema per instance.

Auth resolution order:
  1. CAIDO_PAT env var → PATAuthOptions (no connect() needed)
  2. ~/.caido-mcp/token.json → TokenAuthOptions + connect() for refresh
  3. No auth (guest mode — only health endpoint works)

Token file is shared with caido-mcp-server (Go binary). Run
`caido-mcp-server login` to create it via OAuth device flow.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Annotated

from caido_sdk_client import Client
from caido_sdk_client.types.finding import CreateFindingOptions
from caido_sdk_client.types.network import ConnectionInfoInput
from caido_sdk_client.types.replay_session import (
    CreateReplaySessionFromRaw,
    CreateReplaySessionOptions,
    ReplaySendOptions,
)
from caido_sdk_client.types.scope import CreateScopeOptions
from fastmcp import FastMCP

DEFAULT_CAIDO_URL = "http://localhost:8080"
DEFAULT_TOKEN_PATH = Path.home() / ".caido-mcp" / "token.json"
MAX_OUTPUT_CHARS = 50_000
CONNECT_TIMEOUT = 30

# Upper bound on `replay.send()`. On Caido >= 0.57 the SDK starts a replay task
# and then waits on a task-finished *subscription*. If the target responds
# before that subscription is established, the completion event is missed and
# the await never returns — reproducible against a fast (localhost) target.
# The send itself still succeeds server-side, so on timeout we fall back to
# reading the session's active entry instead of hanging the MCP call forever.
REPLAY_SEND_TIMEOUT = 30
_SAFE_GET_RETRIES = 1
_SAFE_GET_RETRY_DELAY = 2.0  # seconds


class _CaidoClient:
    """Lazy Caido SDK wrapper — authenticates on first use."""

    def __init__(self) -> None:
        self.url = os.environ.get("CAIDO_URL", DEFAULT_CAIDO_URL)
        self._client: Client | None = None

    async def get(self) -> Client:
        if self._client is not None:
            return self._client

        # 1. PAT from env — no connect() needed
        pat = os.environ.get("CAIDO_PAT")
        if pat:
            from caido_sdk_client.auth import PATAuthOptions

            self._client = Client(self.url, auth=PATAuthOptions(pat=pat))
            return self._client

        # 2. Token file (shared with caido-mcp-server Go binary)
        token_path = Path(os.environ.get("CAIDO_TOKEN_PATH", str(DEFAULT_TOKEN_PATH)))
        if token_path.exists():
            from caido_sdk_client.auth import TokenAuthOptions, TokenPair

            data = json.loads(token_path.read_text())
            token = TokenPair(
                access_token=data["accessToken"],
                refresh_token=data.get("refreshToken"),
            )
            client = Client(self.url, auth=TokenAuthOptions(token=token))
            # connect() refreshes the token if expired
            await asyncio.wait_for(client.connect(), timeout=CONNECT_TIMEOUT)
            self._client = client
            return self._client

        # 3. No auth (guest mode)
        self._client = Client(self.url)
        return self._client

    async def safe_get(self) -> tuple[Client | None, str | None]:
        """Get the client, retrying once on transient failures.

        The lazy ``get()`` can fail transiently when Caido is under load
        or when the token-refresh ``connect()`` times out.  A single
        retry with a short delay absorbs the transient so the model
        doesn't conclude the proxy is permanently unavailable.
        """
        for attempt in range(_SAFE_GET_RETRIES + 1):
            try:
                return await self.get(), None
            except Exception as exc:
                self._client = None
                if attempt < _SAFE_GET_RETRIES:
                    await asyncio.sleep(_SAFE_GET_RETRY_DELAY)
                    continue
                return None, f"Error: {exc}"
        # Unreachable — satisfies the type checker.
        return None, "Error: exhausted retries"  # pragma: no cover


_caido = _CaidoClient()


def _render_url(request: object) -> str:
    scheme = "https" if getattr(request, "is_tls", False) else "http"
    url = f"{scheme}://{request.host}{request.path}"
    query = getattr(request, "query", None)
    if query:
        url += f"?{query}"
    return url


mcp = FastMCP("caido")


@mcp.tool
async def caido_health() -> str:
    """Check Caido connection status."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    health = await client.health()
    return (
        f"Connected to Caido at {_caido.url}\n"
        f"  Instance: {health.name}\n"
        f"  Version:  {health.version}\n"
        f"  Ready:    {health.ready}"
    )


@mcp.tool
async def caido_search_requests(
    filter: Annotated[
        str | None, "HTTPQL filter query (e.g. 'host:example.com AND method:POST')"
    ] = None,
    limit: Annotated[int, "Maximum number of results to return"] = 20,
) -> str:
    """Search HTTP requests captured by Caido."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    builder = client.request.list().first(limit)
    if filter:
        builder = builder.filter(filter)
    conn = await builder.execute()

    if not conn.edges:
        return "No requests found matching the filter."

    lines: list[str] = []
    for edge in conn.edges:
        req = edge.node.request
        resp = edge.node.response
        status = resp.status_code if resp else "-"
        length = resp.length if resp else "-"
        lines.append(f"{req.id}\t{req.method}\t{status}\t{length}\t{_render_url(req)}")

    if conn.page_info.has_next_page:
        lines.append(f"# more results available (cursor: {conn.page_info.end_cursor})")

    return "\n".join(lines)


@mcp.tool
async def caido_get_request(
    request_id: Annotated[str, "The Caido request ID to retrieve"],
    include: Annotated[str | None, "Comma-separated: headers,body"] = None,
) -> str:
    """Get detailed info for a specific Caido request."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    entry = await client.request.get(request_id)
    if entry is None:
        return f"Error: Request {request_id} not found."

    request = entry.request
    response = entry.response
    include_set = set(include.split(",")) if include else set()

    lines = [
        f"id: {request.id}",
        f"method: {request.method}",
        f"url: {_render_url(request)}",
        f"created: {request.created_at}",
    ]
    if response:
        lines.append(f"status: {response.status_code}")
        lines.append(f"length: {response.length}")
        lines.append(f"roundtrip: {response.roundtrip_time}ms")

    want_headers = "headers" in include_set
    want_body = "body" in include_set

    if (want_headers or want_body) and request.raw:
        raw_str = request.raw.decode(errors="replace")
        header_end = raw_str.find("\r\n\r\n")
        if want_headers:
            lines.append(
                f"\n--- request headers ---\n"
                f"{raw_str[:header_end] if header_end != -1 else raw_str[:2000]}"
            )
        if want_body and header_end != -1:
            body = raw_str[header_end + 4 :]
            if body:
                lines.append(f"\n--- request body ---\n{body[:4000]}")

    if (want_headers or want_body) and response and response.raw:
        raw_str = response.raw.decode(errors="replace")
        header_end = raw_str.find("\r\n\r\n")
        if want_headers:
            lines.append(
                f"\n--- response headers ---\n"
                f"{raw_str[:header_end] if header_end != -1 else raw_str[:2000]}"
            )
        if want_body and header_end != -1:
            body = raw_str[header_end + 4 :]
            if body:
                truncated = body[:MAX_OUTPUT_CHARS]
                if len(body) > MAX_OUTPUT_CHARS:
                    truncated += f"\n\n... [TRUNCATED: {len(body)} chars total]"
                lines.append(
                    f"\n--- response body ({len(body)} chars) ---\n{truncated}"
                )

    return "\n".join(lines)


async def _replay_result_from_session(client: Client, session_id: object) -> str:
    """Recover a replay result by reading the session's newest entry.

    Used when `replay.send()` times out waiting on the task-finished
    subscription. The send has still happened server-side, so the entry
    carries the real request/response.
    """
    lines = ["status: DONE (recovered — task subscription timed out)"]
    try:
        session = await client.replay.sessions.get(session_id)
        if session is None:
            return "status: UNKNOWN\nerror: replay session vanished after send"
        conn = await session.entries().last(1).execute()
        if not conn.edges:
            return "status: UNKNOWN\nerror: replay session has no entries"
        # Re-fetch by id: entries listed via the session carry no response body.
        entry = await client.replay.entries.get(conn.edges[-1].node.id)
        if entry is None:
            return "status: UNKNOWN\nerror: replay entry not found"
    except Exception as exc:  # noqa: BLE001 - surface, never mask
        return f"status: UNKNOWN\nerror: could not recover replay result: {exc}"

    lines.append(f"entry_id: {entry.id}")
    request = getattr(entry, "request", None)
    if request is not None:
        lines.append(f"request_id: {request.id}")
    # `response` hangs off the entry, not off entry.request.
    response = getattr(entry, "response", None)
    if response is not None:
        lines.append(f"response: {response.status_code} ({response.length} bytes)")
        raw = getattr(response, "raw", None)
        if raw:
            text = raw.decode(errors="replace")
            truncated = text[:MAX_OUTPUT_CHARS]
            if len(text) > MAX_OUTPUT_CHARS:
                truncated += f"\n\n... [TRUNCATED: {len(text)} chars total]"
            lines.append(truncated)
    return "\n".join(lines)


@mcp.tool
async def caido_replay_request(
    raw_request: Annotated[str, "Raw HTTP request including request line"],
    host: Annotated[str, "Target host"],
    port: Annotated[
        int | None, "Target port (default: 443 for TLS, 80 otherwise)"
    ] = None,
    tls: Annotated[bool, "Use TLS"] = True,
) -> str:
    """Send/replay an HTTP request through Caido."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    raw = raw_request.replace("\\r\\n", "\r\n").encode()
    connection = ConnectionInfoInput(
        host=host,
        port=port if port is not None else (443 if tls else 80),
        is_tls=tls,
    )

    # The session must be SEEDED with the request. On Caido >= 0.57 `send()`
    # updates the draft of an existing entry and then starts a replay task — a
    # bare `sessions.create()` yields a session with no entries, so send()
    # aborts with "Replay session has no entries". Creating from raw gives the
    # session its first entry.
    session = await client.replay.sessions.create(
        CreateReplaySessionOptions(
            request_source=CreateReplaySessionFromRaw(raw=raw, connection=connection)
        )
    )
    # Connection details are nested under `connection` (ConnectionInfoInput) —
    # they are not flat kwargs on ReplaySendOptions.
    try:
        result = await asyncio.wait_for(
            client.replay.send(
                session.id,
                ReplaySendOptions(raw=raw, connection=connection),
            ),
            timeout=REPLAY_SEND_TIMEOUT,
        )
    except TimeoutError:
        # The task-finished subscription was missed (see REPLAY_SEND_TIMEOUT).
        # The request itself has almost certainly been sent, so recover the
        # result from the session rather than reporting a false failure.
        return await _replay_result_from_session(client, session.id)

    # ReplaySendResult exposes `status` ("DONE" | "CANCELLED" | "ERROR"). It may
    # arrive as a TaskStatus enum, whose str() is "TaskStatus.DONE" — unwrap to
    # the bare value so output is stable across SDK versions.
    status_value = getattr(result, "status", None)
    status_value = getattr(status_value, "value", status_value)
    status_str = status_value if isinstance(status_value, str) else str(status_value)
    lines = [f"status: {status_str}"]
    if result.error:
        lines.append(f"error: {result.error}")

    entry = getattr(result, "entry", None)
    if entry:
        lines.append(f"entry_id: {entry.id}")
        if getattr(entry, "request", None):
            lines.append(f"request_id: {entry.request.id}")
        if getattr(entry, "response", None):
            resp = entry.response
            lines.append(
                f"response: {resp.status_code} ({resp.length} bytes, {resp.roundtrip_time}ms)"
            )
            if resp.raw:
                raw_str = resp.raw.decode(errors="replace")
                truncated = raw_str[:MAX_OUTPUT_CHARS]
                if len(raw_str) > MAX_OUTPUT_CHARS:
                    truncated += f"\n\n... [TRUNCATED: {len(raw_str)} chars total]"
                lines.append(truncated)

    return "\n".join(lines)


@mcp.tool
async def caido_list_scopes() -> str:
    """List all defined Caido scopes."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    scopes = await client.scope.list()
    if not scopes:
        return "No scopes defined."

    return "\n".join(
        f"{scope.id}\t{scope.name}\tallow={scope.allowlist}\tdeny={scope.denylist}"
        for scope in scopes
    )


@mcp.tool
async def caido_create_scope(
    name: Annotated[str, "Scope name"],
    allowlist: Annotated[list[str], "Allowlist glob patterns"],
    denylist: Annotated[list[str] | None, "Denylist glob patterns"] = None,
) -> str:
    """Create a new Caido scope."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    scope = await client.scope.create(
        CreateScopeOptions(name=name, allowlist=allowlist, denylist=denylist or []),
    )
    return f"Created scope: {scope.id} | {scope.name}"


@mcp.tool
async def caido_list_findings(
    filter: Annotated[str | None, "HTTPQL filter query"] = None,
    limit: Annotated[int, "Maximum number of results to return"] = 20,
) -> str:
    """Query security findings in Caido."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    builder = client.findings.list().first(limit)
    if filter:
        builder = builder.filter(filter)
    conn = await builder.execute()

    if not conn.edges:
        return "No findings found."

    lines = [
        f"{finding.id}\t{finding.reporter}\t{finding.host}{finding.path}\t{finding.title}"
        for finding in (edge.node for edge in conn.edges)
    ]
    if conn.page_info.has_next_page:
        lines.append("# more results available")
    return "\n".join(lines)


@mcp.tool
async def caido_create_finding(
    request_id: Annotated[str, "The Caido request ID to attach the finding to"],
    title: Annotated[str, "Finding title"],
    description: Annotated[str | None, "Finding description"] = None,
    reporter: Annotated[str, "Reporter identifier"] = "dreadnode-agent",
    dedupe_key: Annotated[str | None, "Deduplication key"] = None,
) -> str:
    """Log a security finding in Caido."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    finding = await client.findings.create(
        request_id,
        CreateFindingOptions(
            title=title,
            description=description,
            reporter=reporter,
            dedupe_key=dedupe_key,
        ),
    )
    return f"Created finding: {finding.id} | {finding.title}"


@mcp.tool
async def caido_replay_sessions(
    limit: Annotated[int, "Maximum number of sessions to return"] = 20,
) -> str:
    """List Caido replay sessions."""
    client, err = await _caido.safe_get()
    if err:
        return err

    assert client is not None
    conn = await client.replay.sessions.list().first(limit).execute()
    if not conn.edges:
        return "No replay sessions found."

    lines = [
        f"{session.id}\t{session.name}"
        for session in (edge.node for edge in conn.edges)
    ]
    if conn.page_info.has_next_page:
        lines.append("# more results available")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
