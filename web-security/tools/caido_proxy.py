"""Caido proxy integration for web security testing.

Provides tools to interact with a running Caido instance: search captured
traffic, replay requests with modifications, manage scopes, and record
findings. Requires ``caido-sdk-client`` (``pip install caido-sdk-client``)
and a running Caido instance.

If the SDK is not installed the capability loader will skip this module
(ImportError is caught by the wrapper). If Caido is unreachable at runtime
each tool method returns an error string — the agent keeps working with
the remaining tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import PrivateAttr

try:
    from caido_sdk_client import Client
    from caido_sdk_client.auth import TokenAuthOptions, TokenPair
    from caido_sdk_client.types.finding import CreateFindingOptions
    from caido_sdk_client.types.replay_session import ReplaySendOptions
    from caido_sdk_client.types.scope import CreateScopeOptions
except ImportError as _imp_err:
    raise ImportError(
        "caido-sdk-client is required for Caido tools: pip install caido-sdk-client"
    ) from _imp_err

from dreadnode.agents.tools import Toolset, tool_method

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CAIDO_URL = "http://localhost:8080"
DEFAULT_TOKEN_PATH = Path.home() / ".caido-mcp" / "token.json"


# ---------------------------------------------------------------------------
# Toolset
# ---------------------------------------------------------------------------


class CaidoTools(Toolset):
    """Interact with a running Caido proxy for traffic inspection, replay, and findings."""

    caido_url: str = DEFAULT_CAIDO_URL
    """Base URL of the Caido instance."""
    token_path: str = str(DEFAULT_TOKEN_PATH)
    """Path to the caido-mcp-server token cache JSON file."""
    max_output_chars: int = 50_000
    """Maximum characters returned in response bodies."""

    _client: Client | None = PrivateAttr(default=None)

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _load_tokens(self) -> TokenPair:
        """Load cached tokens from disk.

        Raises FileNotFoundError or json.JSONDecodeError on problems.
        """
        path = Path(self.token_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Token file not found at {path}. "
                "Ensure caido-mcp-server has authenticated at least once."
            )
        data = json.loads(path.read_text())
        return TokenPair(
            access_token=data["accessToken"],
            refresh_token=data.get("refreshToken"),
        )

    async def _ensure_client(self) -> Client:
        """Return an existing client or lazily create and connect one."""
        if self._client is not None:
            return self._client

        tokens = self._load_tokens()
        client = Client(
            self.caido_url,
            auth=TokenAuthOptions(token=tokens),
        )
        await client.connect()
        self._client = client
        return client

    async def _safe_client(self) -> tuple[Client | None, str | None]:
        """Attempt to get a connected client, returning an error string on failure."""
        try:
            client = await self._ensure_client()
            return client, None
        except FileNotFoundError as exc:
            return None, f"Error: {exc}"
        except Exception as exc:
            # Connection refused, auth failure, etc.
            self._client = None
            return None, f"Error: Could not connect to Caido at {self.caido_url}: {exc}"

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    @tool_method(name="caido_health", catch=True)
    async def caido_health(self) -> str:
        """Check connectivity to the Caido instance.

        Use this to verify Caido is running before issuing other caido_*
        commands. Returns instance version and authenticated user info.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        health = await client.health()
        return (
            f"Connected to Caido at {self.caido_url}\n"
            f"  Instance: {health.name}\n"
            f"  Version:  {health.version}\n"
            f"  Ready:    {health.ready}"
        )

    @tool_method(name="caido_search_requests", catch=True)
    async def caido_search_requests(
        self,
        filter: Annotated[str | None, "HTTPQL filter query (e.g. 'host:example.com AND method:POST')"] = None,
        limit: Annotated[int, "Maximum number of results to return"] = 20,
    ) -> str:
        """Search HTTP requests captured by Caido.

        Returns a tab-delimited list of requests with ID, method, status,
        length and URL. Use the HTTPQL filter syntax to narrow results
        (e.g. ``host:example.com``, ``method:POST``, ``status:200``).
        """
        client, err = await self._safe_client()
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
            r = edge.node.request
            resp = edge.node.response
            status = resp.status_code if resp else "-"
            length = resp.content_length if resp else "-"
            scheme = "https" if r.tls else "http"
            url = f"{scheme}://{r.host}{r.path}"
            if r.query:
                url += f"?{r.query}"
            lines.append(f"{r.id}\t{r.method}\t{status}\t{length}\t{url}")

        if conn.page_info.has_next_page:
            lines.append(f"# more results available (cursor: {conn.page_info.end_cursor})")

        return "\n".join(lines)

    @tool_method(name="caido_get_request", catch=True)
    async def caido_get_request(
        self,
        request_id: Annotated[str, "The Caido request ID to retrieve"],
        include: Annotated[str | None, "Comma-separated: headers,body"] = None,
    ) -> str:
        """Get full details of a captured request by ID.

        Optionally include raw headers and/or body content by passing
        ``include='headers,body'``.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        entry = await client.request.get(request_id)
        if entry is None:
            return f"Error: Request {request_id} not found."

        r = entry.request
        resp = entry.response
        include_set = set(include.split(",")) if include else set()

        scheme = "https" if r.tls else "http"
        url = f"{scheme}://{r.host}{r.path}"
        if r.query:
            url += f"?{r.query}"

        lines = [
            f"id: {r.id}",
            f"method: {r.method}",
            f"url: {url}",
            f"created: {r.created_at}",
        ]
        if resp:
            lines.append(f"status: {resp.status_code}")
            lines.append(f"length: {resp.content_length}")
            lines.append(f"roundtrip: {resp.roundtrip}ms")

        want_headers = "headers" in include_set
        want_body = "body" in include_set

        if (want_headers or want_body) and r.raw:
            raw_str = r.raw.decode(errors="replace")
            hdr_end = raw_str.find("\r\n\r\n")
            if want_headers:
                if hdr_end != -1:
                    lines.append(f"\n--- request headers ---\n{raw_str[:hdr_end]}")
                else:
                    lines.append(f"\n--- request raw ---\n{raw_str[:2000]}")
            if want_body and hdr_end != -1:
                body = raw_str[hdr_end + 4:]
                if body:
                    lines.append(f"\n--- request body ---\n{body[:4000]}")

        if (want_headers or want_body) and resp and resp.raw:
            resp_str = resp.raw.decode(errors="replace")
            hdr_end = resp_str.find("\r\n\r\n")
            if want_headers:
                if hdr_end != -1:
                    lines.append(f"\n--- response headers ---\n{resp_str[:hdr_end]}")
                else:
                    lines.append(f"\n--- response raw ---\n{resp_str[:2000]}")
            if want_body and hdr_end != -1:
                body = resp_str[hdr_end + 4:]
                if body:
                    truncated = body[:self.max_output_chars]
                    if len(body) > self.max_output_chars:
                        truncated += f"\n\n... [TRUNCATED: {len(body)} chars total]"
                    lines.append(f"\n--- response body ({len(body)} chars) ---\n{truncated}")

        return "\n".join(lines)

    @tool_method(name="caido_replay_request", catch=True)
    async def caido_replay_request(
        self,
        raw_request: Annotated[str, "Raw HTTP request (e.g. 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n')"],
        host: Annotated[str, "Target host"],
        port: Annotated[int | None, "Target port (default: 443 for TLS, 80 otherwise)"] = None,
        tls: Annotated[bool, "Use TLS"] = True,
    ) -> str:
        """Send a request through Caido's replay engine.

        The request appears in Caido's Replay tab for interactive inspection.
        Provide the full raw HTTP request including the request line.
        Use ``\\r\\n`` for line endings.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        effective_port = port if port is not None else (443 if tls else 80)
        raw_bytes = raw_request.replace("\\r\\n", "\r\n").encode()

        session = await client.replay.sessions.create()
        result = await client.replay.send(
            session.id,
            ReplaySendOptions(
                raw=raw_bytes,
                host=host,
                port=effective_port,
                tls=tls,
            ),
        )

        status_str = result.task_status if isinstance(result.task_status, str) else str(result.task_status)

        lines = [f"status: {status_str}"]
        if result.error:
            lines.append(f"error: {result.error}")

        if hasattr(result, "entry") and result.entry:
            entry = result.entry
            lines.append(f"entry_id: {entry.id}")
            if hasattr(entry, "request") and entry.request:
                lines.append(f"request_id: {entry.request.id}")
            if hasattr(entry, "response") and entry.response:
                r = entry.response
                lines.append(f"response: {r.status_code} ({r.content_length} bytes, {r.roundtrip}ms)")
                if r.raw:
                    resp_str = r.raw.decode(errors="replace")
                    truncated = resp_str[:self.max_output_chars]
                    if len(resp_str) > self.max_output_chars:
                        truncated += f"\n\n... [TRUNCATED: {len(resp_str)} chars total]"
                    lines.append(truncated)

        return "\n".join(lines)

    @tool_method(name="caido_list_scopes", catch=True)
    async def caido_list_scopes(self) -> str:
        """List all defined scopes in Caido.

        Scopes control which hosts/paths are in-scope for testing.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        scopes = await client.scope.list()
        if not scopes:
            return "No scopes defined."

        lines: list[str] = []
        for s in scopes:
            lines.append(f"{s.id}\t{s.name}\tallow={s.allowlist}\tdeny={s.denylist}")
        return "\n".join(lines)

    @tool_method(name="caido_create_scope", catch=True)
    async def caido_create_scope(
        self,
        name: Annotated[str, "Scope name"],
        allowlist: Annotated[list[str], "Allowlist glob patterns (e.g. ['*://example.com/*'])"],
        denylist: Annotated[list[str] | None, "Denylist glob patterns"] = None,
    ) -> str:
        """Create a new scope in Caido.

        Define which hosts and paths are in-scope for testing.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        scope = await client.scope.create(
            CreateScopeOptions(
                name=name,
                allowlist=allowlist,
                denylist=denylist or [],
            ),
        )
        return f"Created scope: {scope.id} | {scope.name}"

    @tool_method(name="caido_list_findings", catch=True)
    async def caido_list_findings(
        self,
        filter: Annotated[str | None, "HTTPQL filter query"] = None,
        limit: Annotated[int, "Maximum number of results to return"] = 20,
    ) -> str:
        """List security findings recorded in Caido.

        Returns ID, reporter, host/path, and title for each finding.
        """
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        builder = client.findings.list().first(limit)
        if filter:
            builder = builder.filter(filter)
        conn = await builder.execute()

        if not conn.edges:
            return "No findings found."

        lines: list[str] = []
        for edge in conn.edges:
            f = edge.node
            lines.append(f"{f.id}\t{f.reporter}\t{f.host}{f.path}\t{f.title}")

        if conn.page_info.has_next_page:
            lines.append("# more results available")

        return "\n".join(lines)

    @tool_method(name="caido_create_finding", catch=True)
    async def caido_create_finding(
        self,
        request_id: Annotated[str, "The Caido request ID to attach the finding to"],
        title: Annotated[str, "Finding title"],
        description: Annotated[str | None, "Finding description"] = None,
        reporter: Annotated[str, "Reporter identifier"] = "dreadnode-agent",
        dedupe_key: Annotated[str | None, "Deduplication key to prevent duplicate findings"] = None,
    ) -> str:
        """Create a security finding in Caido attached to a request.

        Findings appear in Caido's Findings tab alongside manually created ones.
        Use a ``dedupe_key`` to prevent duplicate findings for the same issue.
        """
        client, err = await self._safe_client()
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

    @tool_method(name="caido_replay_sessions", catch=True)
    async def caido_replay_sessions(
        self,
        limit: Annotated[int, "Maximum number of sessions to return"] = 20,
    ) -> str:
        """List replay sessions in Caido."""
        client, err = await self._safe_client()
        if err:
            return err

        assert client is not None
        conn = await client.replay.sessions.list().first(limit).execute()

        if not conn.edges:
            return "No replay sessions found."

        lines: list[str] = []
        for edge in conn.edges:
            s = edge.node
            lines.append(f"{s.id}\t{s.name}")

        if conn.page_info.has_next_page:
            lines.append("# more results available")

        return "\n".join(lines)
