"""
Tests for CaidoTools — Caido proxy integration toolset.

All Caido SDK interactions are mocked. The real caido-sdk-client package is
not required to run these tests; we mock the entire import surface.
"""

from __future__ import annotations

import json
import sys
import types
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fake Caido SDK types — mirrors the real SDK's public API surface so we can
# import ``caido_proxy`` without having ``caido-sdk-client`` installed.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeTokenPair:
    access_token: str
    refresh_token: str | None = None


@dataclass(frozen=True)
class FakeTokenAuthOptions:
    token: FakeTokenPair


@dataclass(frozen=True)
class FakeCreateFindingOptions:
    title: str
    reporter: str
    description: str | None = None
    dedupe_key: str | None = None


@dataclass(frozen=True)
class FakeReplaySendOptions:
    raw: bytes
    host: str | None = None
    port: int | None = None
    tls: bool | None = None
    settings: Any = None


@dataclass(frozen=True)
class FakeCreateScopeOptions:
    name: str
    allowlist: list[str]
    denylist: list[str] | None = None


class FakeClient:
    """Minimal fake of caido_sdk_client.Client."""

    def __init__(self, url: str, auth: Any = None) -> None:
        self.url = url
        self.auth = auth

    async def connect(self) -> None:
        pass

    async def health(self) -> Any:
        pass


# ---------------------------------------------------------------------------
# Install fake SDK modules before importing the toolset.
# ---------------------------------------------------------------------------


def _install_fake_sdk() -> None:
    """Inject fake caido_sdk_client modules into sys.modules."""
    # Top-level package
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = FakeClient  # type: ignore[attr-defined]

    # auth submodule
    auth = types.ModuleType("caido_sdk_client.auth")
    auth.TokenAuthOptions = FakeTokenAuthOptions  # type: ignore[attr-defined]
    auth.TokenPair = FakeTokenPair  # type: ignore[attr-defined]

    # types submodules
    types_pkg = types.ModuleType("caido_sdk_client.types")
    types_finding = types.ModuleType("caido_sdk_client.types.finding")
    types_finding.CreateFindingOptions = FakeCreateFindingOptions  # type: ignore[attr-defined]

    types_replay = types.ModuleType("caido_sdk_client.types.replay_session")
    types_replay.ReplaySendOptions = FakeReplaySendOptions  # type: ignore[attr-defined]

    types_scope = types.ModuleType("caido_sdk_client.types.scope")
    types_scope.CreateScopeOptions = FakeCreateScopeOptions  # type: ignore[attr-defined]

    sys.modules["caido_sdk_client"] = sdk
    sys.modules["caido_sdk_client.auth"] = auth
    sys.modules["caido_sdk_client.types"] = types_pkg
    sys.modules["caido_sdk_client.types.finding"] = types_finding
    sys.modules["caido_sdk_client.types.replay_session"] = types_replay
    sys.modules["caido_sdk_client.types.scope"] = types_scope


_install_fake_sdk()

# NOW safe to import the toolset — it will resolve the fake SDK modules.
# Resolve to repo root regardless of where pytest is invoked from.
_REPO_ROOT = Path(__file__).resolve()
while _REPO_ROOT != _REPO_ROOT.parent:
    if (_REPO_ROOT / "capabilities" / "web-security" / "tools").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "capabilities" / "web-security" / "tools"))

from caido_proxy import CaidoTools  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures — reusable mock helpers
# ---------------------------------------------------------------------------


@dataclass
class FakeHealth:
    name: str = "Caido"
    version: str = "1.0.0"
    ready: bool = True


@dataclass
class FakeRequest:
    id: str = "req_1"
    method: str = "GET"
    host: str = "example.com"
    port: int = 443
    tls: bool = True
    path: str = "/api/v1"
    query: str | None = None
    created_at: datetime = datetime(2025, 1, 1, tzinfo=timezone.utc)
    updated_at: datetime = datetime(2025, 1, 1, tzinfo=timezone.utc)
    raw: bytes | None = None


@dataclass
class FakeResponse:
    status_code: int = 200
    content_length: int = 1234
    roundtrip: int = 42
    raw: bytes | None = None


@dataclass
class FakeRequestResponseOpt:
    request: FakeRequest
    response: FakeResponse | None = None


@dataclass
class FakeEdge:
    node: Any


@dataclass
class FakePageInfo:
    has_next_page: bool = False
    end_cursor: str | None = None


@dataclass
class FakeConnection:
    edges: list[FakeEdge] = field(default_factory=list)
    page_info: FakePageInfo = field(default_factory=FakePageInfo)


@dataclass
class FakeScope:
    id: str = "scope_1"
    name: str = "test-scope"
    allowlist: list[str] | None = None
    denylist: list[str] | None = None
    indexed: bool = True

    def __post_init__(self) -> None:
        if self.allowlist is None:
            self.allowlist = ["*://example.com/*"]
        if self.denylist is None:
            self.denylist = []


@dataclass
class FakeFinding:
    id: str = "find_1"
    request_id: str = "req_1"
    title: str = "XSS in /search"
    reporter: str = "dreadnode-agent"
    description: str | None = None
    dedupe_key: str | None = None
    host: str = "example.com"
    path: str = "/search"
    hidden: bool = False
    created_at: datetime = datetime(2025, 1, 1, tzinfo=timezone.utc)


@dataclass
class FakeReplaySession:
    id: str = "session_1"
    name: str = "Replay Session 1"


@dataclass
class FakeReplayEntry:
    id: str = "entry_1"
    request: FakeRequest | None = None
    response: FakeResponse | None = None


@dataclass
class FakeReplaySendResult:
    task_status: str = "DONE"
    error: str | None = None
    entry: FakeReplayEntry | None = None


def _mock_list_builder(connection: FakeConnection) -> MagicMock:
    """Build a chainable mock list builder (builder.first().filter().execute())."""
    builder = MagicMock()
    builder.first.return_value = builder
    builder.filter.return_value = builder
    builder.execute = AsyncMock(return_value=connection)
    return builder


def _make_mock_client(
    health: FakeHealth | None = None,
    request_list_conn: FakeConnection | None = None,
    request_get_entry: FakeRequestResponseOpt | None = None,
    scopes: list[FakeScope] | None = None,
    finding_list_conn: FakeConnection | None = None,
    created_finding: FakeFinding | None = None,
    created_scope: FakeScope | None = None,
    replay_session: FakeReplaySession | None = None,
    replay_send_result: FakeReplaySendResult | None = None,
    replay_sessions_conn: FakeConnection | None = None,
) -> MagicMock:
    """Create a fully wired mock Client."""
    client = MagicMock()
    client.connect = AsyncMock()

    # health
    client.health = AsyncMock(return_value=health or FakeHealth())

    # request SDK
    client.request.list.return_value = _mock_list_builder(
        request_list_conn or FakeConnection(edges=[])
    )
    client.request.get = AsyncMock(return_value=request_get_entry)

    # scope SDK
    client.scope.list = AsyncMock(return_value=scopes if scopes is not None else [])
    client.scope.create = AsyncMock(return_value=created_scope or FakeScope())

    # findings SDK
    client.findings.list.return_value = _mock_list_builder(
        finding_list_conn or FakeConnection(edges=[])
    )
    client.findings.create = AsyncMock(return_value=created_finding or FakeFinding())

    # replay SDK
    client.replay.sessions.create = AsyncMock(
        return_value=replay_session or FakeReplaySession()
    )
    client.replay.send = AsyncMock(
        return_value=replay_send_result or FakeReplaySendResult()
    )
    client.replay.sessions.list.return_value = _mock_list_builder(
        replay_sessions_conn or FakeConnection(edges=[])
    )

    return client


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    """Write a valid token file and return its path."""
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps({
        "accessToken": "test_access_token",
        "refreshToken": "test_refresh_token",
    }))
    return token_path


@pytest.fixture
def toolset(token_file: Path) -> CaidoTools:
    """Return a CaidoTools instance pointed at the temp token file."""
    return CaidoTools(
        caido_url="http://localhost:8080",
        token_path=str(token_file),
    )


# ---------------------------------------------------------------------------
# Tests — Tool Discovery & Schema
# ---------------------------------------------------------------------------


class TestToolDiscovery:
    """Verify all tools are discovered and have correct metadata."""

    def test_all_tools_discovered(self, toolset: CaidoTools) -> None:
        tools = toolset.get_tools()
        names = {t.name for t in tools}
        expected = {
            "caido_health",
            "caido_search_requests",
            "caido_get_request",
            "caido_replay_request",
            "caido_list_scopes",
            "caido_create_scope",
            "caido_list_findings",
            "caido_create_finding",
            "caido_replay_sessions",
        }
        assert names == expected, f"Missing: {expected - names}, Extra: {names - expected}"

    def test_all_tools_have_descriptions(self, toolset: CaidoTools) -> None:
        for t in toolset.get_tools():
            assert t.description, f"Tool {t.name} has no description"

    def test_tool_schemas_have_correct_types(self, toolset: CaidoTools) -> None:
        """Spot-check parameter schemas for key tools."""
        tools = {t.name: t for t in toolset.get_tools()}

        # caido_search_requests
        search_props = tools["caido_search_requests"].parameters_schema.get("properties", {})
        assert "filter" in search_props
        assert "limit" in search_props

        # caido_create_finding
        finding_props = tools["caido_create_finding"].parameters_schema.get("properties", {})
        assert "request_id" in finding_props
        assert "title" in finding_props
        assert "reporter" in finding_props
        assert "dedupe_key" in finding_props

        # caido_replay_request
        replay_props = tools["caido_replay_request"].parameters_schema.get("properties", {})
        assert "raw_request" in replay_props
        assert "host" in replay_props
        assert "port" in replay_props
        assert "tls" in replay_props

    def test_caido_create_scope_schema(self, toolset: CaidoTools) -> None:
        tools = {t.name: t for t in toolset.get_tools()}
        props = tools["caido_create_scope"].parameters_schema.get("properties", {})
        assert "name" in props
        assert "allowlist" in props
        assert "denylist" in props

    def test_all_tools_have_catch_enabled(self, toolset: CaidoTools) -> None:
        """All tools should use catch=True for graceful error handling."""
        for t in toolset.get_tools():
            assert t.catch is True, f"Tool {t.name} does not have catch=True"


# ---------------------------------------------------------------------------
# Tests — Connection & Auth
# ---------------------------------------------------------------------------


class TestConnection:
    """Test connection lifecycle and auth edge cases."""

    async def test_missing_token_file_returns_error(self) -> None:
        ts = CaidoTools(
            caido_url="http://localhost:8080",
            token_path="/nonexistent/path/token.json",
        )
        result = await ts.caido_health()
        assert "Error:" in result
        assert "not found" in result.lower()

    async def test_invalid_token_json_returns_error(self, tmp_path: Path) -> None:
        bad_token = tmp_path / "bad.json"
        bad_token.write_text("not valid json")
        ts = CaidoTools(caido_url="http://localhost:8080", token_path=str(bad_token))
        result = await ts.caido_health()
        assert "Error:" in result

    async def test_token_missing_access_token_key(self, tmp_path: Path) -> None:
        bad_token = tmp_path / "incomplete.json"
        bad_token.write_text(json.dumps({"refreshToken": "abc"}))
        ts = CaidoTools(caido_url="http://localhost:8080", token_path=str(bad_token))
        result = await ts.caido_health()
        assert "Error:" in result

    async def test_connection_refused_returns_error(self, toolset: CaidoTools) -> None:
        """Simulate Caido not running — Client.connect() raises."""
        mock_client = MagicMock()
        mock_client.connect = AsyncMock(side_effect=ConnectionError("Connection refused"))

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_health()

        assert "Error:" in result
        assert "connect" in result.lower() or "Connection refused" in result

    async def test_client_reused_across_calls(self, toolset: CaidoTools) -> None:
        """Client should be created once and reused."""
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client) as ctor:
                await toolset.caido_health()
                await toolset.caido_health()

        assert ctor.call_count == 1
        assert mock_client.connect.call_count == 1

    async def test_client_reset_on_connection_failure(self, toolset: CaidoTools) -> None:
        """After a connection failure, next call should attempt to reconnect."""
        failing_client = MagicMock()
        failing_client.connect = AsyncMock(side_effect=ConnectionError("down"))

        working_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", side_effect=[failing_client, working_client]):
                result1 = await toolset.caido_health()
                assert "Error:" in result1

                result2 = await toolset.caido_health()
                assert "Error:" not in result2

    async def test_token_with_optional_refresh_token(self, tmp_path: Path) -> None:
        """Token file without refreshToken should still work."""
        token_path = tmp_path / "token.json"
        token_path.write_text(json.dumps({"accessToken": "access_only"}))
        ts = CaidoTools(caido_url="http://localhost:8080", token_path=str(token_path))

        mock_client = _make_mock_client()
        with patch("caido_proxy.Client", return_value=mock_client):
            result = await ts.caido_health()

        assert "Error:" not in result
        assert "Connected" in result


# ---------------------------------------------------------------------------
# Tests — caido_health
# ---------------------------------------------------------------------------


class TestHealth:
    async def test_health_success(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(health=FakeHealth(
            name="MyInstance", version="2.5.0", ready=True
        ))

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_health()

        assert "MyInstance" in result
        assert "2.5.0" in result
        assert "True" in result
        assert "localhost:8080" in result

    async def test_health_not_ready(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(health=FakeHealth(ready=False))

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_health()

        assert "False" in result


# ---------------------------------------------------------------------------
# Tests — caido_search_requests
# ---------------------------------------------------------------------------


class TestSearchRequests:
    async def test_search_no_results(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(
            request_list_conn=FakeConnection(edges=[])
        )

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "No requests found" in result

    async def test_search_with_results(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(id="r1", method="POST", host="target.com", path="/login"),
            response=FakeResponse(status_code=302, content_length=0),
        )
        conn = FakeConnection(edges=[FakeEdge(node=entry)])
        mock_client = _make_mock_client(request_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "r1" in result
        assert "POST" in result
        assert "302" in result
        assert "target.com" in result
        assert "/login" in result

    async def test_search_with_query_string(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(
                id="r2", method="GET", host="api.com", path="/search", query="q=xss"
            ),
            response=FakeResponse(status_code=200, content_length=500),
        )
        conn = FakeConnection(edges=[FakeEdge(node=entry)])
        mock_client = _make_mock_client(request_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "?q=xss" in result

    async def test_search_with_no_response(self, toolset: CaidoTools) -> None:
        """Requests without a response should show dashes."""
        entry = FakeRequestResponseOpt(
            request=FakeRequest(id="r3", method="GET", host="slow.com", path="/"),
            response=None,
        )
        conn = FakeConnection(edges=[FakeEdge(node=entry)])
        mock_client = _make_mock_client(request_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "r3" in result
        assert "-\t-" in result  # status and length are dashes

    async def test_search_passes_filter_and_limit(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(edges=[])
        builder_mock = _mock_list_builder(conn)
        mock_client = _make_mock_client()
        mock_client.request.list.return_value = builder_mock

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_search_requests(filter="host:example.com", limit=5)

        builder_mock.first.assert_called_once_with(5)
        builder_mock.filter.assert_called_once_with("host:example.com")

    async def test_search_no_filter_skips_filter_call(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(edges=[])
        builder_mock = _mock_list_builder(conn)
        mock_client = _make_mock_client()
        mock_client.request.list.return_value = builder_mock

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_search_requests(filter=None, limit=20)

        builder_mock.filter.assert_not_called()

    async def test_search_pagination_indicator(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(),
            response=FakeResponse(),
        )
        conn = FakeConnection(
            edges=[FakeEdge(node=entry)],
            page_info=FakePageInfo(has_next_page=True, end_cursor="abc123"),
        )
        mock_client = _make_mock_client(request_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "more results available" in result
        assert "abc123" in result

    async def test_search_http_scheme_for_non_tls(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(tls=False, host="plain.com", path="/"),
            response=FakeResponse(),
        )
        conn = FakeConnection(edges=[FakeEdge(node=entry)])
        mock_client = _make_mock_client(request_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_search_requests()

        assert "http://plain.com/" in result
        assert "https://" not in result

    async def test_search_caido_down_returns_error(self, toolset: CaidoTools) -> None:
        """When Caido is down, search should return an error, not crash."""
        ts = CaidoTools(
            caido_url="http://localhost:8080",
            token_path="/nonexistent/path/token.json",
        )
        result = await ts.caido_search_requests(filter="host:example.com")
        assert "Error:" in result


# ---------------------------------------------------------------------------
# Tests — caido_get_request
# ---------------------------------------------------------------------------


class TestGetRequest:
    async def test_get_request_not_found(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(request_get_entry=None)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("nonexistent")

        assert "Error:" in result
        assert "not found" in result.lower()

    async def test_get_request_basic_info(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(
                id="req_42", method="PUT", host="api.com", path="/users/1",
                query="admin=true",
            ),
            response=FakeResponse(status_code=200, content_length=256, roundtrip=15),
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_42")

        assert "req_42" in result
        assert "PUT" in result
        assert "api.com" in result
        assert "/users/1" in result
        assert "?admin=true" in result
        assert "200" in result
        assert "256" in result
        assert "15ms" in result

    async def test_get_request_with_headers(self, toolset: CaidoTools) -> None:
        raw_req = b"GET /test HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n"
        raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>"
        entry = FakeRequestResponseOpt(
            request=FakeRequest(raw=raw_req),
            response=FakeResponse(raw=raw_resp),
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_1", include="headers")

        assert "request headers" in result
        assert "Cookie: session=abc" in result
        assert "response headers" in result
        assert "Content-Type: text/html" in result

    async def test_get_request_with_body(self, toolset: CaidoTools) -> None:
        raw_req = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=test"
        raw_resp = b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\nRedirecting..."
        entry = FakeRequestResponseOpt(
            request=FakeRequest(raw=raw_req),
            response=FakeResponse(raw=raw_resp),
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_1", include="headers,body")

        assert "request body" in result
        assert "user=admin&pass=test" in result
        assert "response body" in result
        assert "Redirecting..." in result

    async def test_get_request_no_raw_data(self, toolset: CaidoTools) -> None:
        """When include is requested but raw is None, should not crash."""
        entry = FakeRequestResponseOpt(
            request=FakeRequest(raw=None),
            response=FakeResponse(raw=None),
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_1", include="headers,body")

        assert "id: req_1" in result
        # Should not contain headers/body sections
        assert "request headers" not in result

    async def test_get_request_no_include(self, toolset: CaidoTools) -> None:
        """Without include, should show metadata only."""
        entry = FakeRequestResponseOpt(
            request=FakeRequest(raw=b"GET / HTTP/1.1\r\n\r\n"),
            response=FakeResponse(raw=b"HTTP/1.1 200 OK\r\n\r\n"),
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_1")

        assert "id: req_1" in result
        assert "request headers" not in result

    async def test_get_request_no_response(self, toolset: CaidoTools) -> None:
        entry = FakeRequestResponseOpt(
            request=FakeRequest(),
            response=None,
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_get_request("req_1")

        assert "status:" not in result

    async def test_get_request_large_response_truncated(self, toolset: CaidoTools) -> None:
        """Response body larger than max_output_chars should be truncated."""
        big_body = "X" * 60_000
        raw_resp = f"HTTP/1.1 200 OK\r\n\r\n{big_body}".encode()
        entry = FakeRequestResponseOpt(
            request=FakeRequest(),
            response=FakeResponse(raw=raw_resp),
        )
        ts = CaidoTools(
            caido_url="http://localhost:8080",
            token_path=toolset.token_path,
            max_output_chars=1000,
        )
        mock_client = _make_mock_client(request_get_entry=entry)

        with patch.object(type(ts), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await ts.caido_get_request("req_1", include="body")

        assert "TRUNCATED" in result
        assert "60000 chars total" in result


# ---------------------------------------------------------------------------
# Tests — caido_replay_request
# ---------------------------------------------------------------------------


class TestReplayRequest:
    async def test_replay_basic(self, toolset: CaidoTools) -> None:
        send_result = FakeReplaySendResult(task_status="DONE")
        mock_client = _make_mock_client(replay_send_result=send_result)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
                    host="example.com",
                )

        assert "DONE" in result

    async def test_replay_creates_session(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\nHost: test.com\\r\\n\\r\\n",
                    host="test.com",
                )

        mock_client.replay.sessions.create.assert_called_once()

    async def test_replay_passes_correct_options(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(
            replay_session=FakeReplaySession(id="sess_99"),
        )

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_request(
                    raw_request="POST /api HTTP/1.1\\r\\nHost: h\\r\\n\\r\\nbody",
                    host="target.io",
                    port=8443,
                    tls=True,
                )

        mock_client.replay.send.assert_called_once()
        call_args = mock_client.replay.send.call_args
        assert call_args[0][0] == "sess_99"
        opts = call_args[0][1]
        assert opts.host == "target.io"
        assert opts.port == 8443
        assert opts.tls is True
        assert b"POST /api HTTP/1.1\r\nHost: h\r\n\r\nbody" == opts.raw

    async def test_replay_default_port_tls(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\n\\r\\n",
                    host="secure.com",
                    tls=True,
                )

        opts = mock_client.replay.send.call_args[0][1]
        assert opts.port == 443

    async def test_replay_default_port_no_tls(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\n\\r\\n",
                    host="plain.com",
                    tls=False,
                )

        opts = mock_client.replay.send.call_args[0][1]
        assert opts.port == 80

    async def test_replay_with_response(self, toolset: CaidoTools) -> None:
        send_result = FakeReplaySendResult(
            task_status="DONE",
            entry=FakeReplayEntry(
                id="ent_1",
                request=FakeRequest(id="req_replayed"),
                response=FakeResponse(status_code=200, content_length=42, roundtrip=10),
            ),
        )
        mock_client = _make_mock_client(replay_send_result=send_result)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\n\\r\\n",
                    host="example.com",
                )

        assert "ent_1" in result
        assert "req_replayed" in result
        assert "200" in result

    async def test_replay_error_result(self, toolset: CaidoTools) -> None:
        send_result = FakeReplaySendResult(task_status="ERROR", error="Connection timed out")
        mock_client = _make_mock_client(replay_send_result=send_result)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\n\\r\\n",
                    host="timeout.com",
                )

        assert "ERROR" in result
        assert "Connection timed out" in result

    async def test_replay_crlf_conversion(self, toolset: CaidoTools) -> None:
        """Literal \\r\\n in the string should be converted to actual CRLF bytes."""
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_request(
                    raw_request="GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n",
                    host="x",
                )

        opts = mock_client.replay.send.call_args[0][1]
        assert b"\r\n" in opts.raw
        assert b"\\r\\n" not in opts.raw


# ---------------------------------------------------------------------------
# Tests — caido_list_scopes / caido_create_scope
# ---------------------------------------------------------------------------


class TestScopes:
    async def test_list_scopes_empty(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(scopes=[])

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_list_scopes()

        assert "No scopes defined" in result

    async def test_list_scopes_with_entries(self, toolset: CaidoTools) -> None:
        scopes = [
            FakeScope(id="s1", name="prod", allowlist=["*://prod.com/*"], denylist=[]),
            FakeScope(id="s2", name="staging", allowlist=["*://staging.com/*"], denylist=["*/admin/*"]),
        ]
        mock_client = _make_mock_client(scopes=scopes)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_list_scopes()

        assert "s1" in result
        assert "prod" in result
        assert "s2" in result
        assert "staging" in result
        assert "*/admin/*" in result

    async def test_create_scope(self, toolset: CaidoTools) -> None:
        created = FakeScope(id="s_new", name="new-scope")
        mock_client = _make_mock_client(created_scope=created)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_create_scope(
                    name="new-scope",
                    allowlist=["*://target.com/*"],
                )

        assert "s_new" in result
        assert "new-scope" in result

    async def test_create_scope_passes_correct_options(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_create_scope(
                    name="tight",
                    allowlist=["*://a.com/*", "*://b.com/*"],
                    denylist=["*/logout*"],
                )

        mock_client.scope.create.assert_called_once()
        opts = mock_client.scope.create.call_args[0][0]
        assert opts.name == "tight"
        assert opts.allowlist == ["*://a.com/*", "*://b.com/*"]
        assert opts.denylist == ["*/logout*"]

    async def test_create_scope_default_denylist(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_create_scope(name="simple", allowlist=["*://x.com/*"])

        opts = mock_client.scope.create.call_args[0][0]
        assert opts.denylist == []


# ---------------------------------------------------------------------------
# Tests — caido_list_findings / caido_create_finding
# ---------------------------------------------------------------------------


class TestFindings:
    async def test_list_findings_empty(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(finding_list_conn=FakeConnection(edges=[]))

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_list_findings()

        assert "No findings found" in result

    async def test_list_findings_with_entries(self, toolset: CaidoTools) -> None:
        findings = [
            FakeFinding(id="f1", reporter="agent", host="vuln.com", path="/xss", title="Reflected XSS"),
            FakeFinding(id="f2", reporter="manual", host="vuln.com", path="/sqli", title="SQL Injection"),
        ]
        conn = FakeConnection(edges=[FakeEdge(node=f) for f in findings])
        mock_client = _make_mock_client(finding_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_list_findings()

        assert "f1" in result
        assert "Reflected XSS" in result
        assert "f2" in result
        assert "SQL Injection" in result

    async def test_list_findings_passes_filter(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(edges=[])
        builder_mock = _mock_list_builder(conn)
        mock_client = _make_mock_client()
        mock_client.findings.list.return_value = builder_mock

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_list_findings(filter="host:target.com", limit=10)

        builder_mock.first.assert_called_once_with(10)
        builder_mock.filter.assert_called_once_with("host:target.com")

    async def test_list_findings_pagination(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(
            edges=[FakeEdge(node=FakeFinding())],
            page_info=FakePageInfo(has_next_page=True),
        )
        mock_client = _make_mock_client(finding_list_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_list_findings()

        assert "more results available" in result

    async def test_create_finding(self, toolset: CaidoTools) -> None:
        created = FakeFinding(id="f_new", title="SSRF via redirect")
        mock_client = _make_mock_client(created_finding=created)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_create_finding(
                    request_id="req_42",
                    title="SSRF via redirect",
                )

        assert "f_new" in result
        assert "SSRF via redirect" in result

    async def test_create_finding_passes_correct_options(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_create_finding(
                    request_id="req_99",
                    title="Stored XSS",
                    description="Alert fires in admin panel",
                    reporter="my-agent",
                    dedupe_key="xss-admin-panel",
                )

        mock_client.findings.create.assert_called_once()
        call_args = mock_client.findings.create.call_args[0]
        assert call_args[0] == "req_99"
        opts = call_args[1]
        assert opts.title == "Stored XSS"
        assert opts.description == "Alert fires in admin panel"
        assert opts.reporter == "my-agent"
        assert opts.dedupe_key == "xss-admin-panel"

    async def test_create_finding_default_reporter(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client()

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_create_finding(
                    request_id="req_1",
                    title="Test",
                )

        opts = mock_client.findings.create.call_args[0][1]
        assert opts.reporter == "dreadnode-agent"


# ---------------------------------------------------------------------------
# Tests — caido_replay_sessions
# ---------------------------------------------------------------------------


class TestReplaySessions:
    async def test_replay_sessions_empty(self, toolset: CaidoTools) -> None:
        mock_client = _make_mock_client(replay_sessions_conn=FakeConnection(edges=[]))

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_sessions()

        assert "No replay sessions found" in result

    async def test_replay_sessions_with_entries(self, toolset: CaidoTools) -> None:
        sessions = [
            FakeReplaySession(id="s1", name="Session 1"),
            FakeReplaySession(id="s2", name="Session 2"),
        ]
        conn = FakeConnection(edges=[FakeEdge(node=s) for s in sessions])
        mock_client = _make_mock_client(replay_sessions_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_sessions()

        assert "s1" in result
        assert "Session 1" in result
        assert "s2" in result

    async def test_replay_sessions_pagination(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(
            edges=[FakeEdge(node=FakeReplaySession())],
            page_info=FakePageInfo(has_next_page=True),
        )
        mock_client = _make_mock_client(replay_sessions_conn=conn)

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                result = await toolset.caido_replay_sessions()

        assert "more results available" in result

    async def test_replay_sessions_passes_limit(self, toolset: CaidoTools) -> None:
        conn = FakeConnection(edges=[])
        builder_mock = _mock_list_builder(conn)
        mock_client = _make_mock_client()
        mock_client.replay.sessions.list.return_value = builder_mock

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                await toolset.caido_replay_sessions(limit=5)

        builder_mock.first.assert_called_once_with(5)


# ---------------------------------------------------------------------------
# Tests — handle_tool_call integration
# ---------------------------------------------------------------------------


class TestHandleToolCall:
    """Verify tools work through the full handle_tool_call pipeline."""

    async def test_health_via_handle_tool_call(self, toolset: CaidoTools) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        mock_client = _make_mock_client()
        tools = {t.name: t for t in toolset.get_tools()}

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                tc = ToolCall(
                    id="call_health",
                    function=FunctionCall(name="caido_health", arguments="{}"),
                )
                message, stop = await tools["caido_health"].handle_tool_call(tc)

        assert stop is False
        assert "Connected" in message.content

    async def test_search_via_handle_tool_call(self, toolset: CaidoTools) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        entry = FakeRequestResponseOpt(
            request=FakeRequest(id="r1", method="GET", host="test.com", path="/"),
            response=FakeResponse(),
        )
        conn = FakeConnection(edges=[FakeEdge(node=entry)])
        mock_client = _make_mock_client(request_list_conn=conn)
        tools = {t.name: t for t in toolset.get_tools()}

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                tc = ToolCall(
                    id="call_search",
                    function=FunctionCall(
                        name="caido_search_requests",
                        arguments='{"filter": "host:test.com", "limit": 10}',
                    ),
                )
                message, stop = await tools["caido_search_requests"].handle_tool_call(tc)

        assert stop is False
        assert "r1" in message.content
        assert "test.com" in message.content

    async def test_create_finding_via_handle_tool_call(self, toolset: CaidoTools) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        mock_client = _make_mock_client(
            created_finding=FakeFinding(id="f_htc", title="Via ToolCall"),
        )
        tools = {t.name: t for t in toolset.get_tools()}

        with patch.object(type(toolset), "_load_tokens", return_value=FakeTokenPair("tok")):
            with patch("caido_proxy.Client", return_value=mock_client):
                tc = ToolCall(
                    id="call_create_finding",
                    function=FunctionCall(
                        name="caido_create_finding",
                        arguments='{"request_id": "r1", "title": "Via ToolCall"}',
                    ),
                )
                message, stop = await tools["caido_create_finding"].handle_tool_call(tc)

        assert stop is False
        assert "f_htc" in message.content

    async def test_error_via_handle_tool_call(self) -> None:
        """Errors should be returned as message content, not raised."""
        from dreadnode.agents.tools import FunctionCall, ToolCall

        ts = CaidoTools(
            caido_url="http://localhost:8080",
            token_path="/nonexistent/token.json",
        )
        tools = {t.name: t for t in ts.get_tools()}

        tc = ToolCall(
            id="call_err",
            function=FunctionCall(name="caido_health", arguments="{}"),
        )
        message, stop = await tools["caido_health"].handle_tool_call(tc)

        assert stop is False
        assert "Error:" in message.content


# ---------------------------------------------------------------------------
# Tests — Toolset properties
# ---------------------------------------------------------------------------


class TestToolsetProperties:
    def test_default_values(self) -> None:
        ts = CaidoTools()
        assert ts.caido_url == "http://localhost:8080"
        assert ts.max_output_chars == 50_000

    def test_custom_values(self) -> None:
        ts = CaidoTools(
            caido_url="http://caido:9090",
            max_output_chars=1000,
        )
        assert ts.caido_url == "http://caido:9090"
        assert ts.max_output_chars == 1000

    def test_name_property(self) -> None:
        ts = CaidoTools()
        assert ts.name == "CaidoTools"
