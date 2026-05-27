"""Tests for the Jira MCP server."""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest


def _install_fastmcp_stub() -> None:
    """Install a minimal fastmcp stub so jira.py can be imported."""
    fastmcp = types.ModuleType("fastmcp")

    class _FastMCP:
        def __init__(self, name: str) -> None:
            self.name = name
            self._tools: dict[str, object] = {}

        def tool(self, fn):
            self._tools[fn.__name__] = fn
            return fn

        def run(self, **kwargs) -> None:
            pass

    setattr(fastmcp, "FastMCP", _FastMCP)
    sys.modules["fastmcp"] = fastmcp


_install_fastmcp_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "jira.py"
SPEC = importlib.util.spec_from_file_location("jira_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

_JiraClient = MODULE._JiraClient


def _mock_response(
    status_code: int = 200,
    json_data: object = None,
    text: str | None = None,
) -> httpx.Response:
    kwargs: dict = {
        "status_code": status_code,
        "request": httpx.Request("GET", "https://example.atlassian.net/test"),
    }
    if json_data is not None:
        kwargs["json"] = json_data
    elif text is not None:
        kwargs["text"] = text
    return httpx.Response(**kwargs)


class TestJiraClient:
    def test_settings_missing_credentials(self) -> None:
        client = _JiraClient()
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError, match="JIRA_BASE_URL"):
                client._settings()

    def test_settings_strips_base_url(self) -> None:
        client = _JiraClient()
        env = {
            "JIRA_BASE_URL": "https://example.atlassian.net/",
            "JIRA_EMAIL": "user@example.com",
            "JIRA_API_TOKEN": "token",
        }
        with patch.dict("os.environ", env, clear=True):
            assert client._settings() == (
                "https://example.atlassian.net",
                "user@example.com",
                "token",
            )

    @pytest.mark.asyncio
    async def test_get_builds_basic_auth_client(self) -> None:
        client = _JiraClient()
        env = {
            "JIRA_BASE_URL": "https://example.atlassian.net",
            "JIRA_EMAIL": "user@example.com",
            "JIRA_API_TOKEN": "token",
        }
        with patch.dict("os.environ", env, clear=True):
            http_client = await client.get()

        expected = base64.b64encode(b"user@example.com:token").decode()
        assert http_client.base_url == "https://example.atlassian.net"
        assert http_client.headers["Authorization"] == f"Basic {expected}"


class TestHelpers:
    def test_adf_text_builds_paragraphs_and_breaks(self) -> None:
        adf = MODULE._adf_text("line one\nline two\n\nline three")

        assert adf["type"] == "doc"
        assert adf["version"] == 1
        assert len(adf["content"]) == 2
        first = adf["content"][0]["content"]
        assert first[0] == {"type": "text", "text": "line one"}
        assert first[1] == {"type": "hardBreak"}
        assert first[2] == {"type": "text", "text": "line two"}

    def test_raise_for_jira_includes_status_and_body(self) -> None:
        resp = _mock_response(status_code=403, text="nope")
        with pytest.raises(RuntimeError, match="HTTP 403: nope"):
            MODULE._raise_for_jira(resp, "test")


class TestTools:
    @pytest.mark.asyncio
    async def test_health_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "accountId": "abc123",
                "displayName": "Security Bot",
                "emailAddress": "sec@example.com",
            }
        )

        with patch.object(MODULE._jira, "get", return_value=mock_client):
            result = await MODULE.jira_health()

        assert "Connected to Jira" in result
        assert "abc123" in result
        assert "Security Bot" in result
        mock_client.get.assert_called_once_with("/rest/api/3/myself")

    @pytest.mark.asyncio
    async def test_get_create_metadata_formats_issue_types(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "issueTypes": [
                    {"id": "10001", "name": "Bug", "description": "Bug report"},
                    {"id": "10002", "name": "Task"},
                ]
            }
        )

        with patch.object(MODULE._jira, "get", return_value=mock_client):
            result = await MODULE.jira_get_create_metadata("ENG")

        assert "Creatable issue types for ENG" in result
        assert "10001\tBug" in result
        assert "10002\tTask" in result
        mock_client.get.assert_called_once_with(
            "/rest/api/3/issue/createmeta/ENG/issuetypes"
        )

    @pytest.mark.asyncio
    async def test_create_issue_posts_expected_fields(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(
            status_code=201,
            json_data={"key": "ENG-123"},
        )
        env = {"JIRA_BASE_URL": "https://example.atlassian.net"}

        with (
            patch.object(MODULE._jira, "get", return_value=mock_client),
            patch.dict("os.environ", env, clear=True),
        ):
            result = await MODULE.jira_create_issue(
                project_key="ENG",
                issue_type="Bug",
                summary="Stored XSS in comments",
                description="Validated report body",
                priority="High",
                labels=["web-security", "validated"],
                assignee_account_id="acct-1",
                components=["AppSec"],
            )

        assert result == (
            "Created Jira issue ENG-123: "
            "https://example.atlassian.net/browse/ENG-123"
        )
        _, kwargs = mock_client.post.call_args
        fields = kwargs["json"]["fields"]
        assert fields["project"] == {"key": "ENG"}
        assert fields["issuetype"] == {"name": "Bug"}
        assert fields["priority"] == {"name": "High"}
        assert fields["labels"] == ["web-security", "validated"]
        assert fields["assignee"] == {"accountId": "acct-1"}
        assert fields["components"] == [{"name": "AppSec"}]
        assert fields["description"]["type"] == "doc"

    @pytest.mark.asyncio
    async def test_get_issue_returns_summary(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "key": "ENG-123",
                "fields": {
                    "summary": "Stored XSS",
                    "status": {"name": "Todo"},
                    "priority": {"name": "High"},
                    "description": {"type": "doc"},
                },
            }
        )

        with patch.object(MODULE._jira, "get", return_value=mock_client):
            result = await MODULE.jira_get_issue("ENG-123")

        assert "ENG-123\tTodo\tHigh\tStored XSS" in result
        assert "--- Description ADF ---" in result

    @pytest.mark.asyncio
    async def test_add_comment_posts_adf_body(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(json_data={"id": "10000"})

        with patch.object(MODULE._jira, "get", return_value=mock_client):
            result = await MODULE.jira_add_comment("ENG-123", "new evidence")

        assert result == "Added comment 10000 to Jira issue ENG-123."
        mock_client.post.assert_called_once()
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["body"]["type"] == "doc"
