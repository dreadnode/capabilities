"""Tests for the Linear MCP server."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest


def _install_fastmcp_stub() -> None:
    """Install a minimal fastmcp stub so linear.py can be imported."""
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

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "linear.py"
SPEC = importlib.util.spec_from_file_location("linear_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

_LinearClient = MODULE._LinearClient


def _mock_response(
    status_code: int = 200,
    json_data: object = None,
    text: str | None = None,
) -> httpx.Response:
    kwargs: dict = {
        "status_code": status_code,
        "request": httpx.Request("POST", "https://api.linear.app/graphql"),
    }
    if json_data is not None:
        kwargs["json"] = json_data
    elif text is not None:
        kwargs["text"] = text
    return httpx.Response(**kwargs)


class TestLinearClient:
    def test_settings_requires_credentials(self) -> None:
        client = _LinearClient()
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError, match="LINEAR_API_KEY"):
                client._settings()

    def test_settings_prefers_oauth_access_token(self) -> None:
        client = _LinearClient()
        env = {"LINEAR_API_KEY": "api-key", "LINEAR_ACCESS_TOKEN": "oauth-token"}
        with patch.dict("os.environ", env, clear=True):
            api_url, authorization = client._settings()

        assert api_url == "https://api.linear.app/graphql"
        assert authorization == "Bearer oauth-token"

    def test_settings_uses_personal_api_key_raw_authorization(self) -> None:
        client = _LinearClient()
        with patch.dict("os.environ", {"LINEAR_API_KEY": "api-key"}, clear=True):
            _, authorization = client._settings()

        assert authorization == "api-key"

    @pytest.mark.asyncio
    async def test_graphql_raises_for_graphql_errors(self) -> None:
        client = _LinearClient()
        mock_http = AsyncMock()
        mock_http.post.return_value = _mock_response(
            json_data={"errors": [{"message": "bad input"}]}
        )
        client._client = mock_http

        with pytest.raises(RuntimeError, match="bad input"):
            await client.graphql("query Test { viewer { id } }")


class TestHelpers:
    def test_drop_empty_preserves_false_and_zero(self) -> None:
        result = MODULE._drop_empty(
            {
                "empty": "",
                "none": None,
                "list": [],
                "dict": {},
                "zero": 0,
                "false": False,
                "value": "x",
            }
        )
        assert result == {"zero": 0, "false": False, "value": "x"}


class TestTools:
    @pytest.mark.asyncio
    async def test_health_success(self) -> None:
        data = {
            "viewer": {
                "id": "user-1",
                "displayName": "Security Bot",
                "email": "sec@example.com",
            }
        }
        with patch.object(MODULE._linear, "graphql", return_value=data):
            result = await MODULE.linear_health()

        assert "Connected to Linear" in result
        assert "user-1" in result
        assert "Security Bot" in result

    @pytest.mark.asyncio
    async def test_list_teams_formats_rows(self) -> None:
        data = {
            "teams": {
                "nodes": [
                    {"id": "team-1", "key": "ENG", "name": "Engineering"},
                    {"id": "team-2", "key": "SEC", "name": "Security"},
                ]
            }
        }
        with patch.object(MODULE._linear, "graphql", return_value=data) as graphql:
            result = await MODULE.linear_list_teams(first=10)

        assert "team-1\tENG\tEngineering" in result
        assert "team-2\tSEC\tSecurity" in result
        assert graphql.call_args.args[1] == {"first": 10}

    @pytest.mark.asyncio
    async def test_create_issue_sends_expected_input(self) -> None:
        data = {
            "issueCreate": {
                "success": True,
                "issue": {
                    "id": "issue-1",
                    "identifier": "ENG-123",
                    "title": "Stored XSS",
                    "url": "https://linear.app/dreadnode/issue/ENG-123",
                },
            }
        }
        with patch.object(MODULE._linear, "graphql", return_value=data) as graphql:
            result = await MODULE.linear_create_issue(
                team_id="team-1",
                title="Stored XSS",
                description="Validated report",
                priority=2,
                assignee_id="user-1",
                project_id="project-1",
                state_id="state-1",
                label_ids=["label-1"],
            )

        assert result == (
            "Created Linear issue ENG-123: "
            "https://linear.app/dreadnode/issue/ENG-123"
        )
        variables = graphql.call_args.args[1]
        assert variables["input"] == {
            "teamId": "team-1",
            "title": "Stored XSS",
            "description": "Validated report",
            "priority": 2,
            "assigneeId": "user-1",
            "projectId": "project-1",
            "stateId": "state-1",
            "labelIds": ["label-1"],
        }

    @pytest.mark.asyncio
    async def test_create_issue_raises_on_unsuccessful_mutation(self) -> None:
        with patch.object(
            MODULE._linear,
            "graphql",
            return_value={"issueCreate": {"success": False}},
        ):
            with pytest.raises(RuntimeError, match="success=false"):
                await MODULE.linear_create_issue(
                    team_id="team-1",
                    title="Stored XSS",
                    description="Validated report",
                )

    @pytest.mark.asyncio
    async def test_get_issue_returns_summary(self) -> None:
        data = {
            "issue": {
                "id": "issue-1",
                "identifier": "ENG-123",
                "title": "Stored XSS",
                "url": "https://linear.app/dreadnode/issue/ENG-123",
                "priority": 2,
                "state": {"name": "Todo"},
                "assignee": {"name": "Security Bot"},
                "description": "Validated report",
            }
        }
        with patch.object(MODULE._linear, "graphql", return_value=data):
            result = await MODULE.linear_get_issue("ENG-123")

        assert "ENG-123\tTodo\tpriority=2\tStored XSS" in result
        assert "Assignee: Security Bot" in result
        assert "Validated report" in result

    @pytest.mark.asyncio
    async def test_add_comment_returns_comment_summary(self) -> None:
        data = {
            "commentCreate": {
                "success": True,
                "comment": {
                    "id": "comment-1",
                    "url": "https://linear.app/comment/comment-1",
                },
            }
        }
        with patch.object(MODULE._linear, "graphql", return_value=data) as graphql:
            result = await MODULE.linear_add_comment("ENG-123", "new evidence")

        assert result == (
            "Added Linear comment comment-1: https://linear.app/comment/comment-1"
        )
        variables = graphql.call_args.args[1]
        assert variables["input"] == {"issueId": "ENG-123", "body": "new evidence"}
