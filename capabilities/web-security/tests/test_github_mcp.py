"""Tests for the GitHub MCP server."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest


def _install_fastmcp_stub() -> None:
    """Install a minimal fastmcp stub so github.py can be imported."""
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

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "github.py"
SPEC = importlib.util.spec_from_file_location("github_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

_GitHubClient = MODULE._GitHubClient


def _mock_response(
    status_code: int = 200,
    json_data: object = None,
    text: str | None = None,
) -> httpx.Response:
    kwargs: dict = {
        "status_code": status_code,
        "request": httpx.Request("GET", "https://api.github.com/test"),
    }
    if json_data is not None:
        kwargs["json"] = json_data
    elif text is not None:
        kwargs["text"] = text
    return httpx.Response(**kwargs)


def _issue() -> dict:
    return {
        "number": 123,
        "state": "open",
        "title": "Stored XSS",
        "html_url": "https://github.com/dreadnode/example/issues/123",
        "body": "Validated report",
        "user": {"login": "security-bot"},
        "labels": [{"name": "security"}, {"name": "high"}],
    }


class TestGitHubClient:
    def test_settings_requires_token(self) -> None:
        client = _GitHubClient()
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError, match="GITHUB_TOKEN"):
                client._settings()

    def test_settings_strips_api_url(self) -> None:
        client = _GitHubClient()
        env = {
            "GITHUB_API_URL": "https://github.example.com/api/v3/",
            "GITHUB_TOKEN": "tok",
        }
        with patch.dict("os.environ", env, clear=True):
            assert client._settings() == ("https://github.example.com/api/v3", "tok")

    @pytest.mark.asyncio
    async def test_get_builds_bearer_client(self) -> None:
        client = _GitHubClient()
        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}, clear=True):
            http_client = await client.get()

        assert http_client.base_url == "https://api.github.com"
        assert http_client.headers["Authorization"] == "Bearer tok"
        assert http_client.headers["X-GitHub-Api-Version"] == "2022-11-28"


class TestHelpers:
    def test_drop_empty_preserves_zero_and_false(self) -> None:
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

    def test_raise_for_github_includes_status_and_body(self) -> None:
        resp = _mock_response(status_code=403, text="denied")
        with pytest.raises(RuntimeError, match="HTTP 403: denied"):
            MODULE._raise_for_github(resp, "test")


class TestTools:
    @pytest.mark.asyncio
    async def test_health_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data={
                "login": "security-bot",
                "id": 1,
                "html_url": "https://github.com/security-bot",
            }
        )

        with patch.object(MODULE._github, "get", return_value=mock_client):
            result = await MODULE.github_health()

        assert "Connected to GitHub" in result
        assert "security-bot" in result
        mock_client.get.assert_called_once_with("/user")

    @pytest.mark.asyncio
    async def test_list_labels_formats_rows(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            json_data=[
                {"name": "security", "description": "Security issue"},
                {"name": "high", "description": None},
            ]
        )

        with patch.object(MODULE._github, "get", return_value=mock_client):
            result = await MODULE.github_list_labels("dreadnode", "example")

        assert "Labels for dreadnode/example" in result
        assert "security\tSecurity issue" in result
        assert "high" in result

    @pytest.mark.asyncio
    async def test_create_issue_posts_expected_payload(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(
            status_code=201, json_data=_issue()
        )

        with patch.object(MODULE._github, "get", return_value=mock_client):
            result = await MODULE.github_create_issue(
                owner="dreadnode",
                repo="example",
                title="Stored XSS",
                body="Validated report",
                labels=["security", "high"],
                assignees=["security-bot"],
                milestone=1,
            )

        assert "Created GitHub issue #123\topen\tStored XSS" in result
        mock_client.post.assert_called_once_with(
            "/repos/dreadnode/example/issues",
            json={
                "title": "Stored XSS",
                "body": "Validated report",
                "labels": ["security", "high"],
                "assignees": ["security-bot"],
                "milestone": 1,
            },
        )

    @pytest.mark.asyncio
    async def test_get_issue_returns_body(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(json_data=_issue())

        with patch.object(MODULE._github, "get", return_value=mock_client):
            result = await MODULE.github_get_issue("dreadnode", "example", 123)

        assert "#123\topen\tStored XSS" in result
        assert "Author: security-bot" in result
        assert "Labels: security, high" in result
        assert "Validated report" in result

    @pytest.mark.asyncio
    async def test_add_comment_posts_body(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(
            status_code=201,
            json_data={
                "id": 99,
                "html_url": "https://github.com/dreadnode/example/issues/123#comment-99",
            },
        )

        with patch.object(MODULE._github, "get", return_value=mock_client):
            result = await MODULE.github_add_comment(
                "dreadnode",
                "example",
                123,
                "new evidence",
            )

        assert "Added GitHub comment 99" in result
        mock_client.post.assert_called_once_with(
            "/repos/dreadnode/example/issues/123/comments",
            json={"body": "new evidence"},
        )
