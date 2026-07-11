"""Tests for the AgentMail integration tool."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock

import pytest


def _install_dreadnode_tools_stub() -> None:
    existing = sys.modules.get("dreadnode.agents.tools")
    if existing is not None and hasattr(existing, "Toolset"):
        return

    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    class _Tool:
        def __init__(self, name: str, description: str, catch: bool) -> None:
            self.name = name
            self.description = description
            self.catch = catch

    def tool_method(*, name: str, catch: bool = False):
        def decorator(fn):
            fn._tool_metadata = {
                "name": name,
                "catch": catch,
                "description": fn.__doc__ or "",
            }
            return fn

        return decorator

    class Toolset:
        def get_tools(self):
            discovered = []
            for attr_name in dir(self):
                value = getattr(self, attr_name)
                meta = getattr(value, "_tool_metadata", None)
                if meta:
                    discovered.append(
                        _Tool(meta["name"], meta["description"], meta["catch"])
                    )
            return discovered

    tools.Toolset = Toolset
    tools.tool_method = tool_method
    agents.tools = tools
    dreadnode.agents = agents

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.tools"] = tools


_install_dreadnode_tools_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "agentmail.py"
SPEC = importlib.util.spec_from_file_location("agentmail", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

AgentMail = MODULE.AgentMail


def _mock_response(status_code: int, payload: object) -> AsyncMock:
    resp = AsyncMock()
    resp.status_code = status_code
    resp.json = lambda: payload
    resp.text = payload if isinstance(payload, str) else json.dumps(payload)
    return resp


def _attach_client(toolset: AgentMail, resp: AsyncMock) -> AsyncMock:
    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    client.is_closed = False
    toolset._http = client
    return client


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTMAIL_API_KEY", raising=False)
    monkeypatch.delenv("AGENTMAIL_BASE_URL", raising=False)


@pytest.fixture
def toolset() -> AgentMail:
    return AgentMail()


# ── Tool discovery ───────────────────────────────────────────────────


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: AgentMail) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "agentmail_list_inboxes",
            "agentmail_create_inbox",
            "agentmail_list_messages",
            "agentmail_get_message",
            "agentmail_send_message",
            "agentmail_reply_message",
        }


# ── Auth handling ────────────────────────────────────────────────────


class TestAuth:
    @pytest.mark.asyncio
    async def test_missing_key_errors(self, toolset: AgentMail) -> None:
        result = await toolset.list_inboxes()
        assert "No API key" in result

    @pytest.mark.asyncio
    async def test_env_key_used(
        self, toolset: AgentMail, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTMAIL_API_KEY", "am_env")
        client = _attach_client(
            toolset, _mock_response(200, {"count": 0, "inboxes": []})
        )
        await toolset.list_inboxes()
        _, kwargs = client.request.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer am_env"

    @pytest.mark.asyncio
    async def test_explicit_key_overrides_env(
        self, toolset: AgentMail, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTMAIL_API_KEY", "am_env")
        client = _attach_client(
            toolset, _mock_response(200, {"count": 0, "inboxes": []})
        )
        await toolset.list_inboxes(api_key="am_explicit")
        _, kwargs = client.request.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer am_explicit"


# ── Requests ─────────────────────────────────────────────────────────


class TestRequests:
    @pytest.mark.asyncio
    async def test_list_inboxes(self, toolset: AgentMail) -> None:
        payload = {"count": 1, "inboxes": [{"inbox_id": "a@agentmail.to"}]}
        client = _attach_client(toolset, _mock_response(200, payload))
        result = await toolset.list_inboxes(limit=5, api_key="k")
        args, kwargs = client.request.call_args
        assert args == ("GET", "/inboxes")
        assert kwargs["params"] == {"limit": 5}
        assert "a@agentmail.to" in result

    @pytest.mark.asyncio
    async def test_list_messages_label_filter(self, toolset: AgentMail) -> None:
        client = _attach_client(
            toolset, _mock_response(200, {"count": 0, "messages": []})
        )
        await toolset.list_messages(
            "box@agentmail.to", limit=10, labels="unread, received", api_key="k"
        )
        args, kwargs = client.request.call_args
        assert args == ("GET", "/inboxes/box@agentmail.to/messages")
        assert kwargs["params"] == {"limit": 10, "labels": ["unread", "received"]}

    @pytest.mark.asyncio
    async def test_get_message(self, toolset: AgentMail) -> None:
        client = _attach_client(toolset, _mock_response(200, {"message_id": "m1"}))
        await toolset.get_message("box@agentmail.to", "m1", api_key="k")
        args, _ = client.request.call_args
        assert args == ("GET", "/inboxes/box@agentmail.to/messages/m1")

    @pytest.mark.asyncio
    async def test_send_message_body(self, toolset: AgentMail) -> None:
        client = _attach_client(toolset, _mock_response(200, {"message_id": "m2"}))
        await toolset.send_message(
            "box@agentmail.to",
            to="a@example.com, b@example.com",
            subject="Hi",
            text="Body",
            cc="c@example.com",
            api_key="k",
        )
        args, kwargs = client.request.call_args
        assert args == ("POST", "/inboxes/box@agentmail.to/messages/send")
        assert kwargs["json"] == {
            "to": ["a@example.com", "b@example.com"],
            "subject": "Hi",
            "text": "Body",
            "cc": ["c@example.com"],
        }

    @pytest.mark.asyncio
    async def test_reply_message_body(self, toolset: AgentMail) -> None:
        client = _attach_client(toolset, _mock_response(200, {"message_id": "m3"}))
        await toolset.reply_message(
            "box@agentmail.to", "m1", text="Thanks", api_key="k"
        )
        args, kwargs = client.request.call_args
        assert args == ("POST", "/inboxes/box@agentmail.to/messages/m1/reply")
        assert kwargs["json"] == {"text": "Thanks"}

    @pytest.mark.asyncio
    async def test_create_inbox_omits_blank_fields(self, toolset: AgentMail) -> None:
        client = _attach_client(toolset, _mock_response(200, {"inbox_id": "x"}))
        await toolset.create_inbox(username="agent", api_key="k")
        args, kwargs = client.request.call_args
        assert args == ("POST", "/inboxes")
        assert kwargs["json"] == {"username": "agent"}


# ── Errors ───────────────────────────────────────────────────────────


class TestErrors:
    @pytest.mark.asyncio
    async def test_http_error_surfaced(self, toolset: AgentMail) -> None:
        _attach_client(
            toolset, _mock_response(404, {"name": "not_found", "message": "nope"})
        )
        result = await toolset.get_message("box", "missing", api_key="k")
        assert "HTTP 404" in result
        assert "not_found" in result

    @pytest.mark.asyncio
    async def test_request_exception_surfaced(self, toolset: AgentMail) -> None:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=RuntimeError("boom"))
        client.is_closed = False
        toolset._http = client
        result = await toolset.list_inboxes(api_key="k")
        assert "Request failed" in result
        assert "boom" in result
