"""Tests for the Flareprox IP rotation tool."""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest


def _install_dreadnode_tools_stub() -> None:
    existing = sys.modules.get("dreadnode.agents.tools")
    if existing is not None and hasattr(existing, "FunctionCall"):
        return

    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    class _Tool:
        def __init__(self, name: str, description: str, catch: bool) -> None:
            self.name = name
            self.description = description
            self.catch = catch
            self.parameters_schema = {"properties": {}}

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
        def __init__(self, **kwargs) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)
            if hasattr(self, "model_post_init"):
                self.model_post_init(None)

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

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "flareprox.py"
SPEC = importlib.util.spec_from_file_location("flareprox", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

Flareprox = MODULE.Flareprox


@pytest.fixture
def tmp_state(tmp_path: Path) -> Path:
    return tmp_path / "flareprox.json"


@pytest.fixture
def toolset(tmp_state: Path) -> Flareprox:
    os.environ["CF_API_TOKEN"] = "test-token"
    os.environ["CF_ACCOUNT_ID"] = "test-account"
    try:
        return Flareprox(state_file=str(tmp_state))
    finally:
        os.environ.pop("CF_API_TOKEN", None)
        os.environ.pop("CF_ACCOUNT_ID", None)


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: Flareprox) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "flareprox_status",
            "flareprox_create",
            "flareprox_list",
            "flareprox_proxy_url",
            "flareprox_request",
            "flareprox_cleanup",
        }


class TestStatus:
    @pytest.mark.asyncio
    async def test_status_unconfigured(self, tmp_state: Path) -> None:
        tool = Flareprox(state_file=str(tmp_state))
        result = await tool.flareprox_status()
        assert "not configured" in result

    @pytest.mark.asyncio
    async def test_status_configured(self, toolset: Flareprox) -> None:
        async def fake_get(*args, **kwargs) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": {"subdomain": "testsub"},
                },
            )

        with patch("httpx.AsyncClient.get", side_effect=fake_get):
            result = await toolset.flareprox_status()
        assert "configured: yes" in result
        assert "test-account" in result
        assert "testsub" in result


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_workers(self, toolset: Flareprox) -> None:
        responses = []

        async def fake_put(url: str, **kwargs) -> httpx.Response:
            responses.append(url)
            return httpx.Response(200, json={"success": True, "result": {"id": "script-id"}})

        with patch("httpx.AsyncClient.get", return_value=httpx.Response(
            200, json={"success": True, "result": {"subdomain": "testsub"}}
        )):
            with patch("httpx.AsyncClient.put", side_effect=fake_put):
                result = await toolset.flareprox_create(count=2)

        assert "Created Flareprox workers" in result
        assert result.count("https://") == 2
        assert len(toolset._state["workers"]) == 2

    @pytest.mark.asyncio
    async def test_create_without_credentials(self, tmp_state: Path) -> None:
        tool = Flareprox(state_file=str(tmp_state))
        result = await tool.flareprox_create(count=1)
        assert "CF_API_TOKEN and CF_ACCOUNT_ID must be configured" in result


class TestList:
    @pytest.mark.asyncio
    async def test_list_empty(self, toolset: Flareprox) -> None:
        result = await toolset.flareprox_list()
        assert "No active Flareprox workers" in result

    @pytest.mark.asyncio
    async def test_list_workers(self, toolset: Flareprox) -> None:
        toolset._state["workers"] = [
            {"name": "flareprox-aaa", "url": "https://flareprox-aaa.testsub.workers.dev"},
        ]
        result = await toolset.flareprox_list()
        assert "flareprox-aaa" in result


class TestProxyUrl:
    @pytest.mark.asyncio
    async def test_proxy_url_empty(self, toolset: Flareprox) -> None:
        result = await toolset.flareprox_proxy_url()
        assert "No active workers" in result

    @pytest.mark.asyncio
    async def test_proxy_url_rotates(self, toolset: Flareprox) -> None:
        toolset._state["workers"] = [
            {"name": "a", "url": "https://a.testsub.workers.dev"},
            {"name": "b", "url": "https://b.testsub.workers.dev"},
        ]
        urls = [await toolset.flareprox_proxy_url() for _ in range(4)]
        assert urls[0] == urls[2]
        assert urls[1] == urls[3]
        assert urls[0] != urls[1]


class TestRequest:
    @pytest.mark.asyncio
    async def test_request_no_workers(self, toolset: Flareprox) -> None:
        result = await toolset.flareprox_request("https://example.com/")
        assert "No active Flareprox workers" in result

    @pytest.mark.asyncio
    async def test_request_success(self, toolset: Flareprox) -> None:
        toolset._state["workers"] = [
            {"name": "a", "url": "https://a.testsub.workers.dev"},
        ]

        def fake_request(method: str, url: str, **kwargs) -> httpx.Response:
            assert method == "GET"
            assert url == "https://a.testsub.workers.dev"
            assert kwargs["headers"].get("x-target-url") == "https://example.com/"
            return httpx.Response(200, text="hello")

        with patch("httpx.AsyncClient.request", side_effect=fake_request):
            result = await toolset.flareprox_request("https://example.com/")
        assert "HTTP 200" in result
        assert "hello" in result

    @pytest.mark.asyncio
    async def test_request_filters_headers(self, toolset: Flareprox) -> None:
        toolset._state["workers"] = [
            {"name": "a", "url": "https://a.testsub.workers.dev"},
        ]

        captured: dict = {}

        def fake_request(method: str, url: str, **kwargs) -> httpx.Response:
            captured.update(kwargs)
            return httpx.Response(200, text="ok")

        with patch("httpx.AsyncClient.request", side_effect=fake_request):
            await toolset.flareprox_request(
                "https://example.com/",
                headers={
                    "Authorization": "Bearer token",
                    "X-Custom": "dropped",
                    "Cookie": "session=abc",
                },
            )

        headers = {k.lower(): v for k, v in captured["headers"].items()}
        assert headers["authorization"] == "Bearer token"
        assert headers["cookie"] == "session=abc"
        assert "x-custom" not in headers
        assert "x-target-url" in headers


class TestCleanup:
    @pytest.mark.asyncio
    async def test_cleanup(self, toolset: Flareprox) -> None:
        toolset._state["workers"] = [
            {"name": "flareprox-aaa", "url": "https://flareprox-aaa.testsub.workers.dev"},
        ]

        deleted: list[str] = []

        async def fake_delete(url: str, **kwargs) -> httpx.Response:
            deleted.append(url)
            return httpx.Response(200, json={"success": True})

        with patch("httpx.AsyncClient.delete", side_effect=fake_delete):
            result = await toolset.flareprox_cleanup()

        assert "Removed 1 Flareprox worker" in result
        assert "/workers/scripts/flareprox-aaa" in deleted[0]
        assert toolset._state["workers"] == []
