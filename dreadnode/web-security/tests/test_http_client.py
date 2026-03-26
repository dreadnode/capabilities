"""Tests for ThermopticTools."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TOOLS_DIR = str(Path(__file__).resolve().parent.parent / "tools")
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from thermoptic import ThermopticTools  # noqa: E402


def _make_tools(**kwargs) -> ThermopticTools:
    return ThermopticTools(**kwargs)


class TestThermopticTools:
    @pytest.mark.asyncio
    async def test_default_proxy_url(self) -> None:
        tools = _make_tools()
        assert tools.proxy_url == "http://localhost:1234"

    @pytest.mark.asyncio
    async def test_custom_proxy_url(self) -> None:
        tools = _make_tools(proxy_url="http://localhost:9999")
        assert tools.proxy_url == "http://localhost:9999"

    @pytest.mark.asyncio
    async def test_client_created_with_proxy(self) -> None:
        tools = _make_tools()
        client = tools._ensure_client()
        assert client is not None

    @pytest.mark.asyncio
    async def test_client_reused(self) -> None:
        tools = _make_tools()
        first = tools._ensure_client()
        second = tools._ensure_client()
        assert first is second

    @pytest.mark.asyncio
    async def test_reset_clears_client(self) -> None:
        tools = _make_tools()
        tools._ensure_client()
        result = await tools.thermoptic_reset()
        assert tools._client is None
        assert "reset" in result.lower()

    @pytest.mark.asyncio
    async def test_reset_when_no_session(self) -> None:
        tools = _make_tools()
        result = await tools.thermoptic_reset()
        assert "No active" in result

    @pytest.mark.asyncio
    async def test_request_unreachable_proxy_shows_error(self) -> None:
        tools = _make_tools(proxy_url="http://localhost:99999")
        result = await tools.thermoptic_request("http://example.com")
        assert "error" in result.lower()
        assert "thermoptic" in result.lower()

    @pytest.mark.asyncio
    async def test_health_unreachable_proxy(self) -> None:
        tools = _make_tools(proxy_url="http://localhost:99999")
        result = await tools.thermoptic_health()
        assert "error" in result.lower()
        assert "docker compose" in result.lower()

    @pytest.mark.asyncio
    async def test_higher_default_timeout(self) -> None:
        tools = _make_tools()
        assert tools.timeout == 60
