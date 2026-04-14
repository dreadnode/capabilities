"""Tests for BBScope — bug bounty scope intelligence toolset."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

pytestmark = pytest.mark.asyncio

# Add tools directory to path for import
_REPO_ROOT = Path(__file__).resolve()
while _REPO_ROOT != _REPO_ROOT.parent:
    if (_REPO_ROOT / "dreadnode" / "web-security" / "tools").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "dreadnode" / "web-security" / "tools"))

from bbscope import BBScope


@pytest.fixture
def toolset() -> BBScope:
    return BBScope()


def _mock_response(status_code: int = 200, json_data: object = None) -> httpx.Response:
    resp = httpx.Response(
        status_code=status_code,
        json=json_data,
        request=httpx.Request("GET", "https://bbscope.com/api/v1/test"),
    )
    return resp


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: BBScope) -> None:
        tools = toolset.get_tools()
        names = {t.name for t in tools}
        assert "bbscope_find" in names
        assert "bbscope_program" in names
        assert "bbscope_targets" in names
        assert "bbscope_updates" in names

    def test_all_tools_have_descriptions(self, toolset: BBScope) -> None:
        for tool in toolset.get_tools():
            assert tool.description, f"{tool.name} missing description"

    def test_all_tools_have_catch(self, toolset: BBScope) -> None:
        for tool in toolset.get_tools():
            assert tool.catch is True, f"{tool.name} missing catch=True"


class TestFind:
    async def test_find_with_results(self, toolset: BBScope) -> None:
        mock_data = {
            "query": "example.com",
            "programs": [
                {"platform": "h1", "handle": "example", "url": "https://hackerone.com/example"},
                {"platform": "bc", "handle": "example-bc", "url": "https://bugcrowd.com/example-bc"},
            ],
            "total_count": 2,
        }
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.find(query="example.com")
            assert "2 program(s)" in result
            assert "H1" in result
            assert "example" in result
            assert "BC" in result

    async def test_find_no_results(self, toolset: BBScope) -> None:
        mock_data = {"query": "nonexistent.invalid", "programs": [], "total_count": 0}
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.find(query="nonexistent.invalid")
            assert "No bug bounty programs found" in result

    async def test_find_api_error(self, toolset: BBScope) -> None:
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(status_code=500)
            mock_client.return_value = client

            result = await toolset.find(query="example.com")
            assert "Error" in result
            assert "500" in result


class TestProgram:
    async def test_program_details(self, toolset: BBScope) -> None:
        mock_data = {
            "platform": "h1",
            "handle": "example",
            "url": "https://hackerone.com/example",
            "is_bbp": True,
            "in_scope_count": 5,
            "out_of_scope_count": 2,
            "targets": ["*.example.com", "api.example.com", "app.example.com"],
            "categories": ["wildcard", "url"],
        }
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.program(platform="h1", handle="example")
            assert "Bug Bounty" in result
            assert "*.example.com" in result
            assert "In-scope targets: 5" in result

    async def test_program_vdp(self, toolset: BBScope) -> None:
        mock_data = {
            "platform": "bc",
            "handle": "test",
            "url": "https://bugcrowd.com/test",
            "is_bbp": False,
            "in_scope_count": 1,
            "out_of_scope_count": 0,
            "targets": ["test.com"],
            "categories": ["url"],
        }
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.program(platform="bc", handle="test")
            assert "VDP" in result

    async def test_program_invalid_platform(self, toolset: BBScope) -> None:
        result = await toolset.program(platform="invalid", handle="test")
        assert "Error" in result
        assert "Invalid platform" in result

    async def test_program_not_found(self, toolset: BBScope) -> None:
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(status_code=404)
            mock_client.return_value = client

            result = await toolset.program(platform="h1", handle="nonexistent")
            assert "not found" in result


class TestTargets:
    async def test_targets_wildcards(self, toolset: BBScope) -> None:
        mock_data = ["*.example.com", "*.test.org"]
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.targets(target_type="wildcards")
            assert "*.example.com" in result
            assert "2 wildcards" in result

    async def test_targets_invalid_type(self, toolset: BBScope) -> None:
        result = await toolset.targets(target_type="invalid")
        assert "Error" in result
        assert "Invalid target_type" in result

    async def test_targets_invalid_platform(self, toolset: BBScope) -> None:
        result = await toolset.targets(target_type="domains", platform="invalid")
        assert "Error" in result
        assert "Invalid platform" in result

    async def test_targets_with_limit(self, toolset: BBScope) -> None:
        mock_data = [f"target{i}.com" for i in range(200)]
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.targets(target_type="domains", limit=10)
            assert "200 domains" in result
            assert "190 more" in result


class TestUpdates:
    async def test_updates_today(self, toolset: BBScope) -> None:
        mock_data = {
            "updates": [
                {
                    "change_type": "added",
                    "target": "new.example.com",
                    "platform": "h1",
                    "handle": "example",
                    "scope_type": "in",
                    "timestamp": "2026-04-14T10:00:00Z",
                },
            ],
            "total_count": 1,
            "page": 1,
            "per_page": 50,
            "total_pages": 1,
        }
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.updates(since="today")
            assert "1 scope update" in result
            assert "new.example.com" in result
            assert "added" in result

    async def test_updates_no_results(self, toolset: BBScope) -> None:
        mock_data = {"updates": [], "total_count": 0}
        with patch.object(toolset, "_get_client") as mock_client:
            client = AsyncMock()
            client.get.return_value = _mock_response(json_data=mock_data)
            mock_client.return_value = client

            result = await toolset.updates(since="today")
            assert "No scope updates found" in result
