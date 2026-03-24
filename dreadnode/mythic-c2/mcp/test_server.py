#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0",
# ]
# ///
"""Tests for mythic MCP server — no Mythic instance required."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Import server module from adjacent file
sys.path.insert(0, str(Path(__file__).parent))
import server


class TestConnectionState:
    """Test the connect/disconnect state machine."""

    def setup_method(self):
        server._client = None
        server._config = {}

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("MYTHIC_SERVER_IP", "10.0.0.5")
        monkeypatch.setenv("MYTHIC_PASSWORD", "secret")
        cfg = server._default_config()
        assert cfg["server_ip"] == "10.0.0.5"
        assert cfg["password"] == "secret"
        assert cfg["username"] == "mythic_admin"

    def test_default_config_defaults(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_SERVER_IP", raising=False)
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        cfg = server._default_config()
        assert cfg["server_ip"] == "127.0.0.1"
        assert cfg["password"] == ""

    @pytest.mark.asyncio
    async def test_get_client_errors_without_password(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        server._config = {}
        with pytest.raises(RuntimeError, match="Not connected"):
            await server._get_client()

    @pytest.mark.asyncio
    async def test_connect_sets_config(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        mock_login = AsyncMock(return_value="fake_client")
        with patch.object(server.mythic_sdk, "login", mock_login):
            result = await server.connect(
                server_ip="192.168.1.1", password="test123"
            )
        assert "192.168.1.1" in result
        assert server._client == "fake_client"

    @pytest.mark.asyncio
    async def test_connect_resets_previous_client(self, monkeypatch):
        server._client = "old_client"
        mock_login = AsyncMock(return_value="new_client")
        with patch.object(server.mythic_sdk, "login", mock_login):
            await server.connect(password="pw")
        assert server._client == "new_client"


class TestTruncation:
    def test_short_text_unchanged(self):
        assert server._truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (server.MAX_OUTPUT_CHARS + 100)
        result = server._truncate(text)
        assert len(result) < len(text)
        assert "truncated" in result.lower()

    def test_truncation_preserves_head_and_tail(self):
        head = "HEAD" * 100
        tail = "TAIL" * 100
        middle = "M" * (server.MAX_OUTPUT_CHARS + 1000)
        text = head + middle + tail
        result = server._truncate(text)
        assert result.startswith("HEAD")
        assert result.endswith("TAIL")


class TestToolRegistration:
    def test_expected_tools_registered(self):
        import asyncio
        tools = asyncio.run(server.mcp.list_tools())
        tool_names = {t.name for t in tools}
        # Server tools
        server_tools = {"connect", "get_callbacks", "upload_file", "check_file", "download_file"}
        assert server_tools.issubset(tool_names), f"Missing server tools: {server_tools - tool_names}"
        # Core Apollo implant tools (spot-check)
        apollo_tools = {
            "cat", "cd", "cp", "ls", "pwd", "ps", "download", "download_to_local_file",
            "upload", "whoami", "mimikatz", "powershell", "powerview", "pth",
            "rubeus_kerberoast", "rubeus_asreproast", "sharphound_and_download",
            "shinject", "wmiexecute", "make_token", "steal_token", "rev2self",
        }
        assert apollo_tools.issubset(tool_names), f"Missing Apollo tools: {apollo_tools - tool_names}"
        # Generic execute should NOT be a tool (it's now _execute private helper)
        assert "execute" not in tool_names, "execute should not be exposed as MCP tool"

    def test_tool_count(self):
        import asyncio
        tools = asyncio.run(server.mcp.list_tools())
        assert len(tools) >= 47, f"Expected at least 47 tools, got {len(tools)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
