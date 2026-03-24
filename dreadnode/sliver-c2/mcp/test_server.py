#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "sliver-py>=0.0.6",
#   "protobuf>=4.0",
# ]
# ///
"""Tests for sliver MCP server — no Sliver instance required."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import server


class TestConnectionState:
    def setup_method(self):
        server._client = None
        server._interact = None
        server._interact_id = None
        server._interact_type = None

    def test_discover_config_missing_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path / "nonexistent"))
        assert server._discover_config() is None

    def test_discover_config_finds_newest(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path))
        (tmp_path / "old.cfg").write_text("old")
        (tmp_path / "new.cfg").write_text("new")
        result = server._discover_config()
        assert result is not None
        assert "new.cfg" in result

    @pytest.mark.asyncio
    async def test_get_client_errors_without_config(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SLIVER_CONFIG_FILE", raising=False)
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path / "empty"))
        server._client = None
        with pytest.raises(RuntimeError, match="No Sliver config"):
            await server._get_client()

    @pytest.mark.asyncio
    async def test_interact_errors_without_connection(self):
        server._interact = None
        with pytest.raises(RuntimeError, match="No active implant"):
            await server._get_interact()


class TestImplantStateGating:
    """Implant tools must fail cleanly when no interact() has been called."""

    def setup_method(self):
        server._interact = None

    @pytest.mark.asyncio
    async def test_ls_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.ls()

    @pytest.mark.asyncio
    async def test_execute_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.execute(exe="/bin/ls")

    @pytest.mark.asyncio
    async def test_ps_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.ps()


class TestListenerValidation:
    @pytest.mark.asyncio
    async def test_unknown_listener_type(self):
        server._client = MagicMock()  # fake connected state
        result = await server.start_listener(listener_type="invalid")
        assert "unknown listener type" in result.lower()

    @pytest.mark.asyncio
    async def test_dns_requires_domains(self):
        server._client = MagicMock()
        result = await server.start_listener(listener_type="dns")
        assert "domains required" in result.lower()


class TestTruncation:
    def test_short_text_unchanged(self):
        assert server._truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (server.MAX_OUTPUT_CHARS + 100)
        result = server._truncate(text)
        assert "truncated" in result.lower()


class TestToolRegistration:
    def test_expected_tools_registered(self):
        import asyncio
        tools = asyncio.run(server.mcp.list_tools())
        tool_names = {t.name for t in tools}
        expected = {"connect", "interact", "get_sessions", "get_beacons",
                    "get_jobs", "start_listener", "execute", "ls", "cd",
                    "pwd", "upload", "download", "ps", "screenshot"}
        assert expected.issubset(tool_names), f"Missing: {expected - tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
