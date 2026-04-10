#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
# ]
# ///
"""Tests for mythic-readonly MCP server — no Mythic instance required."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import server


class TestToolRegistration:
    def test_expected_tools_registered(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        tool_names = set(tools) if isinstance(tools, dict) else {t.name for t in tools}
        expected = {
            "get_status",
            "list_callbacks",
            "get_callback",
            "list_tasks",
            "get_task_output",
            "list_credentials",
            "list_files",
            "get_file_contents",
            "list_artifacts",
            "list_keylogs",
            "list_screenshots",
            "list_processes",
            "list_file_browser",
            "list_tokens",
            "search",
        }
        assert expected == tool_names, (
            f"Unexpected: {tool_names - expected}, Missing: {expected - tool_names}"
        )

    def test_tool_count(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        assert len(tools) == 15


class TestConnectionState:
    def setup_method(self):
        server._client = None
        server._config = {}

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("MYTHIC_SERVER_IP", "10.0.0.5")
        monkeypatch.setenv("MYTHIC_SERVER_PORT", "7443")
        monkeypatch.setenv("MYTHIC_USERNAME", "admin")
        monkeypatch.setenv("MYTHIC_PASSWORD", "secret")
        cfg = server._default_config()
        assert cfg["server_ip"] == "10.0.0.5"
        assert cfg["server_port"] == 7443
        assert cfg["username"] == "admin"
        assert cfg["password"] == "secret"

    def test_default_config_defaults(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_SERVER_IP", raising=False)
        monkeypatch.delenv("MYTHIC_SERVER_PORT", raising=False)
        monkeypatch.delenv("MYTHIC_USERNAME", raising=False)
        cfg = server._default_config()
        assert cfg["server_ip"] == "127.0.0.1"
        assert cfg["server_port"] == 7443
        assert cfg["username"] == "mythic_admin"

    @pytest.mark.asyncio
    async def test_ensure_connected_errors_without_credentials(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        monkeypatch.delenv("MYTHIC_API_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="MYTHIC_PASSWORD"):
            await server._ensure_connected()


class TestHelpers:
    def test_decode_b64_plain_text(self):
        # Non-base64 text returns as-is
        assert server._decode_b64("hello world") == "hello world"

    def test_decode_b64_empty(self):
        assert server._decode_b64("") == ""

    def test_decode_b64_valid(self):
        import base64
        encoded = base64.b64encode(b"secret output").decode()
        assert server._decode_b64(encoded) == "secret output"

    def test_first_ip_empty(self):
        assert server._first_ip("") == ""

    def test_first_ip_plain(self):
        assert server._first_ip("192.168.1.1") == "192.168.1.1"

    def test_first_ip_json_array(self):
        assert server._first_ip('["10.0.0.1", "10.0.0.2"]') == "10.0.0.1"

    def test_first_ip_empty_json_array(self):
        assert server._first_ip("[]") == "[]"


class TestSearchTypes:
    def test_all_search_types_mapped(self):
        expected = {"tasks", "credentials", "files", "artifacts", "keylogs"}
        assert set(server._SEARCH_GQL_KEYS) == expected

    def test_gql_keys_are_nonempty(self):
        for k, v in server._SEARCH_GQL_KEYS.items():
            assert v, f"empty gql key for {k}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
