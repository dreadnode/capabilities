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
        assert expected == tool_names, f"Unexpected: {tool_names - expected}, Missing: {expected - tool_names}"

    def test_tool_count(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        assert len(tools) == 15


class TestConnectionState:
    def setup_method(self):
        server._client = None
        server._config = None

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


class TestCallbackIpNormalization:
    """The CallbackSummary model should normalize Mythic's JSON-array ip field."""

    def test_plain_ip_passthrough(self):
        cb = server.CallbackSummary.model_validate({"ip": "192.168.1.1"})
        assert cb.ip == "192.168.1.1"

    def test_json_array_extracts_first(self):
        cb = server.CallbackSummary.model_validate({"ip": '["10.0.0.1", "10.0.0.2"]'})
        assert cb.ip == "10.0.0.1"

    def test_empty_ip(self):
        cb = server.CallbackSummary.model_validate({"ip": ""})
        assert cb.ip == ""

    def test_null_ip_becomes_empty(self):
        cb = server.CallbackSummary.model_validate({"ip": None})
        assert cb.ip == ""


class TestNullCoercion:
    """_MythicBase should coerce None to type-appropriate zero values for
    primitive str/int/bool fields so Hasura's nulls don't fail validation."""

    def test_null_string_becomes_empty(self):
        entry = server.Screenshot.model_validate({"host": None, "timestamp": None})
        assert entry.host == ""
        assert entry.timestamp == ""

    def test_null_int_becomes_zero(self):
        entry = server.Screenshot.model_validate({"id": None})
        assert entry.id == 0

    def test_null_bool_becomes_false(self):
        entry = server.MythicTreeEntry.model_validate({"success": None, "deleted": None})
        assert entry.success is False
        assert entry.deleted is False

    def test_non_null_values_passthrough(self):
        entry = server.Screenshot.model_validate({"id": 5, "host": "SRV", "timestamp": "2026-04-10"})
        assert entry.id == 5
        assert entry.host == "SRV"
        assert entry.timestamp == "2026-04-10"


class TestMythicTreeMetadata:
    """MythicTreeEntry.metadata should accept JSON strings, dicts, or null."""

    def test_metadata_from_json_string(self):
        entry = server.MythicTreeEntry.model_validate({"metadata": '{"pid": 1234}'})
        assert entry.metadata == {"pid": 1234}

    def test_metadata_from_dict(self):
        entry = server.MythicTreeEntry.model_validate({"metadata": {"size": 100}})
        assert entry.metadata == {"size": 100}

    def test_metadata_from_null(self):
        entry = server.MythicTreeEntry.model_validate({"metadata": None})
        assert entry.metadata == {}

    def test_metadata_from_invalid_json(self):
        entry = server.MythicTreeEntry.model_validate({"metadata": "not json"})
        assert entry.metadata == {}


class TestSearchTypes:
    def test_all_search_types_mapped(self):
        expected = {"tasks", "credentials", "files", "artifacts", "keylogs"}
        assert set(server._SEARCH_GQL_KEYS) == expected

    def test_gql_keys_are_nonempty(self):
        for k, v in server._SEARCH_GQL_KEYS.items():
            assert v, f"empty gql key for {k}"

    def test_valid_search_types_none_returns_all(self):
        assert server._valid_search_types(None) == set(server._SEARCH_GQL_KEYS)

    def test_valid_search_types_filters_unknown(self):
        assert server._valid_search_types("tasks,bogus,credentials") == {"tasks", "credentials"}

    def test_valid_search_types_strips_whitespace(self):
        assert server._valid_search_types("tasks, credentials ") == {"tasks", "credentials"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
