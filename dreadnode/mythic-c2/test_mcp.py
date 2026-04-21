#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "mythic>=0.2",
# ]
# ///
"""Tests for the Mythic MCP tool layer — no Mythic instance required.

Covers:
  * ``lib/mythic_api.py`` — config, truncation, null-omission, connection refusal.
  * ``mcp_server.py`` — observation tool registration set.
  * ``lib/apollo.py`` — registration is gated by CAPABILITY_FLAG__MYTHIC_C2__APOLLO.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from lib import mythic_api


def _fresh_mcp(monkeypatch, *, tasking: bool = False, apollo: bool = False):
    """Reimport mcp_server.py with fresh flag state so gates re-evaluate."""
    monkeypatch.setenv("CAPABILITY_FLAG__MYTHIC_C2__TASKING", "1" if tasking else "0")
    monkeypatch.setenv("CAPABILITY_FLAG__MYTHIC_C2__APOLLO", "1" if apollo else "0")
    for name in ("mcp_server", "lib.observation", "lib.tasking", "lib.apollo"):
        sys.modules.pop(name, None)
    mythic_api.reset_connection()
    return importlib.import_module("mcp_server")


# ── mythic_api ───────────────────────────────────────────────────────


class TestConfig:
    def test_env_populates_config(self, monkeypatch):
        monkeypatch.setenv("MYTHIC_SERVER_IP", "10.0.0.5")
        monkeypatch.setenv("MYTHIC_PASSWORD", "secret")
        cfg = mythic_api.default_config()
        assert cfg["server_ip"] == "10.0.0.5"
        assert cfg["password"] == "secret"
        assert cfg["username"] == "mythic_admin"

    def test_defaults_when_env_missing(self, monkeypatch):
        for name in (
            "MYTHIC_SERVER_IP",
            "MYTHIC_SERVER_PORT",
            "MYTHIC_USERNAME",
            "MYTHIC_PASSWORD",
            "MYTHIC_API_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)
        cfg = mythic_api.default_config()
        assert cfg["server_ip"] == "127.0.0.1"
        assert cfg["server_port"] == 7443
        assert cfg["password"] == ""
        assert cfg["api_token"] == ""


class TestEnsureConnected:
    def setup_method(self):
        mythic_api.reset_connection()

    @pytest.mark.asyncio
    async def test_raises_when_no_credentials(self, monkeypatch):
        for name in ("MYTHIC_PASSWORD", "MYTHIC_API_TOKEN"):
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(RuntimeError, match="MYTHIC_PASSWORD or MYTHIC_API_TOKEN"):
            await mythic_api.ensure_connected()


class TestTruncate:
    def test_short_text_unchanged(self):
        assert mythic_api.truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (mythic_api.MAX_OUTPUT_CHARS + 100)
        result = mythic_api.truncate(text)
        assert len(result) < len(text)
        assert "truncated" in result.lower()

    def test_head_and_tail_preserved(self):
        head = "HEAD" * 100
        tail = "TAIL" * 100
        middle = "M" * (mythic_api.MAX_OUTPUT_CHARS + 1000)
        result = mythic_api.truncate(head + middle + tail)
        assert result.startswith("HEAD")
        assert result.endswith("TAIL")


class TestClean:
    def test_drops_none_and_empties(self):
        assert mythic_api.clean({"a": None, "b": "", "c": [], "d": {}}) == {}

    def test_keeps_zero_and_false(self):
        assert mythic_api.clean({"pid": 0, "active": False}) == {
            "pid": 0,
            "active": False,
        }

    def test_recurses_through_nested(self):
        row = {
            "display_id": 21,
            "comment": "",
            "task": {"id": None, "display_id": 99},
            "tags": ["", "real"],
        }
        assert mythic_api.clean(row) == {
            "display_id": 21,
            "task": {"display_id": 99},
            "tags": ["real"],
        }


class TestFirstIP:
    def test_unwraps_list_string(self):
        assert mythic_api.first_ip('["10.0.0.1", "10.0.0.2"]') == "10.0.0.1"

    def test_passthrough_plain_string(self):
        assert mythic_api.first_ip("10.0.0.1") == "10.0.0.1"

    def test_passthrough_none(self):
        assert mythic_api.first_ip(None) is None


# ── mcp — tool registration ─────────────────────────────────────────


_EXPECTED_OBSERVATION = {
    "get_status",
    "list_callbacks",
    "get_callback",
    "list_tasks",
    "get_task",
    "get_task_output",
    "get_recent_callback_activity",
    "get_operation_summary",
    "list_credentials",
    "list_files",
    "list_payloads",
    "find_bloodhound_data",
    "get_file_contents",
    "list_artifacts",
    "list_keylogs",
    "list_screenshots",
    "list_processes",
    "list_file_browser",
    "list_tokens",
    "search",
}

_EXPECTED_TASKING = {
    "issue_task",
    "list_callback_commands",
}

_EXPECTED_APOLLO_SAMPLE = {
    "execute",
    "stage_file",
    "check_staged_file",
    "fetch_staged_file",
    "download_and_fetch",
    "cat",
    "cd",
    "ls",
    "ps",
    "whoami",
    "mimikatz",
    "powershell",
    "powershell_script",
    "powerview",
    "rubeus_kerberoast",
    "sharphound_and_download",
    "shinject",
    "make_token",
    "steal_token",
    "rev2self",
}


class TestFlagGating:
    @pytest.mark.asyncio
    async def test_default_exposes_only_observation_tools(self, monkeypatch):
        module = _fresh_mcp(monkeypatch)
        tools = await module.mcp.list_tools()
        names = {t.name for t in tools}
        assert _EXPECTED_OBSERVATION.issubset(names)
        assert _EXPECTED_TASKING.isdisjoint(names)
        assert _EXPECTED_APOLLO_SAMPLE.isdisjoint(names)
        assert "publish_advisory" not in names

    @pytest.mark.asyncio
    async def test_tasking_flag_registers_generic_tasking(self, monkeypatch):
        module = _fresh_mcp(monkeypatch, tasking=True)
        tools = await module.mcp.list_tools()
        names = {t.name for t in tools}
        assert _EXPECTED_OBSERVATION.issubset(names)
        assert _EXPECTED_TASKING.issubset(names)
        assert _EXPECTED_APOLLO_SAMPLE.isdisjoint(names)

    @pytest.mark.asyncio
    async def test_apollo_flag_registers_apollo_without_tasking(self, monkeypatch):
        module = _fresh_mcp(monkeypatch, apollo=True)
        tools = await module.mcp.list_tools()
        names = {t.name for t in tools}
        assert _EXPECTED_OBSERVATION.issubset(names)
        assert _EXPECTED_APOLLO_SAMPLE.issubset(names)
        assert _EXPECTED_TASKING.isdisjoint(names)

    @pytest.mark.asyncio
    async def test_both_flags_register_both_surfaces(self, monkeypatch):
        module = _fresh_mcp(monkeypatch, tasking=True, apollo=True)
        tools = await module.mcp.list_tools()
        names = {t.name for t in tools}
        assert _EXPECTED_OBSERVATION.issubset(names)
        assert _EXPECTED_TASKING.issubset(names)
        assert _EXPECTED_APOLLO_SAMPLE.issubset(names)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
