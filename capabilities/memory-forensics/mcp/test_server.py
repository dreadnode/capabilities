#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "volatility3>=2.7",
#   "yara-python>=4.5",
# ]
# ///
"""Tests for the volatility MCP server — no memory image required.

Covers the pure helpers (command resolution, JSON rendering, plugin
routing) and verifies the tool surface the runtime exposes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import volatility as srv


class TestCommandResolution:
    def test_explicit_volatility_command(self, monkeypatch):
        monkeypatch.setenv("VOLATILITY_COMMAND", "echo")
        assert srv._resolve_command() == ["echo"]

    def test_explicit_command_unresolvable(self, monkeypatch):
        monkeypatch.setenv("VOLATILITY_COMMAND", "/no/such/binary/anywhere")
        assert srv._resolve_command() is None

    def test_falls_back_to_python_when_no_vol(self, monkeypatch):
        monkeypatch.delenv("VOLATILITY_COMMAND", raising=False)
        monkeypatch.setattr(srv.shutil, "which", lambda _name: None)
        cmd = srv._resolve_command()
        assert cmd is not None
        assert cmd[0] == sys.executable
        assert cmd[1] == "-c"
        assert "from volatility3.cli import main" in cmd[2]

    def test_missing_dependency_message_is_actionable(self):
        msg = srv._missing_dependency_message()
        assert "volatility3" in msg
        assert "VOLATILITY_COMMAND" in msg


class TestPluginRouting:
    @pytest.mark.parametrize(
        "os_kind,short,expected",
        [
            ("windows", "pslist.PsList", "windows.pslist.PsList"),
            ("linux", "pslist.PsList", "linux.pslist.PsList"),
            ("mac", "info.Info", "mac.info.Info"),
        ],
    )
    def test_plugin_for(self, os_kind, short, expected):
        assert srv._plugin_for(os_kind, short) == expected


class TestRenderPluginResult:
    def test_pretty_prints_json_payload(self):
        payload = json.dumps([{"PID": 1, "Name": "init"}])
        out = srv._render_plugin_result(0, payload.encode(), "")
        assert "init" in out
        assert "  " in out  # indented

    def test_falls_back_to_raw_text_on_invalid_json(self):
        raw = "not-json-output\nsecond line"
        out = srv._render_plugin_result(0, raw.encode(), "")
        assert "not-json-output" in out

    def test_returns_empty_array_for_blank_stdout(self):
        out = srv._render_plugin_result(0, b"", "")
        assert json.loads(out) == []

    def test_includes_stderr_on_failure(self):
        out = srv._render_plugin_result(1, b"", "boom")
        assert "Error" in out
        assert "boom" in out


class TestTruncate:
    def test_short_text_passthrough(self):
        assert srv._truncate("ok") == "ok"

    def test_long_text_truncated(self, monkeypatch):
        monkeypatch.setattr(srv, "MAX_OUTPUT_CHARS", 10)
        out = srv._truncate("a" * 20)
        assert out.startswith("a" * 10)
        assert "truncated" in out


class TestToolSurface:
    """Confirm the tools the agent and skills reference are registered."""

    EXPECTED_TOOLS = {
        "volatility_status",
        "volatility_info",
        "volatility_processes",
        "volatility_process_tree",
        "volatility_process_scan",
        "volatility_cmdlines",
        "volatility_network",
        "volatility_malfind",
        "volatility_dll_list",
        "volatility_handles",
        "volatility_registry_hives",
        "volatility_registry_key",
        "volatility_hashdump",
        "volatility_services",
        "volatility_yara_scan",
        "volatility_dump_process",
        "volatility_timeline",
        "volatility_list_plugins",
        "volatility_run_plugin",
    }

    @pytest.mark.asyncio
    async def test_all_expected_tools_registered(self):
        tools = await srv.mcp.list_tools()
        registered = {t.name for t in tools}
        missing = self.EXPECTED_TOOLS - registered
        assert not missing, f"missing tools: {missing}"


class TestStatus:
    @pytest.mark.asyncio
    async def test_status_returns_string(self):
        out = await srv.volatility_status()
        assert isinstance(out, str)

    @pytest.mark.asyncio
    async def test_status_reports_unavailable_when_no_command(self, monkeypatch):
        monkeypatch.setenv("VOLATILITY_COMMAND", "/no/such/binary")
        monkeypatch.setattr(srv.shutil, "which", lambda _name: None)

        def _no_volatility3():
            raise ImportError

        monkeypatch.setitem(sys.modules, "volatility3", None)
        out = await srv.volatility_status()
        assert "unavailable" in out.lower()


class TestRunPluginGuards:
    @pytest.mark.asyncio
    async def test_missing_image_returns_error_string(self, tmp_path):
        out = await srv._run_plugin(str(tmp_path / "absent.mem"), "windows.info.Info")
        assert "does not exist" in out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
