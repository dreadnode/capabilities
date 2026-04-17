"""Tests for the agent-browser MCP wrapper."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


def _install_fastmcp_stub() -> None:
    fastmcp = types.ModuleType("fastmcp")

    class _FastMCP:
        def __init__(self, name: str) -> None:
            self.name = name
            self._tools: dict[str, object] = {}

        def tool(self, fn):
            self._tools[fn.__name__] = fn
            return fn

        def run(self, **kwargs) -> None:
            pass

    fastmcp.FastMCP = _FastMCP
    sys.modules["fastmcp"] = fastmcp


_install_fastmcp_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "agent_browser.py"
SPEC = importlib.util.spec_from_file_location("agent_browser_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_expected_tools_registered() -> None:
    expected = {
        "agent_browser_status",
        "agent_browser_run",
        "agent_browser_open",
        "agent_browser_snapshot",
        "agent_browser_click",
        "agent_browser_fill",
        "agent_browser_type",
        "agent_browser_press",
        "agent_browser_wait",
        "agent_browser_get",
        "agent_browser_screenshot",
        "agent_browser_set_viewport",
        "agent_browser_close",
    }
    assert set(MODULE.mcp._tools) == expected


def test_resolve_command_prefers_configured_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BROWSER_COMMAND", "npx --yes agent-browser")

    with patch.object(MODULE.shutil, "which", return_value="/usr/bin/npx"):
        assert MODULE._resolve_command() == ["npx", "--yes", "agent-browser"]


def test_resolve_command_prefers_agent_browser_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/local/bin/agent-browser" if name == "agent-browser" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["agent-browser"]


def test_resolve_command_falls_back_to_npx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/bin/npx" if name == "npx" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["npx", "--yes", "agent-browser"]


def test_resolve_command_returns_none_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        assert MODULE._resolve_command() is None


@pytest.mark.asyncio
async def test_run_reports_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        result = await MODULE.agent_browser_open("https://example.com")

    assert "agent-browser is unavailable" in result
    assert "AGENT_BROWSER_COMMAND" in result


@pytest.mark.asyncio
async def test_open_passes_argv_without_shell() -> None:
    proc = AsyncMock()
    proc.returncode = 0
    proc.communicate.return_value = (b"opened", b"")

    with (
        patch.object(MODULE, "_resolve_command", return_value=["agent-browser"]),
        patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            return_value=proc,
        ) as create_proc,
    ):
        result = await MODULE.agent_browser_open(
            "https://example.com",
            global_args=["--session-name", "cap"],
            timeout=5,
        )

    create_proc.assert_called_once()
    assert create_proc.call_args.args[:5] == (
        "agent-browser",
        "--session-name",
        "cap",
        "open",
        "https://example.com",
    )
    assert result == "opened"


@pytest.mark.asyncio
async def test_run_empty_args_errors() -> None:
    result = await MODULE.agent_browser_run([])
    assert result == "Error: args must include an agent-browser subcommand."
