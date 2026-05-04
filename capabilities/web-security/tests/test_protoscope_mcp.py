"""Tests for the Protoscope MCP wrapper."""

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

    setattr(fastmcp, "FastMCP", _FastMCP)
    sys.modules["fastmcp"] = fastmcp


_install_fastmcp_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "protoscope.py"
SPEC = importlib.util.spec_from_file_location("protoscope_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_expected_tools_registered() -> None:
    expected = {
        "protoscope_status",
        "protoscope_run",
        "protoscope_help",
        "protoscope_inspect_file",
        "protoscope_inspect_hex",
        "protoscope_assemble_text",
        "protoscope_assemble_file",
    }
    assert set(MODULE.mcp._tools) == expected


def test_resolve_command_prefers_configured_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROTOSCOPE_COMMAND", "/opt/tools/protoscope")

    with patch.object(MODULE.shutil, "which", return_value="/opt/tools/protoscope"):
        assert MODULE._resolve_command() == ["/opt/tools/protoscope"]


def test_resolve_command_prefers_protoscope_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROTOSCOPE_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/local/bin/protoscope" if name == "protoscope" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["protoscope"]


def test_resolve_command_falls_back_to_go_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROTOSCOPE_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/local/go/bin/go" if name == "go" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["go", "run", MODULE.MODULE_PATH]


def test_resolve_command_returns_none_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROTOSCOPE_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        assert MODULE._resolve_command() is None


def test_clean_hex_accepts_common_formats() -> None:
    assert MODULE._clean_hex("08 96 01") == b"\x08\x96\x01"
    assert MODULE._clean_hex("0x08:0x96:0x01") == b"\x08\x96\x01"


def test_clean_hex_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="odd number"):
        MODULE._clean_hex("abc")
    with pytest.raises(ValueError, match="any hex"):
        MODULE._clean_hex("not xyz")


@pytest.mark.asyncio
async def test_run_reports_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROTOSCOPE_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        result = await MODULE.protoscope_help()

    assert "protoscope is unavailable" in result
    assert "PROTOSCOPE_COMMAND" in result


@pytest.mark.asyncio
async def test_help_passes_argv_without_shell() -> None:
    proc = AsyncMock()
    proc.returncode = 0
    proc.communicate.return_value = (b"usage", b"")

    with (
        patch.object(MODULE, "_resolve_command", return_value=["protoscope"]),
        patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            return_value=proc,
        ) as create_proc,
    ):
        result = await MODULE.protoscope_help(timeout=5)

    create_proc.assert_called_once()
    assert create_proc.call_args.args[:2] == ("protoscope", "--help")
    assert result == "usage"


@pytest.mark.asyncio
async def test_assemble_text_returns_hex() -> None:
    with patch.object(MODULE, "_run_protoscope", return_value=(0, b"\x08\x96\x01", "")):
        result = await MODULE.protoscope_assemble_text("1: 150\n")

    assert result == "089601"


@pytest.mark.asyncio
async def test_run_empty_args_errors() -> None:
    result = await MODULE.protoscope_run([])
    assert result == "Error: args must include Protoscope CLI arguments."
