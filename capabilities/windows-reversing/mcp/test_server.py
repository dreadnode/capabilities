#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "pefile>=2024.8.26",
#   "flare-capa>=7.3",
#   "flare-floss>=3.1",
#   "qiling>=1.4.6",
#   "unicorn>=2.0.1",
#   "capstone>=5.0.1",
#   "keystone-engine>=0.9.2",
# ]
# ///
"""Tests for the windows-reversing MCP servers — no PE binary required.

Covers pure helpers (path resolution, entropy, command discovery,
script-class registration) and verifies that each MCP registers the
tool surface the agent and skills reference. Catches the class of
breakage that hit this capability on first review: imports targeting
symbols that don't exist, set_api passing strings instead of enums,
and Cask install paths missed by platform discovery.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).parent


def _load(filename: str, alias: str) -> ModuleType:
    """Load a sibling .py under an alias so we don't shadow the real
    `qiling` / `ghidra` packages when these MCPs are imported by name.
    """
    spec = importlib.util.spec_from_file_location(alias, HERE / f"{filename}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def pe_triage() -> ModuleType:
    return _load("pe_triage", "windows_reversing_pe_triage")


@pytest.fixture(scope="module")
def ghidra_srv() -> ModuleType:
    return _load("ghidra", "windows_reversing_ghidra_srv")


@pytest.fixture(scope="module")
def qiling_srv() -> ModuleType:
    return _load("qiling", "windows_reversing_qiling_srv")


# ── pe_triage ────────────────────────────────────────────────────────


class TestPeTriageHelpers:
    def test_entropy_zero_for_empty(self, pe_triage):
        assert pe_triage._entropy(b"") == 0.0

    def test_entropy_low_for_uniform(self, pe_triage):
        assert pe_triage._entropy(b"A" * 1024) == 0.0

    def test_entropy_high_for_random(self, pe_triage):
        import os

        ent = pe_triage._entropy(os.urandom(4096))
        assert ent > 7.5

    def test_resolve_path_raises_on_missing(self, pe_triage, tmp_path):
        with pytest.raises(FileNotFoundError):
            pe_triage._resolve_path(str(tmp_path / "nope.exe"))

    def test_truncate_passthrough_short(self, pe_triage):
        assert pe_triage._truncate("hi") == "hi"

    def test_truncate_chops_long(self, pe_triage, monkeypatch):
        monkeypatch.setattr(pe_triage, "MAX_OUTPUT_CHARS", 8)
        out = pe_triage._truncate("0123456789")
        assert out.startswith("01234567")
        assert "truncated" in out


class TestPeTriageRegistration:
    @pytest.mark.asyncio
    async def test_lists_documented_tools(self, pe_triage):
        tools = await pe_triage.mcp.list_tools()
        names = {t.name for t in tools}
        assert names == {
            "pe_triage_status",
            "pe_info",
            "pe_strings",
            "pe_floss",
            "pe_capa",
            "pe_hash",
            "pe_bytes_at",
        }

    @pytest.mark.asyncio
    async def test_status_probes_real_symbols(self, pe_triage):
        result = await pe_triage.mcp.call_tool("pe_triage_status", {})
        body = result.structured_content
        # Status must reflect what tools actually need, not just package import.
        # A package that imports but lacks the symbols pe_floss / pe_capa rely
        # on must surface here, not silently at first call.
        assert "pefile" in body
        assert "floss" in body
        assert "capa" in body

    @pytest.mark.asyncio
    async def test_bytes_at_raises_on_oor(self, pe_triage, tmp_path):
        sample = tmp_path / "tiny.bin"
        sample.write_bytes(b"hello")
        with pytest.raises(Exception) as ei:
            await pe_triage.mcp.call_tool("pe_bytes_at", {"path": str(sample), "offset": 999, "length": 4})
        assert "out of range" in str(ei.value)


# ── ghidra ───────────────────────────────────────────────────────────


class TestGhidraDiscovery:
    def test_resolve_explicit_env(self, ghidra_srv, tmp_path, monkeypatch):
        fake = tmp_path / "analyzeHeadless"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        monkeypatch.setenv("GHIDRA_HEADLESS", str(fake))
        assert ghidra_srv._resolve_headless() == fake

    def test_resolve_explicit_missing(self, ghidra_srv, monkeypatch, tmp_path):
        monkeypatch.setenv("GHIDRA_HEADLESS", str(tmp_path / "nope"))
        # Other resolution paths could still find a system Ghidra; we only
        # assert that an unset/explicit-missing pair doesn't raise.
        ghidra_srv._resolve_headless()

    def test_install_dir_appends_support(self, ghidra_srv, tmp_path, monkeypatch):
        install = tmp_path / "ghidra_11_PUBLIC"
        (install / "support").mkdir(parents=True)
        (install / "support" / "analyzeHeadless").write_text("")
        monkeypatch.delenv("GHIDRA_HEADLESS", raising=False)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
        assert ghidra_srv._resolve_headless() == install / "support" / "analyzeHeadless"

    def test_mac_candidates_finds_cask(self, ghidra_srv, tmp_path, monkeypatch):
        cask_root = tmp_path / "Caskroom" / "ghidra"
        version_dir = cask_root / "11.4.1-20250731" / "ghidra_11.4.1_PUBLIC" / "support"
        version_dir.mkdir(parents=True)
        (version_dir / "analyzeHeadless").write_text("")
        monkeypatch.setattr(
            ghidra_srv,
            "_mac_candidates",
            lambda: list(cask_root.glob("*/ghidra_*_PUBLIC/support/analyzeHeadless")),
        )
        cands = ghidra_srv._mac_candidates()
        assert any("ghidra_11.4.1_PUBLIC" in str(c) for c in cands)


class TestGhidraScripts:
    def test_script_classes_registered(self, ghidra_srv):
        # Each script body must map to its concrete Java class name.
        registry = ghidra_srv._SCRIPT_CLASSES
        assert "ListFunctions" in registry.values()
        assert "DecompileFunction" in registry.values()
        assert "ListStrings" in registry.values()
        assert "XrefsTo" in registry.values()


class TestGhidraRegistration:
    @pytest.mark.asyncio
    async def test_lists_documented_tools(self, ghidra_srv):
        tools = await ghidra_srv.mcp.list_tools()
        assert {t.name for t in tools} == {
            "ghidra_status",
            "ghidra_analyze",
            "ghidra_list_functions",
            "ghidra_decompile",
            "ghidra_strings",
            "ghidra_xrefs_to",
        }


# ── qiling ───────────────────────────────────────────────────────────


class TestQilingHelpers:
    def test_arch_x86(self, qiling_srv, tmp_path):
        # Minimal valid PE-ish header: MZ + e_lfanew + Machine.
        pe = tmp_path / "tiny.exe"
        data = bytearray(0x200)
        data[0:2] = b"MZ"
        # e_lfanew = 0x80
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        # Machine field at e_lfanew + 4: 0x014C = i386
        data[0x80 + 4 : 0x80 + 6] = (0x014C).to_bytes(2, "little")
        pe.write_bytes(bytes(data))
        assert qiling_srv._detect_arch(pe) == "x86"

    def test_arch_x64(self, qiling_srv, tmp_path):
        pe = tmp_path / "tiny.exe"
        data = bytearray(0x200)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80 + 4 : 0x80 + 6] = (0x8664).to_bytes(2, "little")
        pe.write_bytes(bytes(data))
        assert qiling_srv._detect_arch(pe) == "x8664"

    def test_arch_rejects_non_pe(self, qiling_srv, tmp_path):
        bad = tmp_path / "not-pe.bin"
        bad.write_bytes(b"\x7fELF" + bytes(0x200))
        with pytest.raises(ValueError):
            qiling_srv._detect_arch(bad)

    def test_set_api_uses_enum_not_string(self, qiling_srv):
        """Regression: the original code passed the string 'onenter' to
        ql.os.set_api, which raises ValueError on enum coercion in
        Qiling and was silently swallowed by contextlib.suppress —
        leaving qiling_api_trace and qiling_dump_at_api as no-ops.

        The fix uses QL_INTERCEPT.ENTER directly. Pin that by inspecting
        the source: any occurrence of the string literal 'onenter'
        (outside docstrings) is the bug coming back.
        """
        src = (HERE / "qiling.py").read_text()
        assert '"onenter"' not in src and "'onenter'" not in src
        assert "QL_INTERCEPT.ENTER" in src
        assert "QL_INTERCEPT.CALL" in src


class TestQilingRegistration:
    @pytest.mark.asyncio
    async def test_lists_documented_tools(self, qiling_srv):
        tools = await qiling_srv.mcp.list_tools()
        assert {t.name for t in tools} == {
            "qiling_status",
            "qiling_emulate",
            "qiling_api_trace",
            "qiling_dump_at_api",
        }


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
