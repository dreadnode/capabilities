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
#   "lief>=0.16",
#   "yara-python>=4.5",
# ]
# ///
"""Tests for the binary-analysis MCP server — no PE binary required.

Covers pure helpers (entropy, path resolution, output truncation) and
verifies that static_triage registers the tool surface the agent and
skill reference.

Note: Ghidra decompilation is provided by the pyghidra-mcp PyPI
package (declared as an MCP server in capability.yaml) and has its
own test suite — it is not tested here. Qiling is exercised via
agent-written Python using templates in the skill's references/, not
wrapped as an MCP.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).parent


def _load(filename: str, alias: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(alias, HERE / f"{filename}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def static_triage() -> ModuleType:
    return _load("static_triage", "binary_analysis_static_triage")


# ── static_triage ────────────────────────────────────────────────────────


class TestPeTriageHelpers:
    def test_entropy_zero_for_empty(self, static_triage):
        assert static_triage._entropy(b"") == 0.0

    def test_entropy_low_for_uniform(self, static_triage):
        assert static_triage._entropy(b"A" * 1024) == 0.0

    def test_entropy_high_for_random(self, static_triage):
        import os

        ent = static_triage._entropy(os.urandom(4096))
        assert ent > 7.5

    def test_resolve_path_raises_on_missing(self, static_triage, tmp_path):
        with pytest.raises(FileNotFoundError):
            static_triage._resolve_path(str(tmp_path / "nope.exe"))

    def test_truncate_passthrough_short(self, static_triage):
        assert static_triage._truncate("hi") == "hi"

    def test_truncate_chops_long(self, static_triage, monkeypatch):
        monkeypatch.setattr(static_triage, "MAX_OUTPUT_CHARS", 8)
        out = static_triage._truncate("0123456789")
        assert out.startswith("01234567")
        assert "truncated" in out


class TestPeTriageRegistration:
    @pytest.mark.asyncio
    async def test_lists_documented_tools(self, static_triage):
        tools = await static_triage.mcp.list_tools()
        names = {t.name for t in tools}
        assert names == {
            "triage_status",
            "pe_info",
            "bin_strings",
            "pe_floss",
            "bin_capa",
            "pe_hash",
            "bin_bytes_at",
            "bin_format_info",
            "bin_yara",
            "debuginfod_symbols",
        }

    @pytest.mark.asyncio
    async def test_status_probes_real_symbols(self, static_triage):
        result = await static_triage.mcp.call_tool("triage_status", {})
        body = result.structured_content
        # Status must reflect what tools actually need, not just package import.
        # A package that imports but lacks the symbols pe_floss / bin_capa rely
        # on must surface here, not silently at first call.
        assert "pefile" in body
        assert "floss" in body
        assert "capa" in body
        assert "lief" in body
        assert "yara" in body

    @pytest.mark.asyncio
    async def test_bytes_at_raises_on_oor(self, static_triage, tmp_path):
        sample = tmp_path / "tiny.bin"
        sample.write_bytes(b"hello")
        with pytest.raises(Exception) as ei:
            await static_triage.mcp.call_tool(
                "bin_bytes_at", {"path": str(sample), "offset": 999, "length": 4}
            )
        assert "out of range" in str(ei.value)

    @pytest.mark.asyncio
    async def test_format_info_rejects_non_binary(self, static_triage, tmp_path):
        # LIEF.parse() returns None on unrecognized bytes; the tool wraps
        # that in a ValueError so the model gets a clear failure.
        junk = tmp_path / "not-a-binary.txt"
        junk.write_text("hello world, definitely not a PE/ELF/Mach-O")
        with pytest.raises(Exception) as ei:
            await static_triage.mcp.call_tool("bin_format_info", {"path": str(junk)})
        assert (
            "unrecognized format" in str(ei.value).lower()
            or "could not parse" in str(ei.value).lower()
        )

    @pytest.mark.asyncio
    async def test_yara_with_explicit_rule(self, static_triage, tmp_path):
        # Verifies the tool end-to-end without needing a clone of the
        # community rule pack — pass `rules=` to a hand-written .yar.
        sample = tmp_path / "target.bin"
        sample.write_bytes(b"some garbage MAGIC_SENTINEL more garbage")
        rules = tmp_path / "test.yar"
        rules.write_text(
            'rule has_sentinel { strings: $a = "MAGIC_SENTINEL" ascii '
            "condition: $a }\n"
        )
        result = await static_triage.mcp.call_tool(
            "bin_yara",
            {"path": str(sample), "rules": str(rules)},
        )
        text = result.content[0].text
        assert "has_sentinel" in text
        assert "MAGIC_SENTINEL".encode().hex() in text

        # summary_only path
        summary = await static_triage.mcp.call_tool(
            "bin_yara",
            {"path": str(sample), "rules": str(rules), "summary_only": True},
        )
        assert "has_sentinel" in summary.content[0].text
        assert "1 matches" in summary.content[0].text

    @pytest.mark.asyncio
    async def test_yara_missing_rules_path(self, static_triage, tmp_path):
        sample = tmp_path / "target.bin"
        sample.write_bytes(b"hello")
        with pytest.raises(Exception) as ei:
            await static_triage.mcp.call_tool(
                "bin_yara",
                {"path": str(sample), "rules": str(tmp_path / "nope.yar")},
            )
        assert "does not exist" in str(ei.value).lower()


class TestDebuginfod:
    """Build-ID note parsing + server resolution are pure/hermetic; the tool's
    ELF guard is checked without touching the network."""

    def test_parse_build_id_note_roundtrip(self, static_triage):
        import struct as _struct

        name = b"GNU\x00"  # namesz = 4
        desc = bytes(range(20))  # 20-byte (sha1-style) build-id
        note = _struct.pack("<III", len(name), len(desc), 3) + name + desc
        assert static_triage._parse_build_id_note(note) == desc.hex()

    def test_parse_build_id_note_rejects_garbage(self, static_triage):
        assert static_triage._parse_build_id_note(b"\x00\x01") is None

    def test_resolve_servers_explicit_arg_wins(self, static_triage):
        got = static_triage._resolve_debuginfod_servers("https://a/, https://b/")
        assert got == ["https://a/", "https://b/"]

    def test_resolve_servers_default_federation(self, static_triage, monkeypatch):
        monkeypatch.delenv("DEBUGINFOD_URLS", raising=False)
        assert static_triage._resolve_debuginfod_servers(None) == [
            static_triage.DEBUGINFOD_FALLBACK
        ]

    def test_resolve_servers_empty_env_is_disabled(self, static_triage, monkeypatch):
        monkeypatch.setenv("DEBUGINFOD_URLS", "")
        with pytest.raises(RuntimeError) as ei:
            static_triage._resolve_debuginfod_servers(None)
        assert "disabled" in str(ei.value).lower()

    @pytest.mark.asyncio
    async def test_rejects_non_elf_before_network(self, static_triage, tmp_path):
        junk = tmp_path / "not-elf.txt"
        junk.write_text("definitely not an ELF")
        with pytest.raises(Exception) as ei:
            await static_triage.mcp.call_tool("debuginfod_symbols", {"path": str(junk)})
        assert "elf" in str(ei.value).lower()


class TestCacheLayout:
    """Cache root resolution + legacy migration shim.

    Verifies the documented env-var precedence (BINANAL_CACHE_ROOT >
    PE_TRIAGE_CAPA_CACHE > default) and that legacy
    `~/.dreadnode/binary-analysis/` content moves to the new root on
    module import.
    """

    def test_cache_root_defaults_to_cache_subdir(self, monkeypatch, tmp_path):
        monkeypatch.delenv("BINANAL_CACHE_ROOT", raising=False)
        monkeypatch.delenv("PE_TRIAGE_CAPA_CACHE", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        # Reload by importing fresh under a new alias
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pet_default", HERE / "static_triage.py"
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["pet_default"] = mod
        spec.loader.exec_module(mod)
        assert str(mod.CAPA_CACHE_ROOT).endswith(".dreadnode/cache/binary-analysis")

    def test_cache_root_honors_new_env_var(self, monkeypatch, tmp_path):
        target = tmp_path / "custom-cache"
        monkeypatch.setenv("BINANAL_CACHE_ROOT", str(target))
        monkeypatch.delenv("PE_TRIAGE_CAPA_CACHE", raising=False)
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pet_new_env", HERE / "static_triage.py"
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["pet_new_env"] = mod
        spec.loader.exec_module(mod)
        assert mod.CAPA_CACHE_ROOT == target
        assert mod.CAPA_RULES_CACHE == target / "capa-rules"
        assert mod.YARA_RULES_CACHE == target / "yara-rules"

    def test_cache_root_falls_back_to_legacy_env(self, monkeypatch, tmp_path):
        legacy_target = tmp_path / "legacy-set-path"
        monkeypatch.delenv("BINANAL_CACHE_ROOT", raising=False)
        monkeypatch.setenv("PE_TRIAGE_CAPA_CACHE", str(legacy_target))
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pet_legacy_env", HERE / "static_triage.py"
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["pet_legacy_env"] = mod
        spec.loader.exec_module(mod)
        assert mod.CAPA_CACHE_ROOT == legacy_target

    def test_legacy_cache_dir_migrates_on_import(self, monkeypatch, tmp_path):
        # Stand up the legacy layout with populated subdirs
        fake_home = tmp_path / "home"
        legacy = fake_home / ".dreadnode" / "binary-analysis"
        (legacy / "capa-rules" / "lib").mkdir(parents=True)
        (legacy / "capa-rules" / "lib" / "anti-debug.yml").write_text("# rule")
        (legacy / "yara-rules").mkdir(parents=True)
        (legacy / "yara-rules" / "test.yar").write_text("rule x { condition: true }")

        new_root = fake_home / ".dreadnode" / "cache" / "binary-analysis"
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("BINANAL_CACHE_ROOT", str(new_root))
        monkeypatch.delenv("PE_TRIAGE_CAPA_CACHE", raising=False)

        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "pet_migrate", HERE / "static_triage.py"
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["pet_migrate"] = mod
        spec.loader.exec_module(mod)

        # After import, legacy subdirs should be at the new root
        assert (new_root / "capa-rules" / "lib" / "anti-debug.yml").exists()
        assert (new_root / "yara-rules" / "test.yar").exists()
        # And the legacy paths should be gone
        assert not (legacy / "capa-rules").exists()
        assert not (legacy / "yara-rules").exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
