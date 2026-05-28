#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
# ]
# ///
"""Tests for the android-apk-research MCP server — no APK required.

Covers pure helpers and verifies the tool surface the skills and agent
reference. The heavyweight downstream tools (jadx, semgrep, joern, codeql)
have their own test suites and are out of scope here.
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
def server() -> ModuleType:
    return _load("android_research", "android_research_mcp")


class TestHelpers:
    def test_truncate_passthrough_short(self, server):
        assert server._truncate("hi") == "hi"

    def test_truncate_chops_long(self, server, monkeypatch):
        monkeypatch.setattr(server, "MAX_OUTPUT_CHARS", 8)
        out = server._truncate("0123456789")
        assert out.startswith("01234567")
        assert "truncated" in out

    def test_strip_none_drops_empties_keeps_falsy(self, server):
        d = server._strip_none(
            {
                "a": 0,
                "b": False,
                "c": None,
                "d": "",
                "e": [],
                "f": {},
                "g": "keep",
                "h": [1, 2],
            }
        )
        assert d == {"a": 0, "b": False, "g": "keep", "h": [1, 2]}

    def test_resolve_existing_raises_on_missing(self, server, tmp_path):
        with pytest.raises(FileNotFoundError):
            server._resolve_existing(str(tmp_path / "nope"))

    def test_resolve_existing_returns_resolved(self, server, tmp_path):
        f = tmp_path / "f.txt"
        f.write_text("hi")
        assert server._resolve_existing(str(f)) == f.resolve()

    def test_resolve_out_creates_parent(self, server, tmp_path):
        out = tmp_path / "a" / "b" / "c.json"
        resolved = server._resolve_out(str(out))
        assert resolved == out.resolve()
        assert out.parent.exists()

    def test_count_lines(self, server, tmp_path):
        f = tmp_path / "lines.jsonl"
        f.write_text("a\nb\nc\n")
        assert server._count_lines(f) == 3
        assert server._count_lines(tmp_path / "missing") == 0

    def test_runtime_kinds_complete(self, server):
        # Must include every value detect_runtime_kind.sh emits.
        # Source of truth: scripts/detect_runtime_kind.sh header.
        assert {
            "native",
            "react_native_js",
            "react_native_hermes",
            "flutter_aot",
            "capacitor",
            "cordova",
            "unity",
            "xamarin",
            "maui",
        }.issubset(server.RUNTIME_KINDS)


class TestRegistration:
    @pytest.mark.asyncio
    async def test_lists_documented_tools(self, server):
        tools = await server.mcp.list_tools()
        names = {t.name for t in tools}
        # Lock the surface. If a tool is added or removed, the skill prose
        # and agent-utility-index must be updated in the same change.
        assert names == {
            "inventory_status",
            "run_corpus_inventory",
            "extract_components",
            "rank_components",
            "detect_runtime_kind",
            "detect_protector",
            "dexprotector_unpack",
            "extract_api_map",
            "rank_backend_richness",
            "normalize_semantic_findings",
        }

    @pytest.mark.asyncio
    async def test_inventory_status_returns_dict(self, server):
        result = await server.mcp.call_tool("inventory_status", {})
        body = result.structured_content
        # Always reports the capability root — that's the one field we can
        # rely on regardless of which CLIs the host has.
        assert "capability_root" in body

    @pytest.mark.asyncio
    async def test_run_corpus_inventory_requires_paths(self, server):
        with pytest.raises(Exception) as ei:
            await server.mcp.call_tool(
                "run_corpus_inventory", {"paths": [], "out_dir": "/tmp/x"}
            )
        assert "paths" in str(ei.value).lower()

    @pytest.mark.asyncio
    async def test_normalize_findings_requires_inputs(self, server):
        with pytest.raises(Exception) as ei:
            await server.mcp.call_tool("normalize_semantic_findings", {"inputs": []})
        assert "inputs" in str(ei.value).lower()

    @pytest.mark.asyncio
    async def test_rank_backend_richness_requires_summaries(self, server):
        with pytest.raises(Exception) as ei:
            await server.mcp.call_tool(
                "rank_backend_richness", {"summaries": [], "out_jsonl": "/tmp/x"}
            )
        assert "summaries" in str(ei.value).lower()


class TestScriptWiring:
    """Verify every script the MCP shells out to actually exists.

    Catches the rename-drift bug class flagged in the audit: tool says
    `python3 scripts/foo.py` but `foo.py` was deleted. We don't run the
    scripts here — just verify the path the MCP would invoke is present.
    """

    @pytest.mark.parametrize(
        "script",
        [
            "run_corpus_inventory.py",
            "extract_corpus_components.py",
            "rank_components.py",
            "detect_runtime_kind.sh",
            "protector_detect.py",
            "dexprotector_unpack.py",
            "extract_api_map.py",
            "rank_backend_richness.py",
            "normalize_findings.py",
        ],
    )
    def test_script_exists(self, server, script):
        path = server.SCRIPTS / script
        assert path.exists(), f"MCP-referenced script missing: {path}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
