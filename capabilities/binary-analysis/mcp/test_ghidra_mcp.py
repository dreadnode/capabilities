#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "pyghidra-mcp",
# ]
# ///
"""Tests for the ghidra_mcp composition server — no Ghidra/JVM required.

Covers the pure helpers and verifies that importing pyghidra-mcp and
registering our extra tools yields one server exposing the full base surface
PLUS the added tools (the composition mechanism). The Ghidra-API logic of each
tool (FID hashing, HighFunction dataflow, EmulatorHelper) needs a Ghidra install
+ JVM to exercise against a real binary and is not reproduced here.

If pyghidra-mcp can't be imported (e.g. GHIDRA_INSTALL_DIR unset in a bare CI
env), the registration tests skip rather than fail — the helper tests that don't
need the import still run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).parent


def _load() -> ModuleType:
    # Load under a distinct alias — NOT "ghidra", which would shadow Ghidra's
    # own `ghidra` Java package once pyghidra boots the JVM.
    spec = importlib.util.spec_from_file_location(
        "binary_analysis_ghidra_mcp", HERE / "ghidra_mcp.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["binary_analysis_ghidra_mcp"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 — pyghidra-mcp/Ghidra not available here
        pytest.skip(f"ghidra_mcp not importable in this env: {e}")
    return mod


@pytest.fixture(scope="module")
def extras() -> ModuleType:
    return _load()


class TestPureHelpers:
    """Helpers that don't touch the JVM — always run."""

    def test_u64_masks_signed(self, extras):
        assert extras._u64(-1) == "0xffffffffffffffff"
        assert extras._u64(0) == "0x0000000000000000"
        assert extras._u64(0x4F9982E418844332) == "0x4f9982e418844332"

    def test_drop_empty_keeps_zero_and_false(self, extras):
        got = extras._drop_empty(
            {"a": 1, "b": None, "c": "", "d": [], "e": {}, "f": 0, "g": False}
        )
        assert got == {"a": 1, "f": 0, "g": False}

    def test_is_default_name(self, extras):
        assert extras._is_default_name("FUN_00401000")
        assert extras._is_default_name("thunk_FUN_00401000")
        assert not extras._is_default_name("validate_license")
        assert not extras._is_default_name("main")

    def test_struct_hash_order_invariant_but_shape_sensitive(self, extras):
        shape = [(0, 2), (1, 1), (2, 0)]
        # Block ordering must not change the hash (it's a sorted multiset)...
        assert extras._struct_hash(shape) == extras._struct_hash(list(reversed(shape)))
        # ...but a different control-flow shape must.
        assert extras._struct_hash(shape) != extras._struct_hash([(0, 1), (1, 0)])

    def test_similarity_ratio_bounds(self, extras):
        assert extras._similarity_ratio([], []) == 1.0
        assert extras._similarity_ratio(["mov", "add"], ["mov", "add"]) == 1.0
        assert (
            0.0 <= extras._similarity_ratio(["mov", "add"], ["mov", "sub", "xor"]) < 1.0
        )

    def test_bsim_db_path_under_cache_root(self, extras, tmp_path, monkeypatch):
        monkeypatch.setenv("BINANAL_CACHE_ROOT", str(tmp_path))
        path = extras._bsim_db_path("corpus")
        assert path == str(tmp_path / "bsim" / "corpus")
        assert (tmp_path / "bsim").is_dir()  # directory is created for the caller


class TestComposition:
    """The added tools register on pyghidra-mcp's FastMCP object without replacing it."""

    @pytest.mark.asyncio
    async def test_extras_registered_alongside_base(self, extras):
        tools = await extras.mcp.list_tools()
        names = {t.name for t in tools}
        # our additions
        assert {
            "ghidra_status",
            "function_fid_hash",
            "function_dataflow",
            "emulate_function",
            "diff_binaries",
            "diff_function",
            "bsim_build_database",
            "bsim_query_function",
            "bsim_overview",
        } <= names, f"missing extras; got {sorted(names)}"
        # base pyghidra-mcp surface still present (we extend, not replace)
        assert {
            "decompile_function",
            "search_code",
            "rename_function",
            "list_xrefs",
        } <= names

    def test_delegates_to_base_main(self, extras):
        # The entrypoint must run pyghidra-mcp's CLI (which drives the same mcp
        # object), not a private runner — otherwise the base surface wouldn't ship.
        import pyghidra_mcp.server as base

        assert extras.mcp is base.mcp


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
