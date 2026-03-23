"""Tests for the temporary Caido compatibility stub."""

from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "caido_proxy.py"
SPEC = importlib.util.spec_from_file_location("caido_proxy", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_caido_proxy_stub_exports_no_toolset() -> None:
    assert getattr(MODULE, "CaidoTools", None) is None
