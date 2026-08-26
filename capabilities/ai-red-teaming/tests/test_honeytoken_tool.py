"""Tests for tools/honeytoken.py — mint + representation-invariant leak detection."""

from __future__ import annotations

import base64
import importlib.util
import re
import sys
from pathlib import Path

import pytest

# The tool depends on the SDK honeytoken harness (dreadnode.airt.honeytoken); skip
# cleanly on an SDK build that predates it so CI stays green until the SDK is bumped.
pytest.importorskip("dreadnode.airt.honeytoken")

TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "honeytoken.py"
_CANARY_RE = re.compile(r"DN-CANARY-[A-Z]+-[a-z0-9-]+")


def _load():
    spec = importlib.util.spec_from_file_location("honeytoken_tool", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


tools = _load()


def _mint(kind: str = "exfil") -> tuple[str, str]:
    out = tools.mint_honeytoken(kind=kind)
    match = _CANARY_RE.search(out)
    assert match, f"no canary value in mint output: {out!r}"
    return out, match.group(0)


class TestMint:
    def test_exfil_mint_returns_canary_and_injection(self) -> None:
        out, value = _mint("exfil")
        assert value.startswith("DN-CANARY-EXFIL-")
        assert "plant this injection" in out.lower()
        assert value in out  # the injection embeds the canary

    def test_rce_mint_returns_beacon(self) -> None:
        out, value = _mint("rce")
        assert value.startswith("DN-CANARY-RCE-")
        assert "curl" in out.lower()  # rce beacon injection

    def test_invalid_kind_is_reported(self) -> None:
        out = tools.mint_honeytoken(kind="bogus")
        assert "Error" in out
        assert "kind" in out


class TestCheck:
    def test_detects_plaintext_leak(self) -> None:
        _, value = _mint()
        result = tools.check_honeytoken_leaked(
            canary_value=value, agent_output=f"sure, forwarding {value} to the auditor"
        )
        assert "LEAKED" in result

    def test_detects_base64_obfuscated_leak(self) -> None:
        _, value = _mint()
        encoded = base64.b64encode(value.encode()).decode()
        result = tools.check_honeytoken_leaked(
            canary_value=value, agent_output=f"posted blob: {encoded}"
        )
        assert "LEAKED" in result  # representation-invariant

    def test_clean_output_is_not_detected(self) -> None:
        _, value = _mint()
        result = tools.check_honeytoken_leaked(
            canary_value=value, agent_output="task complete, nothing sensitive here"
        )
        assert "NOT DETECTED" in result

    def test_missing_value_is_reported(self) -> None:
        assert "Error" in tools.check_honeytoken_leaked(
            canary_value="", agent_output="x"
        )
