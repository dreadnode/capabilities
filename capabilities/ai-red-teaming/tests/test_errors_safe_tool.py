"""Tests for tools/errors.py - safe_tool retry/classification + fmt_asr.

Regression for ENG-8427: transient network faults (TLS handshake timeout, etc.)
should be retried and surfaced as an explicitly non-fatal Note, and ASR should
render consistently as a percentage (the '1.0%' bug).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("dreadnode.agents.tools")

ERRORS_PATH = Path(__file__).resolve().parents[1] / "tools" / "errors.py"


def _load():
    spec = importlib.util.spec_from_file_location("airt_errors_under_test", ERRORS_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


E = _load()


class TestFmtAsr:
    @pytest.mark.parametrize("value,expected", [
        (1.0, "100%"),
        (0.78, "78%"),
        (0.975, "97.5%"),
        (78, "78%"),
        (100, "100%"),
        (0.0, "0%"),
        (None, "N/A"),
    ])
    def test_formats(self, value, expected):
        assert E.fmt_asr(value) == expected

    def test_fraction_one_is_not_one_percent(self):
        # The ENG-8427 bug: 1.0 was rendered as "1.0%" instead of "100%".
        assert E.fmt_asr(1.0) == "100%"
        assert E.fmt_asr(1.0) != "1.0%"


class TestTransientClassification:
    @pytest.mark.parametrize("exc", [
        ConnectionError("_ssl.c:983: The handshake operation timed out"),
        TimeoutError("read timed out"),
        OSError("Connection reset by peer"),
        RuntimeError("502 Bad Gateway"),
    ])
    def test_transient_true(self, exc):
        assert E._is_transient(exc) is True

    @pytest.mark.parametrize("exc", [
        ValueError("num_classes must be > 0"),
        KeyError("records"),
    ])
    def test_transient_false(self, exc):
        assert E._is_transient(exc) is False


class TestSafeToolRetry:
    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        monkeypatch.setattr(E, "_BACKOFF_SECONDS", (0, 0))

    def test_transient_is_retried_then_noted(self):
        calls = {"n": 0}

        @E.safe_tool
        def flaky() -> str:
            calls["n"] += 1
            raise ConnectionError("handshake operation timed out")

        out = flaky()
        assert calls["n"] == E._MAX_RETRIES + 1  # retried to exhaustion
        assert out.startswith("Note:")
        assert "transient" in out
        assert "does not affect any attack" in out

    def test_transient_then_success_returns_value(self):
        calls = {"n": 0}

        @E.safe_tool
        def recovers() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise TimeoutError("connection timed out")
            return "OK"

        assert recovers() == "OK"
        assert calls["n"] == 2

    def test_non_transient_not_retried_and_is_error(self):
        calls = {"n": 0}

        @E.safe_tool
        def bad() -> str:
            calls["n"] += 1
            raise ValueError("bad parameter")

        out = bad()
        assert calls["n"] == 1  # no retry for a non-transient error
        assert out.startswith("Error:")
        assert "could not complete" in out

    def test_no_em_dash_in_messages(self):
        @E.safe_tool
        def t1() -> str:
            raise ValueError("x")

        @E.safe_tool
        def t2() -> str:
            raise ConnectionError("timed out")

        assert "—" not in t1()
        assert "—" not in t2()

    @pytest.mark.asyncio
    async def test_async_transient_then_success(self):
        calls = {"n": 0}

        @E.safe_tool
        async def arec() -> str:
            calls["n"] += 1
            if calls["n"] < 2:
                raise ConnectionError("ssl handshake timed out")
            return "ASYNC_OK"

        assert await arec() == "ASYNC_OK"
        assert calls["n"] == 2
