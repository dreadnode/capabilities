"""Tests for the Caido MCP server wrapper (mcp/caido.py).

Focuses on the _CaidoClient retry and timeout behaviour — the main
defence against the model declaring Caido "intermittently unavailable"
after a single transient failure.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module import — the Caido MCP server is a standalone uv-run script, not a
# package.  Import it from its filesystem path so we can test its internals.
# ---------------------------------------------------------------------------

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "caido.py"


@pytest.fixture(autouse=True)
def _stub_caido_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide minimal stubs for caido-sdk-client so the module can import
    without the real SDK installed in the test env."""
    if "caido_sdk_client" in sys.modules:
        return  # Real SDK is available — nothing to stub.

    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = MagicMock  # type: ignore[attr-defined]

    auth = types.ModuleType("caido_sdk_client.auth")
    auth.PATAuthOptions = MagicMock  # type: ignore[attr-defined]
    auth.TokenAuthOptions = MagicMock  # type: ignore[attr-defined]
    auth.TokenPair = MagicMock  # type: ignore[attr-defined]

    finding_mod = types.ModuleType("caido_sdk_client.types.finding")
    finding_mod.CreateFindingOptions = MagicMock  # type: ignore[attr-defined]

    replay_mod = types.ModuleType("caido_sdk_client.types.replay_session")
    replay_mod.ReplaySendOptions = MagicMock  # type: ignore[attr-defined]

    scope_mod = types.ModuleType("caido_sdk_client.types.scope")
    scope_mod.CreateScopeOptions = MagicMock  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.auth", auth)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", types.ModuleType("caido_sdk_client.types"))
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types.finding", finding_mod)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types.replay_session", replay_mod)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types.scope", scope_mod)


def _load_caido_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("caido_mcp", MODULE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# =============================================================================
# Constants
# =============================================================================


class TestCaidoConstants:
    def test_connect_timeout_is_30(self) -> None:
        mod = _load_caido_module()
        assert mod.CONNECT_TIMEOUT == 30

    def test_retry_constants_exist(self) -> None:
        mod = _load_caido_module()
        assert mod._SAFE_GET_RETRIES >= 1
        assert mod._SAFE_GET_RETRY_DELAY > 0


# =============================================================================
# _CaidoClient.safe_get retry behaviour
# =============================================================================


class TestCaidoClientSafeGetRetry:
    """safe_get must retry once on transient failures before returning an error."""

    def _make_client(self, mod: types.ModuleType) -> object:
        return mod._CaidoClient()

    @pytest.mark.asyncio
    async def test_success_on_first_try(self) -> None:
        mod = _load_caido_module()
        client = self._make_client(mod)
        mock_sdk = MagicMock()
        client.get = AsyncMock(return_value=mock_sdk)  # type: ignore[attr-defined]

        result, err = await client.safe_get()

        assert result is mock_sdk
        assert err is None
        assert client.get.call_count == 1  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_transient_failure_then_success(self) -> None:
        """First get() fails, retry succeeds."""
        mod = _load_caido_module()
        client = self._make_client(mod)
        mock_sdk = MagicMock()
        client.get = AsyncMock(side_effect=[ConnectionError("transient"), mock_sdk])  # type: ignore[attr-defined]

        with patch.object(mod, "_SAFE_GET_RETRY_DELAY", 0):
            result, err = await client.safe_get()

        assert result is mock_sdk
        assert err is None
        assert client.get.call_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_both_attempts_fail_returns_error(self) -> None:
        """Both get() calls fail — returns None + error string."""
        mod = _load_caido_module()
        client = self._make_client(mod)
        client.get = AsyncMock(  # type: ignore[attr-defined]
            side_effect=[TimeoutError("slow"), TimeoutError("still slow")]
        )

        with patch.object(mod, "_SAFE_GET_RETRY_DELAY", 0):
            result, err = await client.safe_get()

        assert result is None
        assert err is not None
        assert "still slow" in err
        assert client.get.call_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_client_reset_between_retries(self) -> None:
        """_client is set to None after each failure so the next get()
        re-authenticates from scratch."""
        mod = _load_caido_module()
        client = self._make_client(mod)
        mock_sdk = MagicMock()

        call_count = 0
        original_client_attr = None

        async def tracking_get() -> MagicMock:
            nonlocal call_count, original_client_attr
            call_count += 1
            if call_count == 1:
                raise ConnectionError("reset")
            # On retry, _client should have been cleared
            original_client_attr = client._client  # type: ignore[attr-defined]
            return mock_sdk

        client.get = tracking_get  # type: ignore[attr-defined]

        with patch.object(mod, "_SAFE_GET_RETRY_DELAY", 0):
            result, err = await client.safe_get()

        assert result is mock_sdk
        assert err is None
        # _client was None when the retry ran (cleared after first failure)
        assert original_client_attr is None

    @pytest.mark.asyncio
    async def test_retry_delay_is_respected(self) -> None:
        """The retry delay is actually awaited between attempts."""
        mod = _load_caido_module()
        client = self._make_client(mod)
        mock_sdk = MagicMock()
        client.get = AsyncMock(side_effect=[OSError("blip"), mock_sdk])  # type: ignore[attr-defined]

        sleep_calls: list[float] = []
        original_sleep = asyncio.sleep

        async def tracking_sleep(delay: float) -> None:
            sleep_calls.append(delay)
            # Don't actually sleep in tests

        with patch.object(mod, "_SAFE_GET_RETRY_DELAY", 2.0), \
             patch("asyncio.sleep", side_effect=tracking_sleep):
            await client.safe_get()

        assert sleep_calls == [2.0]
