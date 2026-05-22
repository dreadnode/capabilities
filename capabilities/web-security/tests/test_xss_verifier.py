"""Tests for XssVerifier — programmatic XSS verification via agent-browser canary."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

pytestmark = pytest.mark.asyncio

_REPO_ROOT = Path(__file__).resolve()
while _REPO_ROOT != _REPO_ROOT.parent:
    if (_REPO_ROOT / "capabilities" / "web-security" / "tools").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "capabilities" / "web-security" / "tools"))

from xss_verifier import XssVerifier


@pytest.fixture
def verifier() -> XssVerifier:
    return XssVerifier()


def _mock_eval(return_value: str) -> AsyncMock:
    return AsyncMock(return_value=return_value)


class TestToolDiscovery:
    def test_tools_discovered(self, verifier: XssVerifier) -> None:
        tools = verifier.get_tools()
        names = {t.name for t in tools}
        assert names == {"xss_inject_canary", "xss_verify", "xss_reset"}

    def test_tools_have_catch(self, verifier: XssVerifier) -> None:
        for tool in verifier.get_tools():
            assert tool.catch is True

    def test_inject_has_description(self, verifier: XssVerifier) -> None:
        tools = {t.name: t for t in verifier.get_tools()}
        assert "BEFORE" in tools["xss_inject_canary"].description

    def test_verify_has_description(self, verifier: XssVerifier) -> None:
        tools = {t.name: t for t in verifier.get_tools()}
        assert "AFTER" in tools["xss_verify"].description


class TestInjectCanary:
    @patch("xss_verifier._eval_js")
    async def test_inject_arms_canary(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        result = await verifier.inject_canary()
        assert "armed" in result.lower()
        assert verifier._nonce is not None

    @patch("xss_verifier._eval_js")
    async def test_inject_generates_unique_nonce(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        first_nonce = verifier._nonce
        await verifier.inject_canary()
        assert verifier._nonce != first_nonce

    @patch("xss_verifier._eval_js")
    async def test_inject_passes_global_args(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary(global_args=["--session-name", "app"])
        assert verifier._global_args == ["--session-name", "app"]


class TestVerify:
    async def test_verify_without_inject_raises(self, verifier: XssVerifier) -> None:
        with pytest.raises(RuntimeError, match="No canary injected"):
            await verifier.verify(
                xss_context="reflected",
                payload_used="<script>alert(1)</script>",
            )

    @patch("xss_verifier._eval_js")
    async def test_verify_unparseable_response_raises(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()

        mock_eval.return_value = "not-json-at-all"
        with pytest.raises(RuntimeError, match="Could not parse canary state"):
            await verifier.verify(
                xss_context="reflected",
                payload_used="<script>alert(1)</script>",
            )

    @patch("xss_verifier._eval_js")
    async def test_confirmed_on_alert(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        # Arm canary
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce = verifier._nonce

        # Verify with alert signal
        mock_eval.return_value = json.dumps({
            "armed": True,
            "nonce": nonce,
            "alerts": ["1"],
            "confirms": [],
            "prompts": [],
            "scriptExecutions": [],
        })
        result = await verifier.verify(
            xss_context="reflected",
            payload_used="<script>alert(1)</script>",
        )
        assert result.startswith("CONFIRMED")
        assert "alert() called 1x" in result

    @patch("xss_verifier._eval_js")
    async def test_confirmed_on_confirm_dialog(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce = verifier._nonce

        mock_eval.return_value = json.dumps({
            "armed": True,
            "nonce": nonce,
            "alerts": [],
            "confirms": ["xss"],
            "prompts": [],
            "scriptExecutions": [],
        })
        result = await verifier.verify(
            xss_context="dom",
            payload_used="<img src=x onerror=confirm('xss')>",
        )
        assert result.startswith("CONFIRMED")

    @patch("xss_verifier._eval_js")
    async def test_partial_on_script_injection_only(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce = verifier._nonce

        mock_eval.return_value = json.dumps({
            "armed": True,
            "nonce": nonce,
            "alerts": [],
            "confirms": [],
            "prompts": [],
            "scriptExecutions": [{"src": None, "inline": "fetch('https://evil.com')"}],
        })
        result = await verifier.verify(
            xss_context="stored",
            payload_used="<script>fetch('https://evil.com')</script>",
        )
        assert result.startswith("PARTIAL")
        assert "<script> injected" in result

    @patch("xss_verifier._eval_js")
    async def test_not_detected_when_clean(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce = verifier._nonce

        mock_eval.return_value = json.dumps({
            "armed": True,
            "nonce": nonce,
            "alerts": [],
            "confirms": [],
            "prompts": [],
            "scriptExecutions": [],
        })
        result = await verifier.verify(
            xss_context="reflected",
            payload_used="<script>alert(1)</script>",
        )
        assert result.startswith("NOT_DETECTED")
        assert "HTML-encoded" in result

    @patch("xss_verifier._eval_js")
    async def test_canary_lost_on_navigation(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()

        mock_eval.return_value = json.dumps({"armed": False})
        result = await verifier.verify(
            xss_context="reflected",
            payload_used="<script>alert(1)</script>",
        )
        assert "CANARY_LOST" in result

    @patch("xss_verifier._eval_js")
    async def test_nonce_mismatch(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()

        mock_eval.return_value = json.dumps({
            "armed": True,
            "nonce": "wrong_nonce",
            "alerts": [],
            "confirms": [],
            "prompts": [],
            "scriptExecutions": [],
        })
        result = await verifier.verify(
            xss_context="reflected",
            payload_used="<script>alert(1)</script>",
        )
        assert "NONCE_MISMATCH" in result


class TestReset:
    @patch("xss_verifier._eval_js")
    async def test_reset_clears_state(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary(global_args=["--session-name", "test"])
        assert verifier._nonce is not None
        assert verifier._global_args is not None

        result = await verifier.reset()
        assert "reset" in result.lower()
        assert verifier._nonce is None
        assert verifier._global_args is None


class TestMultipleCycles:
    @patch("xss_verifier._eval_js")
    async def test_inject_verify_reset_cycle(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        # Cycle 1: inject, verify (confirmed), reset
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce1 = verifier._nonce

        mock_eval.return_value = json.dumps({
            "armed": True, "nonce": nonce1,
            "alerts": ["1"], "confirms": [], "prompts": [], "scriptExecutions": [],
        })
        result = await verifier.verify(xss_context="reflected", payload_used="<script>alert(1)</script>")
        assert result.startswith("CONFIRMED")

        await verifier.reset()

        # Cycle 2: inject, verify (not detected)
        mock_eval.return_value = "armed"
        await verifier.inject_canary()
        nonce2 = verifier._nonce
        assert nonce2 != nonce1

        mock_eval.return_value = json.dumps({
            "armed": True, "nonce": nonce2,
            "alerts": [], "confirms": [], "prompts": [], "scriptExecutions": [],
        })
        result = await verifier.verify(xss_context="dom", payload_used="<img src=x onerror=alert(1)>")
        assert result.startswith("NOT_DETECTED")


class TestErrorPropagation:
    @patch("xss_verifier._eval_js")
    async def test_inject_propagates_eval_error(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.side_effect = RuntimeError("agent-browser is not available")
        with pytest.raises(RuntimeError, match="agent-browser is not available"):
            await verifier.inject_canary()

    @patch("xss_verifier._eval_js")
    async def test_verify_propagates_eval_timeout(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        mock_eval.return_value = "armed"
        await verifier.inject_canary()

        mock_eval.side_effect = RuntimeError("timed out after 60s")
        with pytest.raises(RuntimeError, match="timed out"):
            await verifier.verify(
                xss_context="reflected",
                payload_used="<script>alert(1)</script>",
            )


class TestHandleToolCall:
    @patch("xss_verifier._eval_js")
    async def test_inject_via_handle_tool_call(self, mock_eval: AsyncMock, verifier: XssVerifier) -> None:
        from dreadnode.agents.tools import FunctionCall, ToolCall

        mock_eval.return_value = "armed"
        tools = {t.name: t for t in verifier.get_tools()}
        tc = ToolCall(
            id="call_inject",
            function=FunctionCall(name="xss_inject_canary", arguments="{}"),
        )
        message, stop = await tools["xss_inject_canary"].handle_tool_call(tc)
        assert stop is False
        assert "armed" in message.content.lower()
