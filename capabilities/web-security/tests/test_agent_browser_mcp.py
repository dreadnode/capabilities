"""Tests for the agent-browser MCP wrapper."""

from __future__ import annotations

import importlib.util
import json
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

    fastmcp.FastMCP = _FastMCP
    sys.modules["fastmcp"] = fastmcp


_install_fastmcp_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "mcp" / "agent_browser.py"
SPEC = importlib.util.spec_from_file_location("agent_browser_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_expected_tools_registered() -> None:
    expected = {
        "agent_browser_status",
        "agent_browser_run",
        "agent_browser_open",
        "agent_browser_snapshot",
        "agent_browser_click",
        "agent_browser_fill",
        "agent_browser_type",
        "agent_browser_press",
        "agent_browser_wait",
        "agent_browser_get",
        "agent_browser_screenshot",
        "agent_browser_set_viewport",
        "agent_browser_close",
        "agent_browser_start_js_execution_proof",
        "agent_browser_check_js_execution_proof",
        "agent_browser_reset_js_execution_proof",
    }
    assert set(MODULE.mcp._tools) == expected


def test_resolve_command_prefers_configured_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BROWSER_COMMAND", "npx --yes agent-browser")

    with patch.object(MODULE.shutil, "which", return_value="/usr/bin/npx"):
        assert MODULE._resolve_command() == ["npx", "--yes", "agent-browser"]


def test_resolve_command_prefers_agent_browser_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/local/bin/agent-browser" if name == "agent-browser" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["agent-browser"]


def test_resolve_command_falls_back_to_npx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)

    def fake_which(name: str) -> str | None:
        return "/usr/bin/npx" if name == "npx" else None

    with patch.object(MODULE.shutil, "which", side_effect=fake_which):
        assert MODULE._resolve_command() == ["npx", "--yes", "agent-browser"]


def test_resolve_command_returns_none_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        assert MODULE._resolve_command() is None


@pytest.mark.asyncio
async def test_run_reports_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BROWSER_COMMAND", raising=False)
    with patch.object(MODULE.shutil, "which", return_value=None):
        result = await MODULE.agent_browser_open("https://example.com")

    assert "agent-browser is unavailable" in result
    assert "AGENT_BROWSER_COMMAND" in result


@pytest.mark.asyncio
async def test_open_passes_argv_without_shell() -> None:
    proc = AsyncMock()
    proc.returncode = 0
    proc.communicate.return_value = (b"opened", b"")

    with (
        patch.object(MODULE, "_resolve_command", return_value=["agent-browser"]),
        patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            return_value=proc,
        ) as create_proc,
    ):
        result = await MODULE.agent_browser_open(
            "https://example.com",
            global_args=["--session-name", "cap"],
            timeout=5,
        )

    create_proc.assert_called_once()
    assert create_proc.call_args.args[:5] == (
        "agent-browser",
        "--session-name",
        "cap",
        "open",
        "https://example.com",
    )
    assert result == "opened"


@pytest.mark.asyncio
async def test_run_empty_args_errors() -> None:
    result = await MODULE.agent_browser_run([])
    assert result == "Error: args must include an agent-browser subcommand."


@pytest.mark.asyncio
async def test_js_execution_proof_start_returns_token_payloads() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    with (
        patch.object(MODULE.secrets, "token_urlsafe", return_value="proof-token"),
        patch.object(
            MODULE,
            "_run_agent_browser",
            return_value=json.dumps(
                {
                    "status": "armed",
                    "kind": "browser_js_execution",
                    "token": "proof-token",
                    "url": "https://target.test/search",
                }
            ),
        ) as run_browser,
    ):
        result = await MODULE.agent_browser_start_js_execution_proof(
            proof_id="case-1",
            global_args=["--session-name", "case-1"],
        )

    assert result["kind"] == "browser_js_execution"
    assert result["status"] == "armed"
    assert result["token"] == "proof-token"
    assert result["payloads"]["script_tag"].startswith("<script>")
    assert "proof-token" in result["payloads"]["event_handler"]
    assert "__dreadnode_js_proof" in result["payloads"]["script_tag"]
    assert MODULE._JS_PROOF_SESSIONS["case-1"]["token"] == "proof-token"
    run_browser.assert_called_once()
    assert run_browser.call_args.kwargs["global_args"] == ["--session-name", "case-1"]
    assert run_browser.call_args.args[0][0] == "eval"


@pytest.mark.asyncio
async def test_js_execution_proof_check_confirms_proof_event() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": json.dumps(["--session-name", "case-1"]),
    }
    state = {
        "armed": True,
        "token": "proof-token",
        "url": "https://target.test/search?q=xss",
        "events": [
            {
                "channel": "proof-function",
                "value": "proof-token",
                "matched": True,
                "url": "https://target.test/search?q=xss",
            }
        ],
    }
    with patch.object(MODULE, "_run_agent_browser", return_value=json.dumps(state)):
        result = await MODULE.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["kind"] == "browser_js_execution"
    assert result["verified"] is True
    assert result["verdict"] == "CONFIRMED"
    assert result["confidence"] == "high"
    assert result["evidence"][0]["channel"] == "proof-function"


@pytest.mark.asyncio
async def test_js_execution_proof_check_accepts_nested_json_string() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    state = {
        "armed": True,
        "token": "proof-token",
        "url": "https://target.test/search?q=xss",
        "events": [
            {
                "channel": "alert",
                "value": "__DN_JS_PROOF__:proof-token",
                "matched": True,
            }
        ],
    }
    with patch.object(
        MODULE,
        "_run_agent_browser",
        return_value=json.dumps(json.dumps(state)),
    ):
        result = await MODULE.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["verified"] is True
    assert result["verdict"] == "CONFIRMED"


@pytest.mark.asyncio
async def test_js_execution_proof_check_reports_lost_canary() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    with patch.object(
        MODULE,
        "_run_agent_browser",
        return_value=json.dumps({"armed": False, "url": "https://target.test/next"}),
    ):
        result = await MODULE.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["verified"] is False
    assert result["verdict"] == "CANARY_NOT_OBSERVED"
    assert "Trigger the payload" in result["reason"]


@pytest.mark.asyncio
async def test_js_execution_proof_check_confirms_storage_marker_without_armed_hook() -> (
    None
):
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    state = {
        "kind": "browser_js_execution",
        "armed": False,
        "url": "https://target.test/search?q=xss",
        "storage": {"localStorage": "proof-token", "sessionStorage": ""},
    }
    with patch.object(MODULE, "_run_agent_browser", return_value=json.dumps(state)):
        result = await MODULE.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["verified"] is True
    assert result["verdict"] == "CONFIRMED"
    assert result["evidence"][0]["channel"] == "localStorage"


@pytest.mark.asyncio
async def test_js_execution_proof_check_requires_token() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    with pytest.raises(RuntimeError, match="No proof token"):
        await MODULE.agent_browser_check_js_execution_proof(proof_id="missing")


@pytest.mark.asyncio
async def test_js_execution_proof_reset_clears_session() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    with patch.object(
        MODULE,
        "_run_agent_browser",
        return_value=json.dumps({"status": "reset", "url": "https://target.test/"}),
    ):
        result = await MODULE.agent_browser_reset_js_execution_proof(proof_id="case-1")

    assert result == {
        "kind": "browser_js_execution",
        "status": "reset",
        "proof_id": "case-1",
        "url": "https://target.test/",
    }
    assert "case-1" not in MODULE._JS_PROOF_SESSIONS
