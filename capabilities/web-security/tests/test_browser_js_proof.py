from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "browser_js_proof.py"
SPEC = importlib.util.spec_from_file_location("browser_js_proof", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["browser_js_proof"] = MODULE
SPEC.loader.exec_module(MODULE)


def test_toolset_registers_generic_js_proof_tools() -> None:
    tools = {tool.name for tool in MODULE.BrowserJsProof().get_tools()}

    assert {
        "agent_browser_start_js_execution_proof",
        "agent_browser_check_js_execution_proof",
        "agent_browser_reset_js_execution_proof",
    }.issubset(tools)


@pytest.mark.asyncio
async def test_start_returns_token_payloads() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    toolset = MODULE.BrowserJsProof()

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
        result = await toolset.agent_browser_start_js_execution_proof(
            proof_id="case-1",
            global_args=["--session-name", "case-1"],
        )

    assert result["kind"] == "browser_js_execution"
    assert result["status"] == "armed"
    assert result["token"] == "proof-token"
    assert "__dreadnode_js_proof" in result["payloads"]["script_tag"]
    assert MODULE._JS_PROOF_SESSIONS["case-1"]["token"] == "proof-token"
    assert run_browser.call_args.args[0][0] == "eval"


@pytest.mark.asyncio
async def test_check_confirms_storage_marker_without_armed_hook() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    toolset = MODULE.BrowserJsProof()
    state = {
        "kind": "browser_js_execution",
        "armed": False,
        "url": "https://target.test/search?q=xss",
        "storage": {"localStorage": "proof-token", "sessionStorage": ""},
    }

    with patch.object(MODULE, "_run_agent_browser", return_value=json.dumps(state)):
        result = await toolset.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["verified"] is True
    assert result["verdict"] == "CONFIRMED"
    assert result["evidence"][0]["channel"] == "localStorage"


@pytest.mark.asyncio
async def test_check_confirms_instrumented_browser_event_without_storage() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    MODULE._JS_PROOF_SESSIONS["case-1"] = {
        "token": "proof-token",
        "global_args": "[]",
    }
    toolset = MODULE.BrowserJsProof()
    state = {
        "kind": "browser_js_execution",
        "armed": True,
        "token": "proof-token",
        "url": "https://target.test/#dom-xss",
        "events": [
            {
                "channel": "alert",
                "value": "__DN_JS_PROOF__:proof-token",
                "matched": True,
            }
        ],
        "storage": {},
    }

    with patch.object(MODULE, "_run_agent_browser", return_value=json.dumps(state)):
        result = await toolset.agent_browser_check_js_execution_proof(proof_id="case-1")

    assert result["verified"] is True
    assert result["verdict"] == "CONFIRMED"
    assert result["evidence"][0]["channel"] == "alert"


def test_payload_examples_cover_browser_local_xss_sink_shapes() -> None:
    payloads = MODULE._js_execution_payload_examples("proof-token")

    assert {
        "script_tag",
        "event_handler",
        "svg_onload",
        "javascript_url",
        "dialog",
        "console",
        "post_message",
    } == set(payloads)
    assert "__dreadnode_js_proof" in payloads["script_tag"]
    assert "onerror" in payloads["event_handler"]
    assert "onload" in payloads["svg_onload"]
    assert payloads["javascript_url"].startswith("javascript:")


@pytest.mark.asyncio
async def test_check_requires_token() -> None:
    MODULE._JS_PROOF_SESSIONS.clear()
    toolset = MODULE.BrowserJsProof()

    with pytest.raises(RuntimeError, match="No proof token"):
        await toolset.agent_browser_check_js_execution_proof(proof_id="missing")
