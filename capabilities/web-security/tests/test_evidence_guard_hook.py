from __future__ import annotations

import importlib.util
import json
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import pytest


def _install_hook_stubs() -> list[tuple[str, object]]:
    logs: list[tuple[str, object]] = []
    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    events = types.ModuleType("dreadnode.agents.events")
    reactions = types.ModuleType("dreadnode.agents.reactions")
    core = types.ModuleType("dreadnode.core")
    hook_module = types.ModuleType("dreadnode.core.hook")

    def log_output(name: str, value: object, **_: object) -> None:
        logs.append((name, value))

    @dataclass
    class FunctionCall:
        name: str
        arguments: str = "{}"

    @dataclass
    class ToolCall:
        id: str
        name: str
        function: FunctionCall = field(init=False)

        def __post_init__(self) -> None:
            self.function = FunctionCall(name=self.name)

    @dataclass
    class Message:
        role: str
        content: str | None = None
        tool_calls: list[object] | None = None

    @dataclass
    class AgentEnd:
        agent_id: str

    @dataclass
    class ToolEnd:
        agent_id: str
        tool_call: ToolCall
        result: object | None = None
        error: str | None = None
        error_type: str | None = None

    @dataclass
    class GenerationStep:
        agent_id: str
        messages: list[Message]
        step: int = 1

    @dataclass
    class Continue(Exception):
        feedback: str | None = None

    class Hook:
        def __init__(self, func, event_type) -> None:
            self.func = func
            self.event_type = event_type
            self.__name__ = getattr(func, "__name__", "hook")

        def __call__(self, event):
            if not isinstance(event, self.event_type):
                return None
            return self.func(event)

    def hook(event_type):
        def decorator(fn):
            return Hook(fn, event_type)

        return decorator

    dreadnode.agents = agents
    dreadnode.core = core
    dreadnode.log_output = log_output
    agents.events = events
    core.hook = hook_module
    events.AgentEnd = AgentEnd
    events.GenerationStep = GenerationStep
    events.ToolCall = ToolCall
    events.ToolEnd = ToolEnd
    reactions.Continue = Continue
    reactions.Message = Message
    hook_module.Hook = Hook
    hook_module.hook = hook

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.events"] = events
    sys.modules["dreadnode.agents.reactions"] = reactions
    sys.modules["dreadnode.core"] = core
    sys.modules["dreadnode.core.hook"] = hook_module
    return logs


@pytest.fixture
def hook_module():
    logs = _install_hook_stubs()
    module_path = Path(__file__).resolve().parents[1] / "hooks" / "evidence_guard.py"
    module_name = "test_web_security_evidence_guard"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module._TEST_LOGS = logs
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _tool_end(name: str, result: object, agent_id: str = "agent-1"):
    events = sys.modules["dreadnode.agents.events"]
    return events.ToolEnd(
        agent_id=agent_id,
        tool_call=events.ToolCall("tc-1", name),
        result=result,
    )


def _generation(text: str, agent_id: str = "agent-1"):
    events = sys.modules["dreadnode.agents.events"]
    reactions = sys.modules["dreadnode.agents.reactions"]
    return events.GenerationStep(
        agent_id=agent_id,
        messages=[reactions.Message(role="assistant", content=text)],
    )


@pytest.mark.asyncio
async def test_challenges_confirmed_xss_claim_without_browser_js_proof(hook_module):
    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The XSS is confirmed and the payload executed.")
    )

    assert reaction is not None
    assert "browser_js_execution proof" in reaction.feedback
    assert "agent_browser_start_js_execution_proof" in reaction.feedback


@pytest.mark.asyncio
async def test_issued_browser_js_proof_still_requires_confirmed_check(hook_module):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__agent_browser_start_js_execution_proof",
            {
                "kind": "browser_js_execution",
                "status": "armed",
                "proof_id": "case-1",
                "url": "https://target.test/search",
            },
        )
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("Confirmed XSS, JavaScript execution succeeded.")
    )

    assert reaction is not None
    assert "agent_browser_check_js_execution_proof" in reaction.feedback
    assert "verified: true" in reaction.feedback


@pytest.mark.asyncio
async def test_confirmed_browser_js_proof_allows_xss_claim(hook_module):
    result = {
        "kind": "browser_js_execution",
        "verified": True,
        "verdict": "CONFIRMED",
        "confidence": "high",
        "proof_id": "case-1",
        "url": "https://target.test/search?q=xss",
        "evidence": [{"channel": "proof-function", "matched": True}],
    }
    await hook_module.record_web_security_evidence(
        _tool_end("web_security__agent_browser_check_js_execution_proof", result)
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The reflected XSS is confirmed and executed.")
    )

    assert reaction is None
    state = hook_module._AGENT_STATE["agent-1"]
    assert state.has_confirmed("browser_js_execution") is True


@pytest.mark.asyncio
async def test_structured_browser_js_proof_from_arbitrary_tool_allows_xss_claim(
    hook_module,
):
    result = {
        "kind": "browser_js_execution",
        "verified": True,
        "verdict": "CONFIRMED",
        "confidence": "high",
        "reason": "A payload-controlled token was observed from browser JavaScript execution.",
        "evidence": [{"channel": "localStorage", "matched": True}],
    }
    await hook_module.record_web_security_evidence(
        _tool_end("web_security__future_proof_checker", result)
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("Confirmed XSS, JavaScript execution succeeded.")
    )

    assert reaction is None
    assert hook_module._AGENT_STATE["agent-1"].has_confirmed("browser_js_execution")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claim",
    [
        "The reflected XSS is confirmed and executed.",
        "The stored XSS is confirmed and executed.",
        "The DOM XSS is confirmed and executed.",
        "The mutation XSS is confirmed and executed.",
    ],
)
async def test_browser_local_xss_classes_use_browser_js_execution_proof(
    hook_module,
    claim: str,
):
    result = {
        "kind": "browser_js_execution",
        "verified": True,
        "verdict": "CONFIRMED",
        "confidence": "high",
        "reason": "A payload-controlled token was observed from browser JavaScript execution.",
        "evidence": [{"channel": "localStorage", "value": "proof-token"}],
    }
    await hook_module.record_web_security_evidence(
        _tool_end("web_security__agent_browser_check_js_execution_proof", result)
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(_generation(claim))

    assert reaction is None


@pytest.mark.asyncio
async def test_blind_xss_claim_requires_network_callback_not_browser_local_proof(
    hook_module,
):
    browser_result = {
        "kind": "browser_js_execution",
        "verified": True,
        "verdict": "CONFIRMED",
        "confidence": "high",
        "evidence": [{"channel": "localStorage", "value": "proof-token"}],
    }
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__agent_browser_check_js_execution_proof", browser_result
        )
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The blind XSS is confirmed via callback.")
    )

    assert reaction is not None
    assert "network_callback proof" in reaction.feedback
    assert "check_callbacks" in reaction.feedback


@pytest.mark.asyncio
async def test_network_callback_proof_allows_blind_xss_claim(hook_module):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__check_callbacks",
            "Received 1 callback interaction:\n  1. [now] GET /blind-xss from 10.0.0.1",
        )
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The blind XSS is confirmed via out-of-band callback.")
    )

    assert reaction is None
    assert hook_module._AGENT_STATE["agent-1"].has_confirmed("network_callback")


@pytest.mark.asyncio
async def test_screenshot_is_supporting_evidence_not_xss_proof(hook_module):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__log_image_output",
            {"kind": "image", "path": "/tmp/xss.png", "name": "xss_execution"},
        )
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The XSS is verified and vulnerable.")
    )

    assert reaction is not None
    assert "screenshots as supporting evidence" in reaction.feedback
    state = hook_module._AGENT_STATE["agent-1"]
    assert state.has_confirmed("browser_js_execution") is False


@pytest.mark.asyncio
async def test_callback_issue_and_observation_are_distinct(hook_module):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__get_callback_url",
            "https://webhook.site/token\n\nProvider: webhook_site. Inject this URL.",
        )
    )

    ssrf_claim = _generation("The SSRF is confirmed and triggered.")
    assert await hook_module.challenge_unverified_exploit_claim(ssrf_claim) is not None

    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__check_callbacks",
            "Received 1 callback interactions:\n  1. [now] GET / from 10.0.0.1",
        )
    )

    assert await hook_module.challenge_unverified_exploit_claim(ssrf_claim) is None


@pytest.mark.asyncio
async def test_structured_network_callback_from_arbitrary_tool_allows_ssrf_claim(
    hook_module,
):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__future_callback_checker",
            {
                "kind": "network_callback",
                "verified": True,
                "verdict": "CONFIRMED",
                "url": "https://callback.test/proof",
            },
        )
    )

    reaction = await hook_module.challenge_unverified_exploit_claim(
        _generation("The SSRF is confirmed and triggered.")
    )

    assert reaction is None


@pytest.mark.asyncio
async def test_json_string_tool_result_is_recorded_and_logged(hook_module):
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__agent_browser_check_js_execution_proof",
            json.dumps(
                {
                    "kind": "browser_js_execution",
                    "verified": True,
                    "verdict": "CONFIRMED",
                    "proof_id": "case-1",
                }
            ),
        )
    )

    assert hook_module._AGENT_STATE["agent-1"].has_confirmed("browser_js_execution")
    assert any(name == "web_security_evidence" for name, _ in hook_module._TEST_LOGS)


@pytest.mark.asyncio
async def test_agent_end_logs_summary_and_clears_state(hook_module):
    events = sys.modules["dreadnode.agents.events"]
    await hook_module.record_web_security_evidence(
        _tool_end(
            "web_security__check_callbacks", "No callback interactions received yet."
        )
    )

    await hook_module.clear_evidence_state(events.AgentEnd(agent_id="agent-1"))

    assert "agent-1" not in hook_module._AGENT_STATE
    assert any(
        name == "web_security_evidence_summary" for name, _ in hook_module._TEST_LOGS
    )
