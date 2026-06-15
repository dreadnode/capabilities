from __future__ import annotations

import importlib.util
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml


def _install_hook_stubs() -> None:
    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    events = types.ModuleType("dreadnode.agents.events")
    reactions = types.ModuleType("dreadnode.agents.reactions")
    core = types.ModuleType("dreadnode.core")
    hook_module = types.ModuleType("dreadnode.core.hook")

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
        result: str | None = None
        error: str | None = None
        error_type: str | None = None

    @dataclass
    class ToolError:
        agent_id: str
        tool_call: ToolCall
        error: Exception | str

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

    events.AgentEnd = AgentEnd
    events.GenerationStep = GenerationStep
    events.ToolCall = ToolCall
    events.ToolEnd = ToolEnd
    events.ToolError = ToolError
    reactions.Continue = Continue
    hook_module.Hook = Hook
    hook_module.hook = hook

    dreadnode.agents = agents
    dreadnode.core = core
    agents.events = events
    reactions.Message = Message
    core.hook = hook_module

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.events"] = events
    sys.modules["dreadnode.agents.reactions"] = reactions
    sys.modules["dreadnode.core"] = core
    sys.modules["dreadnode.core.hook"] = hook_module


@pytest.fixture
def hook_module():
    _install_hook_stubs()

    module_path = (
        Path(__file__).resolve().parents[1] / "hooks" / "interrupted_tool_result.py"
    )
    module_name = "test_web_security_interrupted_tool_result"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_manifest_wires_hook_file() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "capability.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert manifest["version"] == "1.1.5"
    assert manifest["hooks"] == ["hooks/interrupted_tool_result.py"]


@pytest.mark.asyncio
async def test_recovers_from_interruption_marker_after_tool_end(hook_module) -> None:
    tool_end = sys.modules["dreadnode.agents.events"].ToolEnd(
        agent_id="agent-1",
        tool_call=sys.modules["dreadnode.agents.events"].ToolCall("tc-1", "bash"),
        error="Command failed (1): nmap target",
    )
    await hook_module.remember_tool_end(tool_end)

    generation = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-1",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="[Response interrupted by a tool call result.]",
            )
        ],
        step=2,
    )

    reaction = await hook_module.recover_interrupted_tool_result(generation)

    assert reaction is not None
    assert "transport artifact" in reaction.feedback
    assert (
        "bash returned an error: Command failed (1): nmap target" in reaction.feedback
    )


@pytest.mark.asyncio
async def test_recovers_from_interruption_marker_after_tool_error(hook_module) -> None:
    tool_error = sys.modules["dreadnode.agents.events"].ToolError(
        agent_id="agent-2",
        tool_call=sys.modules["dreadnode.agents.events"].ToolCall("tc-2", "bash"),
        error=RuntimeError("socket hangup"),
    )
    await hook_module.remember_tool_error(tool_error)

    generation = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-2",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="Response interrupted by a tool call result.",
            )
        ],
        step=3,
    )

    reaction = await hook_module.recover_interrupted_tool_result(generation)

    assert reaction is not None
    assert "bash raised an error: socket hangup" in reaction.feedback


@pytest.mark.asyncio
async def test_does_not_fire_on_normal_text_or_embedded_phrase(hook_module) -> None:
    normal = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-3",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="I found a login form and will test password reset next.",
            )
        ],
        step=1,
    )
    embedded = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-3",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="The UI literally showed [Response interrupted by a tool call result.] once.",
            )
        ],
        step=2,
    )

    assert await hook_module.recover_interrupted_tool_result(normal) is None
    assert await hook_module.recover_interrupted_tool_result(embedded) is None


@pytest.mark.asyncio
async def test_retry_budget_resets_after_valid_turn_and_state_cleans_up(
    hook_module,
) -> None:
    tool_end = sys.modules["dreadnode.agents.events"].ToolEnd(
        agent_id="agent-4",
        tool_call=sys.modules["dreadnode.agents.events"].ToolCall("tc-4", "bash"),
        result="80/tcp open http",
    )
    await hook_module.remember_tool_end(tool_end)

    sentinel = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-4",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="[Response interrupted by a tool call result.]",
            )
        ],
        step=1,
    )

    assert await hook_module.recover_interrupted_tool_result(sentinel) is not None
    assert await hook_module.recover_interrupted_tool_result(sentinel) is not None
    assert await hook_module.recover_interrupted_tool_result(sentinel) is None

    valid_turn = sys.modules["dreadnode.agents.events"].GenerationStep(
        agent_id="agent-4",
        messages=[
            sys.modules["dreadnode.agents.reactions"].Message(
                role="assistant",
                content="Port 80 is open. I will fetch the homepage next.",
            )
        ],
        step=2,
    )
    assert await hook_module.recover_interrupted_tool_result(valid_turn) is None
    assert await hook_module.recover_interrupted_tool_result(sentinel) is not None

    await hook_module.clear_recovery_state(
        sys.modules["dreadnode.agents.events"].AgentEnd(agent_id="agent-4")
    )
    assert "agent-4" not in hook_module._AGENT_STATE
