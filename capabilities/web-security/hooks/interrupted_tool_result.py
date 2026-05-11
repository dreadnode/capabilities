"""Recover from provider interruption sentinels after tool execution."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from dreadnode.agents.events import AgentEnd, GenerationStep, ToolEnd, ToolError
from dreadnode.agents.reactions import Continue
from dreadnode.core.hook import hook

_INTERRUPTION_SENTINEL = re.compile(
    r"^\[?\s*response interrupted by a tool call result\.\s*\]?$",
    re.IGNORECASE,
)
_MAX_RECOVERIES_PER_AGENT = 2
_MAX_SUMMARY_CHARS = 600


@dataclass(slots=True)
class _ToolOutcome:
    tool_name: str
    summary: str


@dataclass(slots=True)
class _AgentState:
    last_tool_outcome: _ToolOutcome | None = None
    recoveries: int = 0


_STATE_LOCK = asyncio.Lock()
_AGENT_STATE: dict[str, _AgentState] = {}


def _normalize_text(value: object | None) -> str | None:
    """Collapse tool output into a short, stable single-line summary."""
    if value is None:
        return None

    text = " ".join(str(value).split()).strip()
    if not text:
        return None
    if len(text) <= _MAX_SUMMARY_CHARS:
        return text
    return f"{text[:_MAX_SUMMARY_CHARS - 3].rstrip()}..."


def _extract_assistant_text(event: GenerationStep) -> str | None:
    """Return the last assistant text only when it is a plain text turn."""
    if not event.messages:
        return None

    last_message = event.messages[-1]
    if getattr(last_message, "role", None) != "assistant":
        return None
    if getattr(last_message, "tool_calls", None):
        return None

    return _normalize_text(getattr(last_message, "content", None))


def _is_interruption_sentinel(text: str | None) -> bool:
    """Match the provider sentinel exactly to avoid false positives."""
    if text is None:
        return False
    return _INTERRUPTION_SENTINEL.fullmatch(text) is not None


def _tool_end_summary(event: ToolEnd) -> str:
    """Describe the last completed tool call for recovery feedback."""
    if event.error:
        detail = _normalize_text(event.error)
        if detail:
            return f"{event.tool_call.name} returned an error: {detail}"
        return f"{event.tool_call.name} returned an error."

    detail = _normalize_text(event.result)
    if detail:
        return f"{event.tool_call.name} returned: {detail}"
    return f"{event.tool_call.name} completed without output."


def _tool_error_summary(event: ToolError) -> str:
    """Describe an uncaught tool exception for recovery feedback."""
    detail = _normalize_text(event.error)
    if detail:
        return f"{event.tool_call.name} raised an error: {detail}"
    return f"{event.tool_call.name} raised an error."


def _recovery_feedback(state: _AgentState) -> str:
    """Build the corrective prompt appended after the sentinel turn."""
    base = (
        "Your last response was a transport artifact "
        "(`[Response interrupted by a tool call result.]`), not a valid assistant turn. "
        "Ignore it."
    )
    if state.last_tool_outcome is None:
        return f"{base} Continue from the current conversation state and take the next best action."
    return (
        f"{base} The last tool outcome was: {state.last_tool_outcome.summary} "
        "Continue from that result and take the next best action."
    )


@hook(ToolEnd)
async def remember_tool_end(event: ToolEnd) -> None:
    """Remember the most recent tool completion for later recovery."""
    async with _STATE_LOCK:
        state = _AGENT_STATE.setdefault(event.agent_id, _AgentState())
        state.last_tool_outcome = _ToolOutcome(
            tool_name=event.tool_call.name,
            summary=_tool_end_summary(event),
        )


@hook(ToolError)
async def remember_tool_error(event: ToolError) -> None:
    """Remember uncaught tool failures for later recovery."""
    async with _STATE_LOCK:
        state = _AGENT_STATE.setdefault(event.agent_id, _AgentState())
        state.last_tool_outcome = _ToolOutcome(
            tool_name=event.tool_call.name,
            summary=_tool_error_summary(event),
        )


@hook(GenerationStep)
async def recover_interrupted_tool_result(event: GenerationStep) -> Continue | None:
    """Continue the run when the model emits the interruption sentinel."""
    assistant_text = _extract_assistant_text(event)

    async with _STATE_LOCK:
        state = _AGENT_STATE.setdefault(event.agent_id, _AgentState())

        if not _is_interruption_sentinel(assistant_text):
            if assistant_text:
                state.recoveries = 0
            return None

        if state.recoveries >= _MAX_RECOVERIES_PER_AGENT:
            return None

        state.recoveries += 1
        feedback = _recovery_feedback(state)

    return Continue(feedback=feedback)


@hook(AgentEnd)
async def clear_recovery_state(event: AgentEnd) -> None:
    """Drop per-agent recovery state when the run ends."""
    async with _STATE_LOCK:
        _AGENT_STATE.pop(event.agent_id, None)
