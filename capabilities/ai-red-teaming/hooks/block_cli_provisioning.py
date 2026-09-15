"""Structural guardrails: deny shell fallbacks that bypass first-class tools.

The AIRT skills mandate tool-only paths for a few operations - most importantly,
`provisioning-and-lifecycle` and `error-troubleshooting` both say to NEVER run
`dreadnode env ...` in a shell and to use the `provision_environment` /
`teardown_environment` tools instead. Skill prose is advisory; a weaker driver
model can ignore it and fall back to the CLI (ENG-8477).

This module enforces those rules structurally with a small policy table. A
`ToolStart` hook inspects every shell tool call and, when its command matches a
rule, denies the call before it runs and redirects the agent to the correct
tool (via `RetryWithFeedback`, which the runtime turns into a `[POLICY DENIED]`
tool result). Rules are scoped narrowly so legitimate shell and CLI usage
(for example `dn airt run`, which the skills permit) is never affected.

To add a guardrail, append a `_Rule` - one line per policy.
"""

from __future__ import annotations

import json
import re
import typing as t
from dataclasses import dataclass

from dreadnode.agents.events import ToolStart
from dreadnode.agents.reactions import RetryWithFeedback
from dreadnode.core.hook import hook

# Shell-style tools that can execute a CLI command.
_SHELL_TOOLS = frozenset({"bash", "shell", "sh", "python", "python3", "run_command", "execute"})


@dataclass(frozen=True)
class _Rule:
    """A single deny-and-redirect policy for shell tool calls."""

    tools: frozenset[str]
    pattern: re.Pattern[str]
    feedback: str


# NOTE: order matters - the first matching rule wins, so list specific rules
# (provision / teardown) before the generic `dreadnode env` catch-all.
_RULES: tuple[_Rule, ...] = (
    _Rule(
        _SHELL_TOOLS,
        re.compile(r"\b(?:dreadnode|dn)\s+env(?:ironment)?\s+(?:provision|create|up|start|new)\b", re.IGNORECASE),
        "Provisioning an environment through the shell/CLI is not permitted. Use the "
        "`provision_environment` tool instead - it resolves the catalog and credentials for you. "
        "If it is unavailable, STOP and inform the user; do not fall back to the shell.",
    ),
    _Rule(
        _SHELL_TOOLS,
        re.compile(r"\b(?:dreadnode|dn)\s+env(?:ironment)?\s+(?:teardown|delete|destroy|down|stop|rm|remove)\b", re.IGNORECASE),
        "Tearing down an environment through the shell/CLI is not permitted. Use the "
        "`teardown_environment` tool instead. If it is unavailable, STOP and inform the user; "
        "do not fall back to the shell.",
    ),
    _Rule(
        _SHELL_TOOLS,
        re.compile(r"\b(?:dreadnode|dn)\s+env(?:ironment)?\b", re.IGNORECASE),
        "Managing environments through the shell/CLI is not permitted. Use the environment tools "
        "(`provision_environment`, `list_environments`, `teardown_environment`) instead. If they "
        "are unavailable, STOP and inform the user; do not fall back to the shell.",
    ),
)


def _iter_strings(value: t.Any) -> t.Iterator[str]:
    """Yield every string in an arbitrarily nested arguments payload."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _match(tool_name: str, args: t.Any) -> _Rule | None:
    """Return the first rule that denies this tool call, if any."""
    name = tool_name.lower()
    texts = list(_iter_strings(args))
    for rule in _RULES:
        if name in rule.tools and any(rule.pattern.search(text) for text in texts):
            return rule
    return None


@hook(ToolStart)
async def block_cli_provisioning(event: ToolStart) -> RetryWithFeedback | None:
    """Deny shell calls that bypass first-class tools and redirect the agent."""
    raw = event.tool_call.function.arguments
    try:
        args: t.Any = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        args = raw

    rule = _match(event.tool_call.name, args)
    if rule is not None:
        return RetryWithFeedback(feedback=rule.feedback, tool_call_id=event.tool_call.id)

    return None
