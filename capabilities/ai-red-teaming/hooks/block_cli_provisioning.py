"""Structural guardrail: deny environment provisioning through the shell.

The `provisioning-and-lifecycle` skill instructs the agent to provision only via
the `provision_environment` tool and to NEVER run `dreadnode env ...` in a shell.
Skill prose is advisory - a weaker driver model can ignore it and fall back to
the CLI (ENG-8477). This hook enforces the rule structurally: if the agent tries
to provision an environment through a shell tool, the call is denied before it
runs and the agent is told to use `provision_environment` (or stop and inform
the user).
"""

from __future__ import annotations

import json
import re
import typing as t

from dreadnode.agents.events import ToolStart
from dreadnode.agents.reactions import RetryWithFeedback
from dreadnode.core.hook import hook

# Shell-style tools that can execute a CLI command.
_SHELL_TOOLS = {"bash", "shell", "sh", "python", "python3", "run_command", "execute"}

# `dreadnode env ...` / `dn env ...` / `dreadnode environment ...` in a shell.
# Matches the exact pattern the skill forbids without touching other CLI usage.
_CLI_PROVISION = re.compile(r"\b(?:dreadnode|dn)\s+env(?:ironment)?\b", re.IGNORECASE)

_FEEDBACK = (
    "Provisioning an environment through the shell/CLI is not permitted. "
    "Use the `provision_environment` tool instead - it resolves the catalog and "
    "credentials for you. If `provision_environment` is unavailable, STOP and "
    "inform the user; do not fall back to the shell."
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


@hook(ToolStart)
async def block_cli_provisioning(event: ToolStart) -> RetryWithFeedback | None:
    """Deny shell-based environment provisioning and redirect to the tool."""
    if event.tool_call.name.lower() not in _SHELL_TOOLS:
        return None

    raw = event.tool_call.function.arguments
    try:
        args: t.Any = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        args = raw

    if any(_CLI_PROVISION.search(text) for text in _iter_strings(args)):
        return RetryWithFeedback(feedback=_FEEDBACK, tool_call_id=event.tool_call.id)

    return None
