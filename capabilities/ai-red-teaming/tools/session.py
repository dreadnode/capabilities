"""Session context for iterative AI red teaming.

Persists attack context (target, goal, results, best prompts) across
tool calls so the agent can support iterative refinement workflows
like "try a different attack on the same target" or "show me the
best scoring prompt from the last run".
"""

from __future__ import annotations

import json
import os
import typing as t
from datetime import datetime, timezone
from pathlib import Path

from dreadnode.agents.tools import tool

SESSION_PATH = Path(
    os.environ.get(
        "AIRT_SESSION_PATH",
        os.path.expanduser("~/workspace/airt/.session_context.json"),
    )
)


def _load() -> dict:
    if SESSION_PATH.exists():
        try:
            return json.loads(SESSION_PATH.read_text())
        except Exception:
            return {}
    return {}


def _save(data: dict) -> None:
    SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    SESSION_PATH.write_text(json.dumps(data, indent=2))


@tool
def save_session_context(
    target_model: t.Annotated[str, "Target model or endpoint being tested"],
    goal: t.Annotated[str, "Attack goal/objective"],
    attack_type: t.Annotated[str, "Last attack type used"] = "",
    attacker_model: t.Annotated[str, "Attacker model used"] = "",
    evaluator_model: t.Annotated[str, "Evaluator/judge model used"] = "",
    transforms: t.Annotated[list[str] | None, "Transforms applied"] = None,
    assessment_name: t.Annotated[str, "Assessment name"] = "",
    best_score: t.Annotated[float | None, "Best ASR or score achieved"] = None,
    best_prompt: t.Annotated[str | None, "Best scoring adversarial prompt"] = None,
    notes: t.Annotated[str, "Any observations or notes"] = "",
) -> str:
    """Save the current attack context for iterative refinement.

    Persists target, goal, models, and results so subsequent attacks
    can reference them. Call this after each attack completes to
    build up the session history.
    """
    session = _load()

    # Update current context
    session["current"] = {
        "target_model": target_model,
        "goal": goal,
        "attack_type": attack_type,
        "attacker_model": attacker_model,
        "evaluator_model": evaluator_model,
        "transforms": transforms or [],
        "assessment_name": assessment_name,
        "best_score": best_score,
        "best_prompt": best_prompt,
        "notes": notes,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Append to history (keep last 20 entries)
    history = session.get("history", [])
    history.append(
        {
            "attack_type": attack_type,
            "target_model": target_model,
            "goal": goal,
            "best_score": best_score,
            "transforms": transforms or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    session["history"] = history[-20:]

    _save(session)
    return "Session context saved. Target: {}, Goal: {}, Last attack: {}".format(target_model, goal[:60], attack_type)


@tool
def get_session_context() -> str:
    """Retrieve the current session context for iterative refinement.

    Returns the last target, goal, models, transforms, and results
    so you can build on previous attacks without the user re-specifying
    everything. Use this at the start of follow-up commands like
    "try another attack" or "add transforms".
    """
    session = _load()
    if not session or "current" not in session:
        return "No session context found. Run an attack first to establish context."

    current = session["current"]
    lines = [
        "Current Session Context:",
        "  Target: {}".format(current.get("target_model", "not set")),
        "  Goal: {}".format(current.get("goal", "not set")),
        "  Last attack: {}".format(current.get("attack_type", "none")),
        "  Attacker model: {}".format(current.get("attacker_model", "not set")),
        "  Evaluator model: {}".format(current.get("evaluator_model", "not set")),
        "  Transforms: {}".format(", ".join(current.get("transforms", [])) or "none"),
        "  Assessment: {}".format(current.get("assessment_name", "not set")),
    ]

    if current.get("best_score") is not None:
        lines.append("  Best score: {}".format(current["best_score"]))
    if current.get("best_prompt"):
        # Truncate long prompts
        prompt = current["best_prompt"]
        if len(prompt) > 200:
            prompt = prompt[:200] + "..."
        lines.append("  Best prompt: {}".format(prompt))
    if current.get("notes"):
        lines.append("  Notes: {}".format(current["notes"]))

    # Show history summary
    history = session.get("history", [])
    if len(history) > 1:
        lines.append("")
        lines.append("Attack History ({} runs):".format(len(history)))
        for h in history[-5:]:  # Show last 5
            score_str = "ASR={}%".format(h["best_score"]) if h.get("best_score") is not None else "no score"
            tx_str = "+{}".format(",".join(h["transforms"])) if h.get("transforms") else ""
            lines.append(
                "  - {} {}: {} ({})".format(h.get("attack_type", "?"), tx_str, h.get("goal", "")[:40], score_str)
            )

    return "\n".join(lines)


@tool
def clear_session_context() -> str:
    """Clear the session context to start fresh.

    Removes all saved context and history. Use when switching
    to a completely different target or assessment.
    """
    if SESSION_PATH.exists():
        SESSION_PATH.unlink()
    return "Session context cleared."
