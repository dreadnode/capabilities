"""Assessment tracking for AI red team engagements.

Provides structured tracking of planned vs completed attacks with
ASR/risk metrics and progress summaries.
"""

from __future__ import annotations

import json
import os
import typing as t
from datetime import datetime, timezone
from pathlib import Path

from dreadnode.agents.tools import tool

ASSESSMENT_PATH = Path(
    os.environ.get("DREADAIRT_ASSESSMENT_PATH", "/tmp/dreadairt_assessment.json")
)


def _load() -> dict:
    if ASSESSMENT_PATH.exists():
        return json.loads(ASSESSMENT_PATH.read_text())
    return {}


def _save(data: dict) -> None:
    ASSESSMENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ASSESSMENT_PATH.write_text(json.dumps(data, indent=2))


@tool
def register_assessment(
    name: t.Annotated[str, "Assessment name"],
    target: t.Annotated[str, "Target model or system being tested"],
    planned_attacks: t.Annotated[list[str], "List of planned attack names"],
    goal: t.Annotated[str, "Overall assessment goal/objective"] = "",
) -> str:
    """Register a new red team assessment with planned attacks.

    Creates a fresh assessment record tracking which attacks are planned
    and completed. Overwrites any existing assessment.
    """
    data = {
        "name": name,
        "target": target,
        "goal": goal,
        "planned_attacks": planned_attacks,
        "completed_attacks": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "in_progress",
    }
    _save(data)
    return (
        f"Assessment '{name}' registered with {len(planned_attacks)} "
        f"planned attacks targeting {target}."
    )


@tool
def get_assessment_status() -> str:
    """Get current assessment progress with completed attack metrics.

    Shows planned vs completed attacks and ASR/risk scores for each.
    """
    data = _load()
    if not data:
        return "No assessment registered. Use register_assessment first."

    planned = set(data.get("planned_attacks", []))
    completed = data.get("completed_attacks", [])
    completed_names = {c["attack_name"] for c in completed}
    remaining = planned - completed_names

    lines = [
        f"Assessment: {data['name']}",
        f"Target: {data['target']}",
        f"Goal: {data.get('goal', 'not specified')}",
        f"Status: {data.get('status', 'unknown')}",
        f"Progress: {len(completed)}/{len(planned)} attacks completed",
        "",
    ]

    if completed:
        lines.append("Completed:")
        for c in completed:
            line = (
                f"  - {c['attack_name']}: ASR={c.get('asr', 'N/A')}%, "
                f"Risk={c.get('risk_score', 'N/A')}/10"
            )
            if c.get("notes"):
                line += f" — {c['notes']}"
            lines.append(line)

    if remaining:
        lines.append(f"\nRemaining: {', '.join(sorted(remaining))}")

    return "\n".join(lines)


@tool
def update_assessment_status(
    attack_name: t.Annotated[str, "Name of the completed attack"],
    status: t.Annotated[str, "Attack status (e.g., 'completed', 'failed', 'skipped')"] = "completed",
    asr: t.Annotated[float | None, "Attack success rate as percentage (0-100)"] = None,
    risk_score: t.Annotated[float | None, "Risk score (0-10)"] = None,
    notes: t.Annotated[str, "Brief notes on findings"] = "",
) -> str:
    """Record completion of an attack with its metrics.

    Updates the assessment with ASR and risk score for a completed attack.
    Replaces any existing entry for the same attack_name.
    """
    data = _load()
    if not data:
        return "No assessment registered. Use register_assessment first."

    entry = {
        "attack_name": attack_name,
        "status": status,
        "asr": asr,
        "risk_score": risk_score,
        "notes": notes,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Replace existing entry for same attack (dedup), or append
    completed = data.get("completed_attacks", [])
    completed = [c for c in completed if c["attack_name"] != attack_name]
    completed.append(entry)
    data["completed_attacks"] = completed

    # Auto-complete assessment if all planned attacks are done
    planned = data.get("planned_attacks", [])
    completed_names = {c["attack_name"] for c in completed}
    if all(a in completed_names for a in planned):
        data["status"] = "completed"

    _save(data)

    total = len(planned)
    done = len(completed)
    asr_str = f" (ASR={asr}%)" if asr is not None else ""
    return f"Recorded {attack_name}: {status}{asr_str}. Progress: {done}/{total}."
