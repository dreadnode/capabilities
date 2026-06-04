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

# Load the shared safe_tool wrapper by file path. Capability tool files are
# loaded as flat modules (no parent package), so relative imports do not work.
import importlib.util as _ilu
from pathlib import Path as _Path
_errors_path = _Path(__file__).resolve().parent / "errors.py"
_spec = _ilu.spec_from_file_location("airt_tools_errors", _errors_path)
_errors_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_errors_mod)
safe_tool = _errors_mod.safe_tool

ASSESSMENT_PATH = Path(os.environ.get("AIRT_ASSESSMENT_PATH", "/tmp/airt_assessment.json"))


def _load() -> dict:
    # Tolerate a missing or corrupt assessment file: treat as "no assessment"
    # rather than raising, so the calling tool can respond cleanly.
    try:
        if ASSESSMENT_PATH.exists():
            return json.loads(ASSESSMENT_PATH.read_text())
    except (OSError, ValueError):
        pass
    return {}


def _save(data: dict) -> None:
    ASSESSMENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ASSESSMENT_PATH.write_text(json.dumps(data, indent=2))


@safe_tool
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
    return f"Assessment '{name}' registered with {len(planned_attacks)} " f"planned attacks targeting {target}."


@safe_tool
def get_assessment_status() -> str:
    """Get current assessment progress with completed attack metrics.

    Shows planned vs completed attacks with the attack success rate (ASR,
    the success probability) for each.
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
            # ASR is the attack success probability (how often the attack
            # worked). Shown as a percentage; that *is* the probability metric.
            asr = c.get("asr")
            asr_str = f"{asr}%" if asr is not None else "N/A"
            line = f"  - {c['attack_name']}: success rate (ASR)={asr_str}"
            if c.get("notes"):
                line += f" — {c['notes']}"
            lines.append(line)

    if remaining:
        lines.append(f"\nRemaining: {', '.join(sorted(remaining))}")

    return "\n".join(lines)


@safe_tool
def update_assessment_status(
    attack_name: t.Annotated[str, "Name of the completed attack"],
    status: t.Annotated[str, "Attack status (e.g., 'completed', 'failed', 'skipped')"] = "completed",
    asr: t.Annotated[float | None, "Attack success rate as percentage (0-100)"] = None,
    risk_score: t.Annotated[
        float | None,
        "Optional severity-weighted risk (0-10), stored for platform parity but "
        "not shown to users. The headline metric is ASR (success probability).",
    ] = None,
    notes: t.Annotated[str, "Brief notes on findings"] = "",
) -> str:
    """Record completion of an attack with its metrics.

    The headline metric is ASR — the attack success rate / success
    probability. ``risk_score`` is still accepted and stored for platform
    parity but is not surfaced in user-facing output.
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
