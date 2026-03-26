#!/usr/bin/env python3
"""Assessment tracker for AI Red Teaming agent sessions.

Tracks planned and completed attacks against a target, including
ASR scores, risk levels, and notes. State is persisted to a JSON
file so it survives across tool calls.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import os
import sys
import time
from pathlib import Path

STATE_FILE = Path(os.environ.get("AIRT_ASSESSMENT_PATH", "/tmp/airt_assessment.json"))


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def register_assessment(params: dict) -> dict:
    name = params["name"]
    target = params["target"]
    planned_attacks = params["planned_attacks"]
    goal = params.get("goal", "")

    state = {
        "name": name,
        "target": target,
        "goal": goal,
        "planned_attacks": planned_attacks,
        "completed_attacks": [],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "in_progress",
    }
    save_state(state)

    return {
        "result": (
            f"Assessment '{name}' registered.\n"
            f"Target: {target}\n"
            f"Planned attacks: {', '.join(planned_attacks)}\n"
            f"Total: {len(planned_attacks)} attacks"
        )
    }


def get_assessment_status(params: dict) -> dict:
    state = load_state()
    if not state:
        return {"error": "No assessment registered. Use register_assessment first."}

    planned = state.get("planned_attacks", [])
    completed = state.get("completed_attacks", [])
    completed_names = [c["attack_name"] for c in completed]
    remaining = [a for a in planned if a not in completed_names]

    lines = [
        f"Assessment: {state.get('name', 'unnamed')}",
        f"Target: {state.get('target', 'unknown')}",
        f"Goal: {state.get('goal', 'not specified')}",
        f"Status: {state.get('status', 'unknown')}",
        f"Created: {state.get('created_at', 'unknown')}",
        "",
        f"Progress: {len(completed)}/{len(planned)} attacks completed",
        "",
    ]

    if completed:
        lines.append("Completed attacks:")
        for c in completed:
            asr_str = f"ASR={c['asr']:.1%}" if c.get("asr") is not None else "ASR=N/A"
            risk_str = f"Risk={c['risk_score']:.1f}" if c.get("risk_score") is not None else ""
            notes_str = f" — {c['notes']}" if c.get("notes") else ""
            lines.append(f"  - {c['attack_name']} [{c['status']}] {asr_str} {risk_str}{notes_str}")
        lines.append("")

    if remaining:
        lines.append(f"Remaining: {', '.join(remaining)}")

    return {"result": "\n".join(lines)}


def update_assessment_status(params: dict) -> dict:
    state = load_state()
    if not state:
        return {"error": "No assessment registered. Use register_assessment first."}

    attack_name = params["attack_name"]
    status = params.get("status", "completed")
    asr = params.get("asr")
    risk_score = params.get("risk_score")
    notes = params.get("notes", "")

    entry = {
        "attack_name": attack_name,
        "status": status,
        "asr": asr,
        "risk_score": risk_score,
        "notes": notes,
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    completed = state.get("completed_attacks", [])
    # Replace existing entry for same attack, or append
    completed = [c for c in completed if c["attack_name"] != attack_name]
    completed.append(entry)
    state["completed_attacks"] = completed

    # Auto-complete assessment if all planned attacks are done
    planned = state.get("planned_attacks", [])
    completed_names = {c["attack_name"] for c in completed}
    if all(a in completed_names for a in planned):
        state["status"] = "completed"

    save_state(state)

    asr_str = f" (ASR: {asr:.1%})" if asr is not None else ""
    return {"result": f"Updated {attack_name}: {status}{asr_str}"}


METHODS = {
    "register_assessment": register_assessment,
    "get_assessment_status": get_assessment_status,
    "update_assessment_status": update_assessment_status,
}


def main() -> None:
    raw = sys.stdin.read()
    request = json.loads(raw)
    # The capability wrapper sends method="tool" (type discriminator) and name="save_workflow" etc.
    # Use "name" field which contains the actual tool name.
    method = request.get("name", request.get("method", ""))
    params = request.get("parameters", {})

    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": f"Unknown method: {method}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
