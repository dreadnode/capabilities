"""Goal category loader for AI red team assessments.

Provides access to bundled harm category goals organized by
safety/security/agentic tiers. Goal text is never exposed to
the agent — only opaque IDs and category metadata.
"""

from __future__ import annotations

import csv
import typing as t
from collections import defaultdict
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

GOALS_CSV = Path(__file__).parent.parent / "data" / "goals.csv"

SUB_CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    # Safety tier
    "cybersecurity": "Cybersecurity",
    "weapons": "Weapons",
    "financial_crimes": "Financial Crimes",
    "identity_theft": "Identity Theft",
    "violence": "Violence",
    "hate_speech": "Hate Speech",
    "misinformation": "Misinformation",
    "self_harm": "Self-Harm",
    "bias_fairness": "Bias & Fairness",
    "content_policy": "Content Policy",
    # Security tier
    "credential_extraction": "Credential Extraction",
    "pii_extraction": "PII Extraction",
    "system_prompt_leak": "System Prompt Leak",
    "tool_misuse": "Tool Misuse",
    "refusal_bypass": "Refusal Bypass",
    # Agentic tier
    "agentic_tool_misuse": "Agentic Tool Misuse",
    "agentic_data_exfil": "Agentic Data Exfiltration",
    "agentic_privilege_escalation": "Agentic Privilege Escalation",
    "agentic_goal_hijacking": "Agentic Goal Hijacking",
    "agentic_prompt_extraction": "Agentic Prompt Extraction",
    "agentic_memory_poisoning": "Agentic Memory Poisoning",
    "agentic_code_execution": "Agentic Code Execution",
    "agentic_supply_chain": "Agentic Supply Chain",
    "agentic_cascading_failure": "Agentic Cascading Failure",
    "agentic_trust_exploitation": "Agentic Trust Exploitation",
}


def _load_goals() -> list[dict]:
    """Load goals from CSV, returning list of row dicts.

    Returns an empty list on any read/parse error so callers can surface a
    clean "dataset not found" message instead of raising.
    """
    try:
        if not GOALS_CSV.exists():
            return []
        with open(GOALS_CSV, newline="") as f:
            return list(csv.DictReader(f))
    except (OSError, csv.Error, ValueError):
        return []


@safe_tool
def list_goal_categories() -> str:
    """List available harm categories with goal counts.

    Returns the category hierarchy (safety/security/agentic tiers)
    with sub-category names and how many goals each contains.
    Goal text is never shown — only counts and category slugs.
    """
    goals = _load_goals()
    if not goals:
        return "Error: Goals dataset not found."

    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in goals:
        cat = row.get("category", "unknown")
        sub = row.get("sub_category", "unknown")
        counts[cat][sub] += 1

    lines = [f"Goal Categories ({len(goals)} total goals):", ""]
    for cat in sorted(counts):
        cat_total = sum(counts[cat].values())
        lines.append(f"## {cat.title()} ({cat_total} goals)")
        for sub in sorted(counts[cat]):
            display = SUB_CATEGORY_DISPLAY_NAMES.get(sub, sub)
            lines.append(f"  - {sub}: {display} ({counts[cat][sub]} goals)")
        lines.append("")

    return "\n".join(lines)


@safe_tool
def get_category_goals(
    sub_categories: t.Annotated[
        list[str],
        "Sub-category slugs to filter (e.g., ['cybersecurity', 'credential_extraction']) "
        "or ['all'] for every sub-category",
    ],
    sample_size: t.Annotated[
        int,
        "Max goals to return per sub-category (0 = all)",
    ] = 0,
) -> str:
    """Get goal IDs and metadata for specific sub-categories.

    Returns goal IDs, sub-categories, and compliance references.
    Goal text is NOT included — IDs are opaque references for use with
    generate_category_attack.
    """
    goals = _load_goals()
    if not goals:
        return "Error: Goals dataset not found."

    valid_subs = {row.get("sub_category") for row in goals}

    # "all" returns every sub-category
    if sub_categories == ["all"]:
        sub_categories = sorted(valid_subs)
    else:
        invalid = set(sub_categories) - valid_subs
        if invalid:
            return (
                f"Error: Unknown sub-categories: {', '.join(sorted(invalid))}. "
                f"Valid: {', '.join(sorted(valid_subs))}"
            )

    filtered = [g for g in goals if g.get("sub_category") in sub_categories]
    if not filtered:
        return "No goals found for the specified sub-categories."

    # Apply per-category sampling if requested
    if sample_size > 0:
        import random

        by_sub: dict[str, list[dict]] = defaultdict(list)
        for g in filtered:
            by_sub[g.get("sub_category", "unknown")].append(g)
        sampled: list[dict] = []
        for sub in sorted(by_sub):
            pool = by_sub[sub]
            sampled.extend(random.sample(pool, min(sample_size, len(pool))))
        filtered = sampled

    lines = [f"Found {len(filtered)} goals:"]
    for g in filtered:
        lines.append(f"  - {g['id']}: [{g['sub_category']}] " f"refs={g.get('compliance_refs', 'N/A')}")

    return "\n".join(lines)
