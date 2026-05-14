#!/usr/bin/env python3
"""Goal loader — list and filter goals from the bundled CSV dataset.

Returns only metadata (category, sub-category names, goal counts, goal IDs)
— never goal text. The orchestrating agent must never see goal content; it
works with opaque IDs and sub-category slugs only.

CSV columns: id, category, sub_category, goal, target, sdk_scorer, compliance_refs

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

# ── Data path ─────────────────────────────────────────────────────────────────

GOALS_CSV = Path(__file__).parent.parent / "data" / "goals.csv"

# ── Sub-category display names ────────────────────────────────────────────────

SUB_CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    # Safety tier
    "cybersecurity": "Cybersecurity & Hacking",
    "weapons": "Weapons & Explosives",
    "financial_crimes": "Financial Crimes",
    "identity_theft": "Identity Theft & Privacy",
    "violence": "Violence & Physical Harm",
    "hate_speech": "Hate Speech & Discrimination",
    "misinformation": "Misinformation & Manipulation",
    "self_harm": "Self-Harm & Suicide",
    "bias_fairness": "Bias & Fairness",
    "content_policy": "Content Policy Violations",
    # Security tier
    "credential_extraction": "Credential & Secret Extraction",
    "pii_extraction": "PII Extraction & Privacy",
    "system_prompt_leak": "System Prompt Leakage",
    "tool_misuse": "Tool & Agent Misuse",
    "refusal_bypass": "Refusal Bypass & Jailbreaking",
    # Agentic tier (OWASP Agentic Top 10)
    "agentic_tool_misuse": "Agentic Tool Misuse (ASI02)",
    "agentic_data_exfil": "Agentic Data Exfiltration (ASI02)",
    "agentic_privilege_escalation": "Agentic Privilege Escalation (ASI03)",
    "agentic_goal_hijacking": "Agentic Goal Hijacking (ASI01)",
    "agentic_prompt_extraction": "Agentic Prompt Extraction (ASI07)",
    "agentic_memory_poisoning": "Agentic Memory Poisoning (ASI06)",
    "agentic_code_execution": "Agentic Code Execution (ASI05)",
    "agentic_supply_chain": "Agentic Supply Chain (ASI04)",
    "agentic_cascading_failure": "Agentic Cascading Failure (ASI08)",
    "agentic_trust_exploitation": "Agentic Trust Exploitation (ASI09)",
}


# ── CSV loading ───────────────────────────────────────────────────────────────


def _load_goals() -> list[dict[str, str]]:
    """Load all goals from the bundled CSV."""
    if not GOALS_CSV.exists():
        raise FileNotFoundError(f"Goals CSV not found at {GOALS_CSV}")
    with open(GOALS_CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ── Tool functions ────────────────────────────────────────────────────────────


def list_categories(params: dict) -> dict:
    """List available categories and sub-categories with goal counts.

    Returns hierarchy: category (safety/security) → sub-categories with counts.
    No goal text in output.
    """
    goals = _load_goals()

    # Count goals per sub-category, grouped by category
    cat_sub_counts: dict[str, dict[str, int]] = {}
    for row in goals:
        cat = row["category"]
        sub = row["sub_category"]
        if cat not in cat_sub_counts:
            cat_sub_counts[cat] = {}
        cat_sub_counts[cat][sub] = cat_sub_counts[cat].get(sub, 0) + 1

    categories = []
    all_sub_categories = []
    for cat in sorted(cat_sub_counts.keys()):
        subs = []
        for slug in sorted(cat_sub_counts[cat].keys()):
            sub_entry = {
                "slug": slug,
                "name": SUB_CATEGORY_DISPLAY_NAMES.get(slug, slug),
                "count": cat_sub_counts[cat][slug],
            }
            subs.append(sub_entry)
            all_sub_categories.append(slug)

        categories.append(
            {
                "category": cat,
                "sub_categories": subs,
                "total_goals": sum(s["count"] for s in subs),
            }
        )

    return {
        "result": {
            "categories": categories,
            "total_goals": len(goals),
            "available_sub_categories": all_sub_categories,
        }
    }


def get_category_goals(params: dict) -> dict:
    """Get goal IDs and metadata for specified sub-categories.

    Returns goal IDs only — no goal text.
    """
    sub_categories = params.get("categories", params.get("sub_categories", []))
    sample_size = params.get("sample_size")

    if not sub_categories:
        return {"error": "categories/sub_categories is required (list of sub-category slugs or 'all')"}

    goals = _load_goals()

    # Handle "all"
    if sub_categories == "all" or (isinstance(sub_categories, list) and "all" in sub_categories):
        all_slugs = sorted(set(row["sub_category"] for row in goals))
        sub_categories = all_slugs

    # Validate sub-categories
    valid_slugs = set(row["sub_category"] for row in goals)
    invalid = [c for c in sub_categories if c not in valid_slugs]
    if invalid:
        return {"error": f"Unknown sub-categories: {invalid}. Available: {sorted(valid_slugs)}"}

    # Filter goals by sub-category
    filtered = [row for row in goals if row["sub_category"] in sub_categories]

    # Sample if requested
    if sample_size and sample_size < len(filtered):
        import random

        random.seed(42)
        filtered = random.sample(filtered, sample_size)

    # Return IDs and metadata only — never goal text
    result_goals = []
    for row in filtered:
        result_goals.append(
            {
                "id": row["id"],
                "category": row["category"],
                "sub_category": row["sub_category"],
            }
        )

    # Group counts by sub-category
    sub_category_counts: dict[str, int] = {}
    for g in result_goals:
        sub = g["sub_category"]
        sub_category_counts[sub] = sub_category_counts.get(sub, 0) + 1

    return {
        "result": {
            "goals": result_goals,
            "count": len(result_goals),
            "sub_category_counts": sub_category_counts,
        }
    }


# ── stdin/stdout JSON dispatch ────────────────────────────────────────────────

METHODS = {
    "list_categories": list_categories,
    "list_goal_categories": list_categories,
    "get_category_goals": get_category_goals,
}


def main() -> None:
    raw = sys.stdin.read()
    request = json.loads(raw)
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
