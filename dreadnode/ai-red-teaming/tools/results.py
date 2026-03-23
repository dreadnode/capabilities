"""Results inspector for AI red team output files.

Provides tools to browse and analyze output files from attack runs
in the ~/workspace/airt/ directory.
"""

from __future__ import annotations

import json
import os
import typing as t
from pathlib import Path

from dreadnode.agents.tools import tool

WORKSPACE_DIR = Path(
    os.environ.get("DREADAIRT_OUTPUT_DIR", str(Path.home() / "workspace" / "airt"))
)


def _safe_path(relative: str) -> Path | None:
    """Resolve a relative path within workspace, rejecting traversal."""
    resolved = (WORKSPACE_DIR / relative).resolve()
    if not resolved.is_relative_to(WORKSPACE_DIR.resolve()):
        return None
    return resolved


@tool
def inspect_results(
    file_type: t.Annotated[
        str,
        "Type of files to inspect: 'analytics', 'results', 'reports', or 'all'",
    ] = "all",
    filename: t.Annotated[
        str,
        "Specific file to read (relative to ~/workspace/airt/). "
        "If omitted, lists matching files.",
    ] = "",
) -> str:
    """Browse and read output files from attack runs.

    Lists or reads analytics JSON, result files, and reports from
    the ~/workspace/airt/ output directory.
    """
    if not WORKSPACE_DIR.exists():
        return f"Workspace directory not found: {WORKSPACE_DIR}"

    if filename:
        path = _safe_path(filename)
        if path is None:
            return "Error: Path traversal rejected."
        if not path.exists():
            return f"File not found: {filename}"
        try:
            content = path.read_text()
            if path.suffix == ".json":
                parsed = json.loads(content)
                return json.dumps(parsed, indent=2)[:50_000]
            return content[:50_000]
        except Exception as e:
            return f"Error reading file: {e}"

    patterns = {
        "analytics": ["*analytics*.json"],
        "results": ["*result*.json", "*study*.json"],
        "reports": ["*.md", "*.html", "*.txt"],
        "all": ["*analytics*.json", "*result*.json", "*study*.json", "*.md", "*.html"],
    }

    globs = patterns.get(file_type, patterns["all"])
    found: list[str] = []
    for pattern in globs:
        for p in WORKSPACE_DIR.rglob(pattern):
            if p.is_file():
                found.append(str(p.relative_to(WORKSPACE_DIR)))

    if not found:
        return f"No {file_type} files found in {WORKSPACE_DIR}"

    found.sort()
    lines = [f"Found {len(found)} {file_type} files in {WORKSPACE_DIR}:"]
    for f in found[:50]:
        lines.append(f"  - {f}")
    if len(found) > 50:
        lines.append(f"  ... and {len(found) - 50} more")

    return "\n".join(lines)


@tool
def get_analytics_summary(
    attack_name: t.Annotated[
        str,
        "Filter by attack name (substring match). Empty for all.",
    ] = "",
) -> str:
    """Aggregate key metrics across all analytics files.

    Scans all analytics, results, and study JSON files in the output
    directory. Optionally filters by attack name. Returns ASR, risk
    scores, severity, compliance, and trial counts for each file.
    """
    if not WORKSPACE_DIR.exists():
        return f"Output directory not found: {WORKSPACE_DIR}"

    analytics_files: list[Path] = []
    for pattern in ["*analytics*.json", "*result*.json", "*study*.json"]:
        analytics_files.extend(WORKSPACE_DIR.rglob(pattern))

    if not analytics_files:
        return "No analytics files found. Run an attack workflow first."

    summaries: list[str] = []
    for f in sorted(analytics_files):
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue

        # Filter by attack name if specified
        if attack_name:
            file_attack = data.get("attack_name", data.get("name", ""))
            if attack_name.lower() not in file_attack.lower():
                continue

        lines = [f"--- {f.relative_to(WORKSPACE_DIR)} ---"]

        if "asr" in data:
            lines.append(f"ASR: {data['asr']}%")
        if "risk_score" in data:
            lines.append(f"Risk Score: {data['risk_score']}/10")
        if "overall_risk" in data:
            lines.append(f"Overall Risk: {data['overall_risk']}")

        severity = data.get("severity_breakdown", data.get("severity", {}))
        if severity:
            lines.append("Severity: " + ", ".join(f"{k}={v}" for k, v in severity.items()))

        compliance = data.get("compliance_coverage", data.get("compliance", {}))
        if compliance:
            lines.append("Compliance: " + ", ".join(f"{k}={v}" for k, v in compliance.items()))

        trials = data.get("trials", data.get("results", []))
        if isinstance(trials, list):
            lines.append(f"Trials: {len(trials)}")

        for key in ["attack_name", "attack_type", "attacks"]:
            if key in data:
                lines.append(f"Attack: {data[key]}")
                break

        if "goals" in data:
            goals = data["goals"]
            if isinstance(goals, list):
                lines.append(f"Goals tested: {len(goals)}")

        summaries.append("\n".join(lines))

    if not summaries:
        filter_msg = f" for '{attack_name}'" if attack_name else ""
        return f"No analytics data found{filter_msg}."

    return "\n\n".join(summaries)
