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
    os.environ.get("AIRT_OUTPUT_DIR", str(Path.home() / "workspace" / "airt"))
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
        "Filter by assessment name (substring match). Empty for all.",
    ] = "",
) -> str:
    """Get analytics summary from platform data - NO INTERPRETATION.

    ⚠️  PLATFORM DATA ONLY - This tool retrieves raw assessment metrics
    from the Dreadnode platform via assessment tracking. Does NOT interpret,
    analyze, or generate any analytics data. Returns only factual platform
    records: ASR, risk scores, severity counts, trial numbers.
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
            if isinstance(severity, dict):
                lines.append("Severity: " + ", ".join(f"{k}={v}" for k, v in severity.items()))
            else:
                lines.append(f"Severity: {severity}")

        compliance = data.get("compliance_coverage", data.get("compliance", {}))
        if compliance:
            if isinstance(compliance, dict):
                lines.append("Compliance: " + ", ".join(f"{k}={v}" for k, v in compliance.items()))
            else:
                lines.append(f"Compliance: {compliance}")

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
        return f"No local analytics files found{filter_msg}. The data may be available on the Dreadnode platform. Use the assessment tracking tools to retrieve recent results."

    return "\n\n".join(summaries)


@tool
def get_workspace_info() -> str:
    """Show current workspace configuration and suggest improvements.

    Displays the current workspace directory, checks for analytics files,
    and provides guidance on workspace organization.
    """
    info = [f"Current AIRT workspace: {WORKSPACE_DIR}"]

    if WORKSPACE_DIR.exists():
        analytics_count = len(list(WORKSPACE_DIR.rglob("*analytics*.json")))
        result_count = len(list(WORKSPACE_DIR.rglob("*result*.json")))
        workflow_count = len(list(WORKSPACE_DIR.rglob("*.py")))

        info.append(f"Analytics files: {analytics_count}")
        info.append(f"Result files: {result_count}")
        info.append(f"Workflow files: {workflow_count}")

        if analytics_count == 0:
            info.append("")
            info.append("⚠️  No local analytics files found.")
            info.append("This usually means:")
            info.append("1. Attack results are being sent to the platform via OTEL traces")
            info.append("2. Local analytics writing is not configured")
            info.append("3. Use assessment tracking tools to retrieve platform data")
    else:
        info.append("Workspace directory does not exist")
        info.append("Run an attack workflow to create it automatically")

    info.append("")
    info.append("Environment variables:")
    info.append(f"  AIRT_OUTPUT_DIR: {os.environ.get('AIRT_OUTPUT_DIR', 'not set')}")
    info.append(f"  AIRT_WORKFLOWS_DIR: {os.environ.get('AIRT_WORKFLOWS_DIR', 'not set')}")

    return "\n".join(info)


@tool
def get_platform_assessment_data(
    assessment_name: t.Annotated[str, "Assessment name to retrieve from platform"] = "",
) -> str:
    """Retrieve raw assessment data directly from Dreadnode platform.

    ⚠️  PLATFORM ONLY - NO INTERPRETATION OR ANALYSIS

    This tool ONLY returns factual data from the platform's assessment
    tracking system. It does NOT:
    - Interpret or analyze results
    - Generate summaries or insights
    - Make recommendations
    - Hallucinate any metrics

    Returns only raw platform records: assessment ID, status, ASR values,
    trial counts, attack configurations, timestamps.

    Use get_assessment_status() and update_assessment_status() to access
    this data through the official assessment tracking tools.
    """
    return (
        "❌ PLATFORM DATA RETRIEVAL NOT IMPLEMENTED\n\n"
        "This tool is a placeholder to prevent analytics hallucination.\n"
        "Use the official assessment tracking tools instead:\n\n"
        "- get_assessment_status() - Get current assessment status\n"
        "- update_assessment_status() - Log completed results\n"
        "- register_assessment() - Start new assessment tracking\n\n"
        "These tools connect to the actual platform data, not local files.\n"
        "Assessment analytics flow through OTEL traces to ClickHouse on the platform."
    )


@tool
def validate_attack_results() -> str:
    """Validate that attack execution completed successfully.

    Checks for common issues in the attack workflow:
    - Analytics files were created
    - No JSON parsing errors
    - Expected result structure exists
    - Platform assessment was registered

    Returns validation report with actionable fixes.
    """
    issues = []
    suggestions = []

    # Check workspace directory
    if not WORKSPACE_DIR.exists():
        issues.append("❌ Workspace directory not found")
        suggestions.append("Run an attack workflow to create workspace")
    else:
        # Check for analytics files
        analytics_files = list(WORKSPACE_DIR.rglob("*analytics*.json"))
        result_files = list(WORKSPACE_DIR.rglob("*result*.json"))

        if not analytics_files and not result_files:
            issues.append("❌ No analytics or result files found")
            suggestions.append("Check if attack execution completed successfully")
        else:
            issues.append(f"✅ Found {len(analytics_files)} analytics, {len(result_files)} result files")

        # Test JSON parsing
        for f in analytics_files[:5]:  # Check first 5 files
            try:
                data = json.loads(f.read_text())
                # Test the problematic fields
                severity = data.get("severity_breakdown", data.get("severity", {}))
                if severity and not isinstance(severity, (dict, str)):
                    issues.append(f"⚠️  Invalid severity format in {f.name}")
                    suggestions.append("Analytics parsing bug - severity field type issue")
            except Exception as e:
                issues.append(f"❌ JSON parsing failed for {f.name}: {e}")
                suggestions.append(f"Fix malformed JSON in {f.name}")

    # Check environment
    env_vars = ["AIRT_OUTPUT_DIR", "DREADNODE_WORKSPACE_ROOT", "DREADNODE_ORG_KEY"]
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            issues.append(f"✅ {var}={value}")
        else:
            issues.append(f"ℹ️  {var} not set (using defaults)")

    report = ["=== Attack Results Validation ===", ""]
    report.extend(issues)

    if suggestions:
        report.extend(["", "=== Suggestions ==="])
        report.extend(suggestions)

    return "\n".join(report)
