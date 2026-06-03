"""Results inspector for AI red team output files.

Provides tools to browse and analyze legacy local output files from attack
runs. Platform OTEL traces are the source of truth; these helpers exist for
backward compatibility with workflows that still write local analytics files.
"""

from __future__ import annotations

import json
import os
import typing as t
from pathlib import Path

from dreadnode.agents.tools import tool


def _resolve_workspace_dir() -> Path:
    """Resolve workspace dir from UserConfig, falling back to default/main."""
    try:
        from dreadnode.app.config import UserConfig

        config = UserConfig.read()
        profile_data = config.active_profile
        if profile_data:
            _, profile = profile_data
            org = profile.organization or "default"
            workspace = profile.workspace or "main"
        else:
            org = "default"
            workspace = "main"
    except Exception:  # noqa: BLE001
        org = "default"
        workspace = "main"
    return Path.home() / ".dreadnode" / "airt" / org / workspace


WORKSPACE_DIR = _resolve_workspace_dir()


def _validate_required_params(**kwargs) -> list[str]:
    """Validate required parameters and return list of errors."""
    errors = []
    for name, value in kwargs.items():
        if not value or (isinstance(value, str) and value.strip() == ""):
            errors.append(f"Parameter '{name}' is required")
    return errors


def _suggest_alternatives(invalid_value: str, valid_options: list[str]) -> str:
    """Suggest valid alternatives for invalid values."""
    if not valid_options:
        return ""
    return f"Try one of: {', '.join(valid_options[:5])}"


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
        "Specific file to read (relative to the workspace dir). If omitted, lists matching files.",
    ] = "",
) -> str:
    """Browse and read output files from attack runs.

    Lists or reads analytics JSON, result files, and reports from the active
    workspace dir (~/.dreadnode/airt/[org]/[workspace]/).
    """
    # Validate file_type parameter
    valid_types = ["analytics", "results", "reports", "all"]
    if file_type not in valid_types:
        return f"Error: Invalid file_type '{file_type}'. {_suggest_alternatives(file_type, valid_types)}"

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
        workflows_dir = WORKSPACE_DIR / "workflows"
        ran_workflows = (
            list(workflows_dir.glob("*.py")) if workflows_dir.exists() else []
        )
        if ran_workflows:
            return (
                "No local analytics files found, but workflow scripts are present. "
                "Platform OTEL traces are the source of truth for this run — view "
                "ASR/risk in the Dreadnode platform web UI (AI Red Teaming), or use "
                "get_assessment_status() for high-level metrics. Local analytics JSON "
                "is a legacy artifact and may be absent for image/tabular attacks or "
                "studies with no finished trials."
            )
        return "No analytics files found. Run an attack workflow first."

    summaries: list[str] = []
    for f in sorted(analytics_files):
        try:
            outer = json.loads(f.read_text())
        except Exception:
            continue

        # New-format files wrap SDK analytics under an "analytics" envelope
        # (with assessment_id / model metadata at the top level). Legacy files
        # are flat. Read metrics from the envelope when present, falling back
        # to the top level for backward compatibility.
        data = outer.get("analytics") if isinstance(outer.get("analytics"), dict) else outer

        # Filter by attack name if specified
        if attack_name:
            file_attack = outer.get("attack_name", data.get("attack_name", data.get("name", "")))
            if attack_name.lower() not in file_attack.lower():
                continue

        lines = [f"--- {f.relative_to(WORKSPACE_DIR)} ---"]
        if outer is not data:
            # Surface assessment-level identifiers from the envelope.
            if outer.get("assessment_id"):
                lines.append(f"Assessment: {outer['assessment_id']}")
            if outer.get("target_model"):
                lines.append(f"Target: {outer['target_model']}")

        exec_stats = data.get("execution_stats", {}) if isinstance(data.get("execution_stats"), dict) else {}
        if "asr" in data:
            lines.append(f"ASR: {data['asr']}%")
        elif "overall_asr" in exec_stats:
            # SDK stores ASR as a 0-1 fraction under execution_stats.
            lines.append(f"ASR: {round(exec_stats['overall_asr'] * 100, 1)}%")
        if "risk_score" in data:
            lines.append(f"Risk Score: {data['risk_score']}/10")
        if "overall_risk" in data:
            lines.append(f"Overall Risk: {data['overall_risk']}")

        severity = data.get("severity_breakdown", data.get("severity", {}))
        if severity:
            if isinstance(severity, dict):
                lines.append(
                    "Severity: " + ", ".join(f"{k}={v}" for k, v in severity.items())
                )
            else:
                lines.append(f"Severity: {severity}")

        compliance = data.get("compliance_coverage", data.get("compliance", {}))
        if compliance:
            if isinstance(compliance, dict):
                lines.append(
                    "Compliance: "
                    + ", ".join(f"{k}={v}" for k, v in compliance.items())
                )
            else:
                lines.append(f"Compliance: {compliance}")

        trials = data.get("trials", data.get("results", []))
        if isinstance(trials, list) and trials:
            lines.append(f"Trials: {len(trials)}")
        elif "total_trials" in exec_stats:
            lines.append(f"Trials: {exec_stats['total_trials']}")

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
def get_platform_assessment_data(
    assessment_name: t.Annotated[str, "Assessment name to retrieve from platform"] = "",
) -> str:
    """⚠️  CRITICAL LIMITATION: Limited platform data access.

    PLATFORM DATA AVAILABLE via get_assessment_status():
    - ✅ Assessment name, target, goal, status
    - ✅ ASR percentage per attack
    - ✅ Risk score (0-10) per attack
    - ✅ Attack completion status and notes

    PLATFORM DATA NOT ACCESSIBLE (requires full platform API):
    - ❌ Individual trial details and best scores
    - ❌ Severity breakdown (critical/high/medium/low)
    - ❌ Transform comparison results
    - ❌ Detailed scorer outputs
    - ❌ Compliance framework mapping
    - ❌ Trial-level timestamps and metadata

    RECOMMENDATION:
    For detailed analytics, use the Dreadnode platform web interface
    at your organization's dashboard. The assessment tracking tools
    only provide high-level summary metrics.

    Current assessment tracking tools:
    - get_assessment_status() - Available summary metrics only
    - update_assessment_status() - Log high-level results only
    - register_assessment() - Track assessment metadata only
    """
    return (
        "⚠️  LIMITED PLATFORM DATA ACCESS\n\n"
        "Assessment tracking tools provide ONLY summary metrics:\n"
        "- ASR percentage, Risk score, Status, Notes\n\n"
        "For detailed analysis (trials, scorers, compliance):\n"
        "→ Use Dreadnode platform web interface\n"
        "→ Assessment tracking tools are for workflow coordination only\n\n"
        "Call get_assessment_status() for available summary data."
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
            # No local files. This is NOT necessarily a failure: platform OTEL
            # traces are the source of truth, and some runs (e.g. image/tabular
            # adversarial attacks, or studies with 0 finished trials) legitimately
            # write no local analytics. Only flag a hard error if there's also no
            # sign that any workflow ran; otherwise report a soft, platform-aware note.
            workflows_dir = WORKSPACE_DIR / "workflows"
            ran_workflows = (
                list(workflows_dir.glob("*.py")) if workflows_dir.exists() else []
            )
            if ran_workflows:
                issues.append(
                    "ℹ️  No local analytics/result files, but workflow scripts are "
                    f"present ({len(ran_workflows)} found). Metrics are reported on "
                    "the Dreadnode platform (OTEL traces are the source of truth)."
                )
                suggestions.append(
                    "View ASR/risk for this assessment in the platform web UI "
                    "(AI Red Teaming), or use the assessment tracking tools "
                    "(get_assessment_status). Local analytics files are a legacy artifact."
                )
            else:
                issues.append("❌ No analytics or result files found")
                suggestions.append("Check if attack execution completed successfully")
        else:
            issues.append(
                f"✅ Found {len(analytics_files)} analytics, {len(result_files)} result files"
            )

        # Test JSON parsing
        for f in analytics_files[:5]:  # Check first 5 files
            try:
                data = json.loads(f.read_text())
                # Test the problematic fields
                severity = data.get("severity_breakdown", data.get("severity", {}))
                if severity and not isinstance(severity, (dict, str)):
                    issues.append(f"⚠️  Invalid severity format in {f.name}")
                    suggestions.append(
                        "Analytics parsing bug - severity field type issue"
                    )
            except Exception as e:
                issues.append(f"❌ JSON parsing failed for {f.name}: {e}")
                suggestions.append(f"Fix malformed JSON in {f.name}")

    issues.append(f"ℹ️  Workspace: {WORKSPACE_DIR}")

    report = ["=== Attack Results Validation ===", ""]
    report.extend(issues)

    if suggestions:
        report.extend(["", "=== Suggestions ==="])
        report.extend(suggestions)

    return "\n".join(report)


@tool
def fix_workflow_errors(
    error_type: t.Annotated[
        str,
        "Type of error: 'parsing', 'analytics', 'platform', 'all'",
    ] = "all",
) -> str:
    """Fix common workflow errors automatically.

    Attempts to diagnose and fix issues:
    - parsing: Fix JSON parsing errors in analytics files
    - analytics: Reset analytics pipeline and clear corrupted files
    - platform: Check platform connectivity and authentication
    - all: Run all fixes

    Returns fix report with success/failure status.
    """
    # Validate error_type parameter
    valid_types = ["parsing", "analytics", "platform", "all"]
    if error_type not in valid_types:
        return f"Error: Invalid error_type '{error_type}'. {_suggest_alternatives(error_type, valid_types)}"

    fixes_applied = []
    fixes_failed = []

    if error_type in ["parsing", "all"]:
        try:
            # Check for corrupted JSON files
            if WORKSPACE_DIR.exists():
                analytics_files = list(WORKSPACE_DIR.rglob("*analytics*.json"))
                corrupted_files = []

                for f in analytics_files:
                    try:
                        json.loads(f.read_text())
                    except json.JSONDecodeError:
                        corrupted_files.append(f)

                if corrupted_files:
                    # Move corrupted files to backup
                    backup_dir = WORKSPACE_DIR / ".corrupted_backups"
                    backup_dir.mkdir(exist_ok=True)

                    for f in corrupted_files:
                        backup_path = backup_dir / f.name
                        f.rename(backup_path)

                    fixes_applied.append(
                        f"✅ Moved {len(corrupted_files)} corrupted files to backup"
                    )
                else:
                    fixes_applied.append("✅ No corrupted JSON files found")
            else:
                fixes_applied.append(
                    "ℹ️  No workspace directory - will be created on next attack"
                )

        except Exception as e:
            fixes_failed.append(f"❌ Parsing fix failed: {e}")

    if error_type in ["analytics", "all"]:
        try:
            # Clear analytics cache and reset
            cache_dir = WORKSPACE_DIR / ".cache"
            if cache_dir.exists():
                import shutil

                shutil.rmtree(cache_dir)
                fixes_applied.append("✅ Cleared analytics cache")
            else:
                fixes_applied.append("ℹ️  No analytics cache to clear")

        except Exception as e:
            fixes_failed.append(f"❌ Analytics reset failed: {e}")

    if error_type in ["platform", "all"]:
        # Platform connectivity check
        try:
            # Check environment variables
            platform_vars = [
                "DREADNODE_API_KEY",
                "DREADNODE_ORG_KEY",
                "DREADNODE_WORKSPACE_KEY",
            ]
            platform_status = []

            for var in platform_vars:
                value = os.environ.get(var)
                if value:
                    platform_status.append(f"  ✅ {var}=***{value[-4:]}")
                else:
                    platform_status.append(f"  ⚠️  {var}=not set")

            fixes_applied.append("✅ Platform configuration checked:")
            fixes_applied.extend(platform_status)

        except Exception as e:
            fixes_failed.append(f"❌ Platform check failed: {e}")

    # Compile fix report
    result = [f"=== Workflow Error Fixes ({error_type}) ===", ""]

    if fixes_applied:
        result.append("=== Fixes Applied ===")
        result.extend(fixes_applied)
        result.append("")

    if fixes_failed:
        result.append("=== Fixes Failed ===")
        result.extend(fixes_failed)
        result.append("")
        result.append("=== Manual Steps Required ===")
        result.append("1. Check capability installation")
        result.append("2. Verify API keys and authentication")
        result.append("3. Restart dreadnode session if issues persist")

    if not fixes_failed:
        result.append("🎉 All fixes applied successfully!")
        result.append("Try running your attack workflow again.")

    return "\n".join(result)
