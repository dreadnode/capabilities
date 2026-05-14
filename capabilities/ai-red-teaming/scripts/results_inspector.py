#!/usr/bin/env python3
"""Results inspector for AI Red Teaming output files.

Reads analytics JSON, result files, and reports from the active workspace dir
(~/.dreadnode/airt/[org]/[workspace]/) to provide summaries and detailed
inspection of attack outputs.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import sys
from pathlib import Path


def _resolve_workspace_dir() -> Path:
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


AIRT_DIR = _resolve_workspace_dir()


def inspect_results(params: dict) -> dict:
    path = params.get("path", "")
    file_type = params.get("file_type", "all")

    target = (AIRT_DIR / path).resolve() if path else AIRT_DIR
    if not target.is_relative_to(AIRT_DIR.resolve()):
        return {"error": "Path must be within the AIRT output directory"}

    if not target.exists():
        return {"error": f"Path not found: {target}"}

    # If it's a specific file, read and return it
    if target.is_file():
        return _read_file(target)

    # List directory contents, filtered by type
    files = _list_files(target, file_type)
    if not files:
        return {"result": f"No {file_type} files found in {target}"}

    lines = [f"Files in {target} ({len(files)} found):"]
    for f in files:
        rel = f.relative_to(AIRT_DIR) if f.is_relative_to(AIRT_DIR) else f
        size = f.stat().st_size
        lines.append(f"  - {rel} ({_human_size(size)})")

    return {"result": "\n".join(lines)}


def get_analytics_summary(params: dict) -> dict:
    attack_name = params.get("attack_name")

    # Find all JSON files that look like analytics or results
    analytics_files = []
    for pattern in ["*analytics*.json", "*result*.json", "*study*.json"]:
        analytics_files.extend(AIRT_DIR.rglob(pattern))

    if not analytics_files:
        return {
            "error": f"No analytics files found in {AIRT_DIR}. Run an attack workflow first."
        }

    summaries = []
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

        summary = _summarize_data(f.name, data)
        if summary:
            summaries.append(summary)

    if not summaries:
        filter_msg = f" for '{attack_name}'" if attack_name else ""
        return {"result": f"No analytics data found{filter_msg}."}

    return {"result": "\n\n".join(summaries)}


def _read_file(path: Path) -> dict:
    """Read and return file contents, parsing JSON if applicable."""
    try:
        content = path.read_text()
    except Exception as e:
        return {"error": f"Cannot read {path}: {e}"}

    if path.suffix == ".json":
        try:
            data = json.loads(content)
            # Pretty-print JSON with key metrics highlighted
            return {"result": json.dumps(data, indent=2, default=str)[:10000]}
        except json.JSONDecodeError:
            pass

    # Return raw content (truncated)
    if len(content) > 10000:
        content = content[:10000] + "\n\n... (truncated)"
    return {"result": content}


def _list_files(directory: Path, file_type: str) -> list[Path]:
    """List files in directory, optionally filtered by type."""
    if not directory.is_dir():
        return []

    type_patterns = {
        "analytics": ["*analytics*.json", "*metrics*.json"],
        "results": ["*result*.json", "*study*.json"],
        "reports": ["*.md", "*report*.json", "*report*.html"],
        "all": ["*"],
    }

    patterns = type_patterns.get(file_type, type_patterns["all"])
    files: list[Path] = []
    for pattern in patterns:
        files.extend(f for f in directory.rglob(pattern) if f.is_file())

    return sorted(set(files))


def _human_size(size: int) -> str:
    """Format bytes as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def _summarize_data(filename: str, data: dict) -> str | None:
    """Extract key metrics from a data dict."""
    lines = [f"── {filename} ──"]

    # Try common metric fields
    if "asr" in data or "attack_success_rate" in data:
        asr = data.get("asr", data.get("attack_success_rate"))
        if isinstance(asr, (int, float)):
            lines.append(f"  ASR: {asr:.1%}")

    if "risk_score" in data:
        lines.append(f"  Risk Score: {data['risk_score']:.1f}/10")

    if "overall_risk_score" in data:
        lines.append(f"  Overall Risk: {data['overall_risk_score']:.1f}/10")

    if "severity_breakdown" in data:
        sev = data["severity_breakdown"]
        lines.append(f"  Severity: {json.dumps(sev)}")

    if "best_score" in data:
        lines.append(f"  Best Score: {data['best_score']:.2f}")

    if "total_trials" in data:
        finished = data.get("finished_trials", data.get("completed_trials", "?"))
        lines.append(f"  Trials: {finished}/{data['total_trials']}")

    if "compliance_coverage" in data:
        coverage = data["compliance_coverage"]
        if isinstance(coverage, dict):
            lines.append("  Compliance Coverage:")
            for framework, pct in coverage.items():
                if isinstance(pct, (int, float)):
                    lines.append(f"    {framework}: {pct:.0%}")
                else:
                    lines.append(f"    {framework}: {pct}")

    if "attack_name" in data or "name" in data:
        name = data.get("attack_name", data.get("name", ""))
        lines.insert(1, f"  Attack: {name}")

    if "goal" in data:
        goal = data["goal"]
        if len(goal) > 100:
            goal = goal[:100] + "..."
        lines.append(f"  Goal: {goal}")

    # Only return if we found something beyond the header
    if len(lines) <= 1:
        return None

    return "\n".join(lines)


METHODS = {
    "inspect_results": inspect_results,
    "get_analytics_summary": get_analytics_summary,
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
