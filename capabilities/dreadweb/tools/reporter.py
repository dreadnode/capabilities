#!/usr/bin/env python3
"""Vulnerability reporter tool for web security testing.

Structured vulnerability reporting with deduplication, severity tracking,
and cumulative session reports.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Persistent state for reported vulns across tool invocations
STATE_FILE = Path(os.environ.get("REPORTER_STATE_PATH", "/tmp/dreadweb_reports.json"))
REPORT_FILE = Path(os.environ.get("REPORTER_OUTPUT_PATH", "/tmp/dreadweb_report.md"))


def load_reports() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"vulnerabilities": {}, "session_start": datetime.now(timezone.utc).isoformat()}


def save_reports(reports: dict) -> None:
    STATE_FILE.write_text(json.dumps(reports, indent=2))


def _vuln_key(endpoint: str, vuln_type: str) -> str:
    return f"{endpoint}|{vuln_type}"


def _write_markdown_report(reports: dict) -> None:
    """Write cumulative markdown report."""
    vulns = reports["vulnerabilities"]
    if not vulns:
        return

    lines = [
        "# Vulnerability Report",
        f"**Session started:** {reports.get('session_start', 'unknown')}",
        f"**Total findings:** {len(vulns)}",
        "",
    ]

    # Group by severity
    by_severity = {}
    for v in vulns.values():
        sev = v.get("severity", "unknown")
        by_severity.setdefault(sev, []).append(v)

    severity_order = ["critical", "high", "medium", "low", "informational"]
    for sev in severity_order:
        findings = by_severity.get(sev, [])
        if not findings:
            continue

        lines.append(f"## {sev.upper()} ({len(findings)})")
        lines.append("")

        for v in findings:
            lines.append(f"### {v.get('category', 'Unknown')}: {', '.join(v.get('tags', []))}")
            lines.append(f"- **Endpoint:** `{v.get('endpoint', '')}`")
            lines.append(f"- **Method:** {v.get('method', 'GET')}")
            lines.append(f"- **Type:** {v.get('vuln_type', 'unknown')}")
            if v.get("cvss_score"):
                lines.append(f"- **CVSS:** {v['cvss_score']}")
            lines.append(f"- **Payload:** `{v.get('payload', '')}`")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append(f"```\n{v.get('evidence', 'No evidence provided.')}\n```")
            lines.append("")
            if v.get("poc_steps"):
                lines.append("**Reproduction Steps:**")
                for i, step in enumerate(v["poc_steps"], 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

    REPORT_FILE.write_text("\n".join(lines))


def report_vulnerability(params: dict) -> dict:
    reports = load_reports()

    endpoint = params.get("endpoint", "")
    vuln_type = params.get("vuln_type", "unknown")
    key = _vuln_key(endpoint, vuln_type)

    # Check for duplicate
    if key in reports["vulnerabilities"]:
        existing = reports["vulnerabilities"][key]
        return {
            "result": (
                f"Duplicate: {existing.get('category', 'Unknown')} at {endpoint} was already reported. "
                f"Use list_reported_vulnerabilities to see all findings."
            )
        }

    vuln = {
        "vuln_type": vuln_type,
        "category": params.get("category", "Unknown"),
        "tags": params.get("tags", []),
        "endpoint": endpoint,
        "method": params.get("method", "GET"),
        "payload": params.get("payload", ""),
        "evidence": params.get("evidence", ""),
        "poc_steps": params.get("poc_steps", []),
        "severity": params.get("severity", "medium"),
        "cvss_score": params.get("cvss_score"),
        "reported_at": datetime.now(timezone.utc).isoformat(),
    }

    # Include authorization-specific fields if present
    for field in ["tested_param", "tested_value", "tested_path", "tested_query"]:
        if params.get(field):
            vuln[field] = params[field]

    reports["vulnerabilities"][key] = vuln
    save_reports(reports)
    _write_markdown_report(reports)

    category = f"{vuln['category']}: {', '.join(vuln['tags'])}"
    total = len(reports["vulnerabilities"])
    return {
        "result": f"Reported {category} at {endpoint} (severity: {vuln['severity']}). Total findings: {total}."
    }


def list_reported_vulnerabilities(_params: dict) -> dict:
    reports = load_reports()
    vulns = reports["vulnerabilities"]

    if not vulns:
        return {"result": "No vulnerabilities reported yet in this session."}

    summaries = []
    for v in vulns.values():
        summaries.append({
            "endpoint": v["endpoint"],
            "vuln_type": v["vuln_type"],
            "category": v["category"],
            "tags": v["tags"],
            "severity": v["severity"],
            "method": v["method"],
        })

    result = {
        "total_reported": len(summaries),
        "vulnerabilities": summaries,
    }
    return {"result": json.dumps(result, indent=2)}


def get_report(_params: dict) -> dict:
    if REPORT_FILE.exists():
        return {"result": REPORT_FILE.read_text()}
    return {"result": "No report generated yet. Report vulnerabilities first."}


METHODS = {
    "report_vulnerability": report_vulnerability,
    "list_reported_vulnerabilities": list_reported_vulnerabilities,
    "get_report": get_report,
}


def main():
    raw = sys.stdin.read()
    request = json.loads(raw)
    method = request.get("method", request.get("name", ""))
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
