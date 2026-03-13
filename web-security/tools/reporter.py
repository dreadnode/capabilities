"""Vulnerability reporter with deduplication and severity tracking.

Provides structured vulnerability reporting with automatic deduplication,
severity-based grouping, and markdown report generation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr


class ReportingTools(Toolset):
    """Report and track discovered vulnerabilities with deduplication."""

    _reported: dict[str, dict] = PrivateAttr(default_factory=dict)

    @tool_method(name="report_vulnerability", catch=True)
    async def report_vulnerability(
        self,
        endpoint: str,
        vuln_type: str,
        severity: str = "medium",
        category: str = "Unknown",
        tags: list[str] | None = None,
        method: str = "GET",
        payload: str = "",
        evidence: str = "",
        poc_steps: list[str] | None = None,
        cvss_score: float | None = None,
        tested_param: str | None = None,
        tested_value: str | None = None,
        tested_path: str | None = None,
        tested_query: str | None = None,
    ) -> str:
        """Report a discovered vulnerability.

        The evidence field MUST contain the complete HTTP request and response
        showing the vulnerability. Duplicates (same endpoint + vuln_type) are
        automatically detected and rejected.

        Args:
            endpoint: Full URL where vulnerability was found
            vuln_type: Vulnerability class (e.g., reflected_xss, sqli_union, ssrf)
            severity: critical, high, medium, low, or informational
            category: Broad category (e.g., XSS, Injection, Authorization)
            tags: Descriptive tags for the finding
            method: HTTP method used (GET, POST, etc.)
            payload: Exploit payload that triggered the vulnerability
            evidence: Full HTTP request/response evidence
            poc_steps: Step-by-step reproduction instructions
            cvss_score: Optional CVSS score
            tested_param: For auth bugs — parameter name tested
            tested_value: For auth bugs — value used
            tested_path: For auth bugs — path tested
            tested_query: For auth bugs — query string tested
        """
        key = f"{endpoint}|{vuln_type}"

        if key in self._reported:
            return (
                f"Duplicate: {category} at {endpoint} was already reported. "
                f"Use list_reported_vulnerabilities to see all findings."
            )

        vuln: dict = {
            "vuln_type": vuln_type,
            "category": category,
            "tags": tags or [],
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "evidence": evidence,
            "poc_steps": poc_steps or [],
            "severity": severity,
            "cvss_score": cvss_score,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }

        for field, value in [
            ("tested_param", tested_param),
            ("tested_value", tested_value),
            ("tested_path", tested_path),
            ("tested_query", tested_query),
        ]:
            if value:
                vuln[field] = value

        self._reported[key] = vuln

        display_type = f"{category}: {', '.join(tags or [])}"
        total = len(self._reported)
        return f"Reported {display_type} at {endpoint} (severity: {severity}). Total findings: {total}."

    @tool_method(name="list_reported_vulnerabilities", catch=True)
    async def list_reported_vulnerabilities(self) -> str:
        """List all vulnerabilities reported in this session.

        Use to track progress and avoid re-reporting the same vulnerabilities.
        """
        if not self._reported:
            return "No vulnerabilities reported yet in this session."

        summaries = [
            {
                "endpoint": v["endpoint"],
                "vuln_type": v["vuln_type"],
                "category": v["category"],
                "tags": v["tags"],
                "severity": v["severity"],
                "method": v["method"],
            }
            for v in self._reported.values()
        ]

        return json.dumps(
            {"total_reported": len(summaries), "vulnerabilities": summaries},
            indent=2,
        )

    @tool_method(name="get_report", catch=True)
    async def get_report(self) -> str:
        """Generate a markdown vulnerability report of all findings.

        Groups findings by severity and includes payloads, evidence,
        and reproduction steps for each vulnerability.
        """
        if not self._reported:
            return "No vulnerabilities to report."

        lines = [
            "# Vulnerability Report",
            f"**Total findings:** {len(self._reported)}",
            "",
        ]

        by_severity: dict[str, list] = {}
        for v in self._reported.values():
            by_severity.setdefault(v["severity"], []).append(v)

        for sev in ["critical", "high", "medium", "low", "informational"]:
            findings = by_severity.get(sev, [])
            if not findings:
                continue

            lines.append(f"## {sev.upper()} ({len(findings)})")
            lines.append("")

            for v in findings:
                lines.append(f"### {v['category']}: {', '.join(v['tags'])}")
                lines.append(f"- **Endpoint:** `{v['endpoint']}`")
                lines.append(f"- **Method:** {v['method']}")
                lines.append(f"- **Type:** {v['vuln_type']}")
                if v.get("cvss_score"):
                    lines.append(f"- **CVSS:** {v['cvss_score']}")
                lines.append(f"- **Payload:** `{v['payload']}`")
                lines.append("")
                lines.append("**Evidence:**")
                lines.append(
                    f"```\n{v.get('evidence', 'No evidence provided.')}\n```"
                )
                lines.append("")
                if v.get("poc_steps"):
                    lines.append("**Reproduction Steps:**")
                    for i, step in enumerate(v["poc_steps"], 1):
                        lines.append(f"{i}. {step}")
                    lines.append("")

        return "\n".join(lines)
