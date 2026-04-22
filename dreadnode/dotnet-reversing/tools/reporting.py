"""Reporting tools for logging findings, credentials, and PoCs to Dreadnode.

These tools integrate with the Dreadnode tracing system to persist analysis
results as metrics, outputs, and artifacts for tracking across runs.
"""

from __future__ import annotations

import typing as t
import uuid
from pathlib import Path

import dreadnode as dn
from dreadnode.agents.tools import tool
from dreadnode.core.types import Markdown

REPORTS_DIR = Path.home() / "workspace" / "reports"


@tool
def finish_task(
    success: t.Annotated[bool, "Whether the task completed successfully"],
    markdown_summary: t.Annotated[str, "Markdown summary of findings and conclusions"],
) -> str:
    """Mark your task as complete with a success/failure status and summary.

    Call this when you have finished analyzing the target and want to record
    the final outcome. The summary should include key findings, vulnerabilities
    discovered, and any recommendations.
    """
    dn.log_metric("task_success", float(success))
    if success:
        dn.tag("success")

    dn.log_output("task_summary", Markdown(markdown_summary))

    status = "successfully" if success else "with errors"
    return f"Task marked as completed {status}. Summary logged."


@tool
def report_auth(
    auth_material: t.Annotated[
        str, "Markdown details or code showing the auth material"
    ],
) -> str:
    """Report authentication material such as hardcoded keys, tokens, or passwords.

    Use this when you discover credentials, API keys, tokens, connection strings,
    or other sensitive authentication data in the analyzed code. Include the
    relevant code snippet and context.
    """
    output_dir = REPORTS_DIR / "auth"
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / f"{uuid.uuid4().hex[:8]}.md"
    file_path.write_text(auth_material, encoding="utf-8")

    dn.log_output(
        "auth_material",
        Markdown(f"### Auth material in {file_path}\n\n{auth_material}"),
    )
    dn.log_metric("auth_material", 1, aggregation="count")
    dn.log_param("auth_material", auth_material)
    dn.tag("creds")
    dn.log_artifact(file_path)

    return f"Auth material reported and saved to {file_path}"


@tool
def report_finding(
    file: t.Annotated[str, "The file path where the finding was discovered"],
    method: t.Annotated[str, "The method or type name containing the vulnerability"],
    criticality: t.Annotated[
        str,
        "Severity level: 'critical', 'high', 'medium', 'low', or 'info'",
    ],
    content: t.Annotated[str, "Markdown description of the finding with code evidence"],
) -> str:
    """Report a security finding or vulnerability.

    Use this for any security-relevant discoveries: vulnerabilities, dangerous
    patterns, misconfigurations, or areas of interest. Include decompiled code
    evidence and explain the potential impact.
    """
    valid_criticalities = {"critical", "high", "medium", "low", "info"}
    normalized_criticality = criticality.lower()
    if normalized_criticality not in valid_criticalities:
        allowed_values = ", ".join(sorted(valid_criticalities))
        raise ValueError(
            f"Invalid criticality '{criticality}'. Allowed values: {allowed_values}"
        )

    dn.log_output(
        "finding",
        Markdown(
            f"### Finding in {file} - {method}\n\n**Criticality:** {normalized_criticality}\n\n{content}"
        ),
    )
    dn.log_metric("num_reports", 1, aggregation="count")
    dn.tag(normalized_criticality)

    return f"Finding reported: {method} in {file} [{normalized_criticality}]"


@tool
def report_poc(
    poc: t.Annotated[str, "Markdown proof-of-concept with exploitation steps"],
) -> str:
    """Save a Proof of Concept (PoC) for a discovered vulnerability.

    Use this when you have detailed exploitation steps or working PoC code.
    Include prerequisites, step-by-step instructions, and expected outcomes.
    """
    output_dir = REPORTS_DIR / "pocs"
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / f"{uuid.uuid4().hex[:8]}.md"
    file_path.write_text(poc, encoding="utf-8")

    dn.log_output("poc", Markdown(poc))
    dn.tag("poc")
    dn.log_metric("num_pocs", 1, aggregation="count")
    dn.log_artifact(file_path)

    return f"PoC saved to {file_path}"
