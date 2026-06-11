"""Structured ASM finding recorder for worker-coordinated runs."""

import typing as t

from dreadnode.agents.tools import tool

Severity = t.Literal["critical", "high", "medium", "low", "informational"]
Confidence = t.Literal["high", "medium", "low"]
ValidationStatus = t.Literal[
    "validated", "partially_validated", "unvalidated", "rejected"
]


@tool
def record_asm_finding(
    id: t.Annotated[
        str,
        "Stable finding id, e.g. ASM-HIGH-001. Used by the coordinator to label validator sessions.",
    ],
    title: t.Annotated[str, "Short human-readable title."],
    severity: t.Annotated[
        Severity, "One of: critical, high, medium, low, informational."
    ],
    confidence: t.Annotated[
        Confidence, "Confidence in the finding before validator review."
    ],
    asset: t.Annotated[
        str, "Primary affected host, URL, IP, service, or asset cluster."
    ],
    claim: t.Annotated[
        str, "One- or two-sentence claim of what is exposed and why it matters."
    ],
    evidence: t.Annotated[
        str,
        "Concrete evidence: tool outputs, graph query results, HTTP observations, screenshots, versions, ports, or CVE references.",
    ],
    gadget: t.Annotated[
        str,
        "The attack-surface gadget or chain this finding belongs to, e.g. exposed staging API plus weak error handling.",
    ],
    validation_status: t.Annotated[
        ValidationStatus,
        "Validation state reached by the reviewer before spawning dedicated validators.",
    ],
    validation_method: t.Annotated[
        str,
        "Non-destructive method already used or recommended to validate the claim.",
    ],
    impact: t.Annotated[
        str, "Operational or security impact if the exposure is exploitable."
    ],
    next_steps: t.Annotated[str, "Specific next actions for a human operator."],
    scope_notes: t.Annotated[
        str,
        "Why the asset appears in-scope, out-of-scope, or uncertain based on the provided scope.",
    ],
    origin: t.Annotated[
        t.Literal["discovery", "enrichment", "gadget", "final-reviewer"],
        "Pipeline stage that produced or accepted this finding.",
    ],
    rejected_alternatives: t.Annotated[
        str,
        "Brief notes on plausible explanations or leads that were rejected. Empty string if none.",
    ] = "",
) -> str:
    """Record one structured ASM finding for validator review.

    The coordinator inspects tool calls from the final reviewer and launches
    validator agents for high and critical findings. Findings only described in
    prose are not eligible for validator fan-out.
    """
    return f"Recorded {id} ({severity}): {title}"
