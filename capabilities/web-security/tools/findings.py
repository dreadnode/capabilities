"""Structured finding recording for the web-security pipeline.

The coordinator inspects ``tool_calls`` from the triage reviewer. Each
``record_ws_finding`` call becomes a candidate for validator fan-out.
"""

import typing as t

from dreadnode.agents.tools import tool

Severity = t.Literal["critical", "high", "medium", "low", "informational"]
Confidence = t.Literal["high", "medium", "low"]
Origin = t.Literal[
    "specialist-derived", "chain-discoverer-derived", "triage-reviewer-new"
]


@tool
def record_ws_finding(
    id: t.Annotated[
        str,
        "Stable finding id, e.g. WS-HIGH-001. Used to label validator sessions.",
    ],
    title: t.Annotated[str, "Short human-readable title."],
    severity: t.Annotated[
        Severity, "One of: critical, high, medium, low, informational."
    ],
    confidence: t.Annotated[Confidence, "Confidence before validator review."],
    url: t.Annotated[str, "Primary affected URL or endpoint."],
    claim: t.Annotated[
        str,
        "One- or two-sentence claim of what is exposed and why it is exploitable.",
    ],
    evidence: t.Annotated[
        str,
        "Concrete evidence: request/response excerpts, payloads, screenshots, traces, or source references.",
    ],
    attacker_capability: t.Annotated[
        str,
        "What the attacker must be able to do, e.g. unauthenticated request or standard user account.",
    ],
    impact: t.Annotated[str, "What the attacker gains if exploitation succeeds."],
    suggested_validation: t.Annotated[
        str,
        "Fastest safe validation path for the validator agent.",
    ],
    origin: t.Annotated[Origin, "Where this finding came from in the pipeline."],
    method: t.Annotated[str, "HTTP method, or empty string if not applicable."] = "",
    parameter: t.Annotated[
        str, "Affected parameter, header, cookie, or empty string."
    ] = "",
    auth_required: t.Annotated[
        bool,
        "Whether exploitation requires authentication.",
    ] = False,
    vulnerability_class: t.Annotated[
        str,
        "Vulnerability class, e.g. SSRF, request smuggling, IDOR.",
    ] = "",
    cwe: t.Annotated[str, "CWE identifier if known, e.g. CWE-918."] = "",
    exploit_prerequisites: t.Annotated[
        str,
        "Configuration, version, role, or environmental prerequisites. State 'default' when none.",
    ] = "default",
    scope_notes: t.Annotated[
        str,
        "Why the target appears in-scope, out-of-scope, or uncertain.",
    ] = "",
    accepted_risk_notes: t.Annotated[
        str,
        "Notes on intentional behavior or accepted risk. Empty if not applicable.",
    ] = "",
) -> str:
    """Record one structured web security finding for validator review.

    Call this once per confirmed high or critical finding before writing the
    triage report. Findings only mentioned in prose are not eligible for
    automatic validator fan-out.
    """
    return f"Recorded {id} ({severity}): {title}"
