"""Tools the source-analysis agents use to record structured findings.

The coordinator worker inspects ``tool_calls`` on the agent's
``turn.completed`` payload to discover findings. Each ``record_finding``
call corresponds to one structured finding the worker may then hand to a
validator agent.
"""

import typing as t

from dreadnode.agents.tools import tool

Severity = t.Literal["critical", "high", "medium", "low", "informational"]


@tool
def record_finding(
    id: t.Annotated[
        str,
        "Stable finding id, e.g. HIGH-001 or CRIT-002. Used to label validator sessions and stitch the final report together.",
    ],
    title: t.Annotated[
        str,
        "Short human-readable title.",
    ],
    severity: t.Annotated[
        Severity,
        "One of: critical, high, medium, low, informational.",
    ],
    confidence: t.Annotated[
        t.Literal["high", "medium", "low"],
        "Your confidence in the finding before validation.",
    ],
    claim: t.Annotated[
        str,
        "One- or two-sentence claim of what is wrong and why it is exploitable.",
    ],
    evidence: t.Annotated[
        str,
        "Concrete evidence: file paths, line numbers, commit hashes, command outputs, test names. Be specific.",
    ],
    affected_files: t.Annotated[
        list[str],
        "List of relative paths in the repository where the issue lives.",
    ],
    attacker_capability: t.Annotated[
        str,
        "What the attacker must already be able to do (e.g. send unauthenticated HTTP requests, control a dependency, push a PR).",
    ],
    reachable_entrypoint: t.Annotated[
        str,
        "The user-, network-, or operator-facing entry point through which the attacker reaches the bug.",
    ],
    impact: t.Annotated[
        str,
        "What the attacker gains if the exploit succeeds (RCE, data exfil, auth bypass, etc.).",
    ],
    exploit_prerequisites: t.Annotated[
        str,
        "Configuration, version, or environmental conditions that must hold for the exploit to work. State 'default' when no extra config is required.",
    ],
    deployment_assumptions: t.Annotated[
        str,
        "Deployment assumptions the exploit relies on. State 'default' when none.",
    ],
    version_or_commit_scope: t.Annotated[
        str,
        "Affected versions or commit range, or 'unknown' if you could not pin it down.",
    ],
    suggested_validation: t.Annotated[
        str,
        "Fastest concrete validation path the validator agent should follow.",
    ],
    origin: t.Annotated[
        t.Literal["specialist-derived", "final-reviewer-new"],
        "Where this finding came from in the pipeline.",
    ],
    accepted_risk_notes: t.Annotated[
        str,
        "Notes on whether the project might consider this accepted risk and why. Empty string if not applicable.",
    ] = "",
) -> str:
    """Record one structured high or critical finding for validator review.

    Call this once per finding before writing the final markdown report. The
    worker that owns this run inspects your tool calls to spawn a validator
    agent for each high or critical finding. Findings only mentioned in prose
    will not be validated.
    """
    return f"Recorded {id} ({severity}): {title}"
