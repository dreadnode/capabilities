"""Structured confidence calibration for security claims.

Forces the agent to evaluate its confidence per-claim before asserting
findings, reducing false positives. Tool-based reflection outperforms
system-prompt hedging because it operates per-claim rather than globally.
No external dependencies.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from dreadnode.agents.tools import Toolset, tool_method

EvidenceBasis = Literal[
    "poc_confirmed",
    "response_verified",
    "data_flow_traced",
    "code_pattern_with_context",
    "behavior_observed",
    "pattern_only",
    "scanner_output",
    "assumed",
]

ConfidenceLevel = Literal["high", "medium", "low", "uncertain"]

_STRONG_EVIDENCE = {"poc_confirmed", "response_verified", "data_flow_traced"}
_MEDIUM_EVIDENCE = {"code_pattern_with_context", "behavior_observed"}


class CredenceTool(Toolset):
    """Confidence calibration checkpoint for security claims."""

    @tool_method(name="assess_confidence", catch=True)
    async def assess_confidence(
        self,
        claim: Annotated[
            str,
            "The specific security claim. Be precise: "
            "'user input reaches innerHTML sink in app.js:456' "
            "not 'there might be XSS'",
        ],
        confidence: Annotated[
            ConfidenceLevel,
            "Your honest confidence in this claim",
        ],
        evidence_basis: Annotated[
            EvidenceBasis,
            "What is your confidence based on? "
            "poc_confirmed: payload sent, expected result received. "
            "response_verified: server response confirms behavior. "
            "data_flow_traced: input traced from source to sink in code. "
            "code_pattern_with_context: read surrounding code, not just snippet. "
            "behavior_observed: saw something in proxy/browser, didn't confirm root cause. "
            "pattern_only: matched a code pattern (innerHTML, eval, etc). "
            "scanner_output: automated tool flagged this. "
            "assumed: inferring without direct evidence.",
        ],
        agent_string: Annotated[
            str,
            "Your agent identifier (e.g. 'agent-opus', 'dn-agent-kimi', "
            "'agent-codex'). Used for log attribution across multi-agent sessions.",
        ] = "unknown",
    ) -> str:
        """Use BEFORE making any claim about a vulnerability, exploitability,
        tech stack, or security impact. Forces structured reflection on what
        you actually know vs. what you're inferring. Do NOT skip this for
        findings you plan to report or act on.
        """
        credence_id = str(uuid.uuid4())
        prefix = f"[{agent_string}] [credence_id:{credence_id}] "

        if confidence == "high" and evidence_basis in _STRONG_EVIDENCE:
            return (
                f"{prefix}CONFIRMED — High confidence with strong evidence ({evidence_basis}). "
                "Proceed with assertion. This is reportable if impact is demonstrated."
            )

        if confidence == "high" and evidence_basis not in _STRONG_EVIDENCE:
            return (
                f"{prefix}OVERCONFIDENT — You claimed high confidence but your evidence "
                f"basis is '{evidence_basis}'. Downgrade to a lead/gadget until you have: "
                "traced data flow, confirmed with PoC, or verified server response. "
                "Do NOT claim this is a vulnerability yet."
            )

        if confidence == "medium":
            if evidence_basis in _STRONG_EVIDENCE:
                return (
                    f"{prefix}UPGRADE AVAILABLE — You have strong evidence ({evidence_basis}) "
                    "but only medium confidence. Re-evaluate: if the evidence directly "
                    "confirms the claim, upgrade to high confidence and proceed."
                )
            return (
                f"{prefix}UNCONFIRMED LEAD — Medium confidence ({evidence_basis}). "
                "State this as a potential finding requiring validation. "
                "Specify exactly what evidence is missing before it becomes reportable. "
                "Do NOT assign severity or write a report for this yet."
            )

        # low or uncertain
        return (
            f"{prefix}INSUFFICIENT — Low confidence ({evidence_basis}). "
            "Do NOT assert this as a finding. Log as a pattern/gadget for "
            "future investigation only. Do not invest PoC time without "
            "additional supporting evidence."
        )
