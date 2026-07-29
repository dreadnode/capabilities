"""Typed Agent Output records for persistent recursive code analysis."""

import typing as t
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

RunState = t.Literal[
    "planned",
    "running",
    "paused",
    "completed",
    "exhausted",
    "stale",
]
TargetKind = t.Literal[
    "repository",
    "module",
    "file",
    "class",
    "function",
    "endpoint",
    "data-flow",
    "configuration",
    "dependency",
]
TargetState = t.Literal[
    "queued",
    "in-progress",
    "analyzed",
    "blocked",
    "skipped",
    "stale",
]
ClaimCategory = t.Literal[
    "behavior",
    "trust-boundary",
    "vulnerability",
    "assumption",
    "coverage-gap",
]
ClaimDisposition = t.Literal[
    "hypothesized",
    "verified",
    "refuted",
    "unresolved",
]
Confidence = t.Literal["high", "medium", "low"]
NonEmptyText = t.Annotated[str, StringConstraints(min_length=1)]
RunKey = t.Annotated[
    str,
    StringConstraints(
        min_length=24,
        max_length=24,
        pattern=r"^[0-9a-f]{24}$",
    ),
]


class AnalysisRun(BaseModel):
    """One bounded analysis of a repository revision."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "run_state": {
                                "enum": ["paused", "completed", "exhausted", "stale"]
                            }
                        },
                        "required": ["run_state"],
                    },
                    "then": {
                        "required": ["stop_reason"],
                        "properties": {
                            "stop_reason": {"type": "string", "minLength": 1}
                        },
                    },
                }
            ]
        },
    )

    title: str = Field(..., min_length=1, max_length=512)
    run_key: RunKey = Field(
        description=(
            "First 24 lowercase hex characters of SHA-256 over canonical "
            "repository, immutable revision, and normalized objective separated "
            "by newlines."
        ),
    )
    objective: str = Field(
        ...,
        min_length=1,
        description="The security or code-understanding question this run must answer.",
    )
    repository: str = Field(
        ...,
        min_length=1,
        description="Canonical local path or repository URL.",
    )
    revision: str = Field(
        ...,
        min_length=1,
        description="Git commit or other immutable source revision.",
    )
    run_state: RunState = Field(default="running")
    scope: list[str] = Field(
        default_factory=list,
        description="Included directories, components, or vulnerability classes.",
    )
    exclusions: list[str] = Field(
        default_factory=list,
        description="Explicitly excluded code or concerns.",
    )
    max_targets: int = Field(
        default=50,
        ge=1,
        le=1_000,
        description="Maximum targets in this run; bounded by the frontier scan contract.",
    )
    max_depth: int = Field(default=8, ge=0, le=100)
    iterations_completed: int = Field(default=0, ge=0)
    non_expanding_iterations: int = Field(
        default=0,
        ge=0,
        description="Consecutive completed targets that added no useful claim or child target.",
    )
    targets_discovered: int = Field(default=0, ge=0)
    stop_conditions: list[str] = Field(
        default_factory=list,
        description="Conditions that end the worklist loop.",
    )
    stop_reason: str | None = Field(
        default=None,
        description="Why the run paused or ended.",
    )

    @model_validator(mode="after")
    def validate_run_invariants(self) -> "AnalysisRun":
        material = f"{self.repository}\n{self.revision}\n{self.objective}".encode()
        expected_run_key = sha256(material).hexdigest()[:24]
        if self.run_key != expected_run_key:
            raise ValueError(
                "run_key must be the first 24 lowercase hex characters of SHA-256 "
                "over repository, revision, and objective separated by newlines"
            )
        if self.run_state in {"paused", "completed", "exhausted", "stale"}:
            if not self.stop_reason:
                raise ValueError("terminal or paused run_state requires stop_reason")
        return self


class AnalysisTarget(BaseModel):
    """One bounded code unit or path waiting on the analysis frontier."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "target_state": {"enum": ["analyzed", "blocked", "skipped"]}
                        },
                        "required": ["target_state"],
                    },
                    "then": {
                        "required": ["summary"],
                        "properties": {"summary": {"type": "string", "minLength": 1}},
                    },
                },
                {
                    "if": {
                        "properties": {"target_state": {"const": "analyzed"}},
                        "required": ["target_state"],
                    },
                    "then": {
                        "required": ["evidence_refs"],
                        "properties": {
                            "evidence_refs": {
                                "type": "array",
                                "minItems": 1,
                            }
                        },
                    },
                },
            ]
        },
    )

    title: str = Field(..., min_length=1, max_length=512)
    run_ref: str = Field(
        ...,
        min_length=1,
        description="Stable ref of the analysis_run that owns this target.",
    )
    target_key: str = Field(
        ...,
        min_length=1,
        description="Stable identity within the revision, such as path::symbol.",
    )
    kind: TargetKind
    location: str = Field(
        ...,
        min_length=1,
        description="File, symbol, endpoint, or graph-node location.",
    )
    priority: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Best-first priority; higher values are processed first.",
    )
    rationale: str = Field(
        ...,
        min_length=1,
        description="Why this target could advance the run objective.",
    )
    target_state: TargetState = Field(default="queued")
    depth: int = Field(default=0, ge=0, le=100)
    parent_ref: str | None = Field(
        default=None,
        description="Ref of the target whose analysis discovered this target.",
    )
    summary: str | None = Field(
        default=None,
        description="Compact conclusion retained after the bounded analysis pass.",
    )
    evidence_refs: list[NonEmptyText] = Field(
        default_factory=list,
        description="Important file:line, tool result, or artifact anchors.",
    )
    open_questions: list[NonEmptyText] = Field(
        default_factory=list,
        description="Questions that may justify new child targets.",
    )
    source_fingerprint: str | None = Field(
        default=None,
        description="Optional content hash used to detect stale conclusions.",
    )

    @model_validator(mode="after")
    def require_terminal_summary(self) -> "AnalysisTarget":
        if self.target_state in {"analyzed", "blocked", "skipped"} and not self.summary:
            raise ValueError("terminal target_state requires summary")
        if self.target_state == "analyzed" and not self.evidence_refs:
            raise ValueError("analyzed target_state requires evidence_refs")
        return self


class AnalysisClaim(BaseModel):
    """An evidence-bearing hypothesis or conclusion about one analysis target."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "disposition": {"const": "verified"},
                            "claim_category": {"const": "vulnerability"},
                        },
                        "required": ["disposition", "claim_category"],
                    },
                    "then": {
                        "required": ["weakness", "severity", "impact"],
                        "properties": {
                            "weakness": {"type": "string", "minLength": 1},
                            "severity": {
                                "enum": [
                                    "critical",
                                    "high",
                                    "medium",
                                    "low",
                                    "info",
                                ]
                            },
                            "impact": {"type": "string", "minLength": 1},
                        },
                    },
                }
            ]
        },
    )

    title: str = Field(..., min_length=1, max_length=512)
    run_ref: str = Field(
        ...,
        min_length=1,
        description="Stable ref of the owning analysis_run.",
    )
    target_ref: str = Field(
        ...,
        min_length=1,
        description="Stable ref of the analysis_target this claim concerns.",
    )
    claim_category: ClaimCategory
    statement: str = Field(..., min_length=1)
    disposition: ClaimDisposition = Field(default="hypothesized")
    confidence: Confidence = Field(default="medium")
    weakness: str | None = Field(
        default=None,
        description=(
            "For vulnerability-category claims, the standard taxonomy anchor: a "
            "CWE id (e.g. 'CWE-89'), OWASP category, or CVE. Grounds the claim in "
            "shared vocabulary and flows into the promoted finding's category."
        ),
    )
    severity: t.Literal["critical", "high", "medium", "low", "info"] | None = Field(
        default=None,
        description=(
            "CVSS-aligned impact estimate for a vulnerability claim, justified by "
            "the evidence. Carries forward to the built-in finding's severity."
        ),
    )
    evidence_refs: list[NonEmptyText] = Field(
        ...,
        min_length=1,
        description="Concrete file:line, trace, tool result, or artifact anchors.",
    )
    counterevidence: list[NonEmptyText] = Field(
        default_factory=list,
        description="Evidence that weakens or refutes the statement.",
    )
    impact: str | None = Field(
        default=None,
        description="Security or analysis consequence if the claim is true.",
    )
    next_steps: list[NonEmptyText] = Field(
        default_factory=list,
        description="Specific checks that could resolve remaining uncertainty.",
    )

    @model_validator(mode="after")
    def require_verified_evidence(self) -> "AnalysisClaim":
        if self.disposition == "verified" and not self.evidence_refs:
            raise ValueError("verified claim requires evidence_refs")
        if self.disposition == "verified" and self.claim_category == "vulnerability":
            missing = [
                name
                for name, value in (
                    ("weakness", self.weakness),
                    ("severity", self.severity),
                    ("impact", self.impact),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "verified vulnerability claim requires " + ", ".join(missing)
                )
        return self
