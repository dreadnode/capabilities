"""Structured item types for the web-security capability.

These Pydantic models define the schemas for items emitted via
``report_item`` during web application pentesting, bug bounty, and
vulnerability research engagements. They are referenced by the
``produces`` key in ``capability.yaml`` and validated at emit time
so the agent gets immediate feedback on malformed payloads.

The platform's built-in ``finding`` and ``asset`` types are also
enabled alongside these domain-specific types.

Design principles
-----------------
- Fields mirror what bug bounty platforms (HackerOne, Bugcrowd),
  vuln databases (NVD, CWE/MITRE), and professional pentest reports
  actually require — not theoretical nice-to-haves.
- Optional fields are genuinely optional: a black-box tester may not
  have source-level detail, and that's fine.
- CVSS vectors are stored as strings so the platform can parse and
  render them; scores are floats for filtering/sorting.
- Evidence fields accept markdown so the agent can embed HTTP
  request/response pairs, code snippets, and reproduction steps
  inline.
"""

from __future__ import annotations

import typing as t

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Shared enums / literals
# ---------------------------------------------------------------------------

Severity = t.Literal["critical", "high", "medium", "low", "informational"]

Confidence = t.Literal["confirmed", "firm", "tentative"]
"""
PTES/OWASP-style confidence:
- confirmed: PoC executed, impact demonstrated
- firm: strong evidence, reproduction pending or partial
- tentative: pattern match or behavioral signal, needs validation
"""

ValidationVerdict = t.Literal[
    "confirmed",
    "chain_confirmed",
    "partially_confirmed",
    "cannot_reproduce",
    "false_positive",
    "untested",
]
"""Mirrors the finding-validator agent's verdict vocabulary."""


# ---------------------------------------------------------------------------
# Web Vulnerability — the core deliverable
# ---------------------------------------------------------------------------


class CvssV31(BaseModel):
    """CVSS 3.1 score and vector string."""

    model_config = ConfigDict(extra="ignore")

    vector: str = Field(
        ...,
        description=(
            "Full CVSS 3.1 vector string, e.g. "
            "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'."
        ),
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS 3.1 base score (0.0–10.0).",
    )


class CvssV40(BaseModel):
    """CVSS 4.0 score and vector string."""

    model_config = ConfigDict(extra="ignore")

    vector: str = Field(
        ...,
        description=(
            "Full CVSS 4.0 vector string, e.g. "
            "'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'."
        ),
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS 4.0 base score (0.0–10.0).",
    )


class WebVulnerability(BaseModel):
    """A confirmed or suspected web application vulnerability.

    The primary structured output for web pentesting, bug bounty, and
    vulnerability research. Captures everything needed for triage,
    reporting, and downstream validation — from a quick blind-SSRF
    lead to a fully reproduced IDOR chain with CVSS scores.
    """

    model_config = ConfigDict(extra="ignore")

    # -- Identity & classification ----------------------------------------

    title: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "Short, specific title. Format: "
            "'[Vuln Type] in [Component] via [Vector] leading to [Impact]'. "
            "Example: 'Stored XSS in Comment Renderer via Markdown Image Alt Text'."
        ),
    )
    severity: Severity = Field(
        ...,
        description="Impact-based severity: critical, high, medium, low, or informational.",
    )
    confidence: Confidence = Field(
        "tentative",
        description=(
            "How solidly the vulnerability is established. "
            "'confirmed' = PoC executed with demonstrated impact. "
            "'firm' = strong evidence, reproduction pending or partial. "
            "'tentative' = behavioral signal or pattern match, needs validation."
        ),
    )
    vulnerability_class: str | None = Field(
        None,
        description=(
            "Vulnerability family name. Examples: 'SQL Injection', "
            "'Stored XSS', 'IDOR', 'SSRF', 'SSTI', 'Broken Access Control', "
            "'Race Condition', 'Path Traversal', 'Open Redirect', "
            "'Prompt Injection'."
        ),
    )
    cwe: str | None = Field(
        None,
        description="CWE identifier, e.g. 'CWE-89' for SQL Injection.",
    )
    owasp_category: str | None = Field(
        None,
        description=(
            "OWASP Top 10 (2021) category, e.g. 'A01:2021 – Broken Access Control'."
        ),
    )

    # -- Affected surface -------------------------------------------------

    affected_endpoint: str = Field(
        ...,
        description=(
            "Primary affected URL or API endpoint, including method if relevant. "
            "Example: 'POST https://api.example.com/v2/users/{id}/profile'."
        ),
    )
    affected_parameter: str | None = Field(
        None,
        description=(
            "The specific parameter, header, cookie, or input field that carries "
            "the payload or is misconfigured. Example: 'user_id (path parameter)', "
            "'X-Forwarded-Host (header)', 'comment (JSON body field)'."
        ),
    )
    affected_component: str | None = Field(
        None,
        description=(
            "Application component, feature, or module affected. "
            "Example: 'User Profile API', 'Payment Webhook Handler', "
            "'Admin Dashboard'."
        ),
    )

    # -- Evidence & reproduction ------------------------------------------

    description: str = Field(
        ...,
        description=(
            "Technical root cause explanation. What is wrong and why it is "
            "exploitable. 2–4 paragraphs. Do NOT repeat the title or PoC steps."
        ),
    )
    evidence: str | None = Field(
        None,
        description=(
            "Concrete proof in markdown: HTTP request/response pairs, payloads, "
            "status codes, screenshots references, OOB callback logs, extracted "
            "data samples, or timing measurements. Use fenced code blocks for "
            "HTTP exchanges."
        ),
    )
    reproduction_steps: str | None = Field(
        None,
        description=(
            "Numbered step-by-step reproduction instructions. Must be "
            "independently reproducible — no assumed context. Include exact "
            "URLs, payloads, and expected responses."
        ),
    )

    # -- Impact & scoring -------------------------------------------------

    impact: str | None = Field(
        None,
        description=(
            "What the attacker gains: data exfiltration, account takeover, "
            "RCE, privilege escalation, etc. State the before/after delta. "
            "Concrete demonstrated impact, not theoretical worst-case."
        ),
    )
    cvss_v31: CvssV31 | None = Field(
        None,
        description="CVSS 3.1 base score and vector string.",
    )
    cvss_v40: CvssV40 | None = Field(
        None,
        description="CVSS 4.0 base score and vector string.",
    )

    # -- Attacker model ---------------------------------------------------

    attacker_capability: str | None = Field(
        None,
        description=(
            "What the attacker must already have or be able to do. "
            "Examples: 'Unauthenticated network access', "
            "'Authenticated as low-privilege user', "
            "'Victim must click a crafted link'."
        ),
    )
    exploit_prerequisites: str | None = Field(
        None,
        description=(
            "Environmental conditions required for exploitation. "
            "'default' if no special config is needed. Otherwise: "
            "versions, features, deployment mode, etc."
        ),
    )

    # -- Validation state -------------------------------------------------

    validation_verdict: ValidationVerdict = Field(
        "untested",
        description=(
            "Current validation status. Set to 'confirmed' only when PoC "
            "is fully reproduced with demonstrated impact."
        ),
    )
    suggested_chain: str | None = Field(
        None,
        description=(
            "If this finding chains with another (e.g. SSRF → cloud metadata, "
            "open redirect → OAuth token theft), describe the second leg and "
            "the escalated impact."
        ),
    )

    # -- Metadata ---------------------------------------------------------

    metadata: dict[str, t.Any] = Field(
        default_factory=dict,
        description=(
            "Additional machine-readable context. Common keys: "
            "'tech_stack', 'waf_detected', 'program_handle', "
            "'bug_bounty_platform', 'confidence_trace_id'."
        ),
    )


# ---------------------------------------------------------------------------
# Web Endpoint — discovered attack surface
# ---------------------------------------------------------------------------


class WebEndpoint(BaseModel):
    """A discovered web endpoint, service, or API surface worth tracking.

    Use for mapping the attack surface: API endpoints, admin panels,
    authenticated routes, interesting parameters, technology
    fingerprints, and other assets the agent discovers during recon
    or testing that may be relevant to current or future findings.
    """

    model_config = ConfigDict(extra="ignore")

    title: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "Short label for the endpoint or service. "
            "Example: 'Admin API — user management', "
            "'GraphQL introspection endpoint', "
            "'S3 bucket (public-read)'."
        ),
    )
    url: str = Field(
        ...,
        description=(
            "Full URL or URL pattern. "
            "Example: 'https://api.example.com/admin/users', "
            "'https://cdn.example.com/assets/*'."
        ),
    )
    method: str | None = Field(
        None,
        description="HTTP method if specific. Example: 'POST', 'PUT', 'DELETE'.",
    )
    endpoint_type: str | None = Field(
        None,
        description=(
            "Kind of endpoint. Examples: 'api', 'admin_panel', 'webhook', "
            "'graphql', 'websocket', 'file_upload', 'auth', 'oauth', "
            "'health_check', 'debug', 'static_asset', 'cdn'."
        ),
    )
    technology: str | None = Field(
        None,
        description=(
            "Detected technology, framework, or server. "
            "Example: 'Express.js', 'Spring Boot', 'Next.js', "
            "'Apache httpd 2.4', 'Cloudflare'."
        ),
    )
    auth_required: bool | None = Field(
        None,
        description="Whether this endpoint requires authentication.",
    )
    description: str | None = Field(
        None,
        description="What this endpoint does and why it is interesting.",
    )
    response_fingerprint: str | None = Field(
        None,
        description=(
            "Key response characteristics: status code, notable headers, "
            "content type, or distinguishing response features. "
            "Example: '200 OK, application/json, x-powered-by: Express'."
        ),
    )
    parameters: list[str] | None = Field(
        None,
        description=(
            "Interesting parameters, headers, or input fields observed. "
            "Example: ['user_id', 'redirect_url', 'X-Forwarded-For']."
        ),
    )
    metadata: dict[str, t.Any] = Field(
        default_factory=dict,
        description=(
            "Additional machine-readable context. Common keys: "
            "'cors_policy', 'csp_header', 'waf', 'cdn', "
            "'openapi_spec_url', 'rate_limited'."
        ),
    )


# ---------------------------------------------------------------------------
# Forward-reference finalization
# ---------------------------------------------------------------------------
#
# This module uses ``from __future__ import annotations`` (PEP 563), so every
# field annotation is stored as a string and resolved lazily on first schema
# build. The Dreadnode capability loader and OCI packager import this file by
# path (``importlib.util.spec_from_file_location`` + ``exec_module``) WITHOUT
# registering it in ``sys.modules``. In that state, Pydantic's deferred
# forward-reference resolution cannot locate this module's namespace, so the
# first ``model_json_schema()`` call — which the ``report_item`` tool build and
# the package builder both make — raises ``PydanticUserError: ... is not fully
# defined``. That failure is swallowed upstream, silently dropping the typed
# ``report_item`` tool and every structured output type this capability
# declares in ``produces``.
#
# Rebuilding each model here, at module scope, resolves every forward reference
# against this module's globals while they are still in scope — independent of
# how the module was imported. The loop covers all models defined above and any
# added later, so new types are finalized automatically with no extra wiring.
for _model in list(globals().values()):
    if (
        isinstance(_model, type)
        and issubclass(_model, BaseModel)
        and _model is not BaseModel
    ):
        _model.model_rebuild()
del _model
