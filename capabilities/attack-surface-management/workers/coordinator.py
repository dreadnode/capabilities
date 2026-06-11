"""Multi-agent ASM pipeline coordinator.

Subscribes to ``asm.analysis.requested`` and runs a progressive
attack-surface-management pipeline:

    scope normalization
        │
        ▼
    discovery operator
        │
        ▼
    lead enrichment + gadget clustering
        │
        ▼
    final reviewer records high/critical findings
        │
        ▼
    validator fan-out per recorded finding
        │
        ▼
    final report synthesis

The existing ``asm-operator`` remains available for single-agent runs. This
worker is an additive path for long-horizon runs where raw leads should be
progressively enriched into gadgets and findings.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import typing as t
from uuid import uuid4

from dreadnode.capabilities.worker import EventEnvelope, RuntimeClient, Worker
from loguru import logger

CAPABILITY_NAME = "attack-surface-management"

REQUEST_EVENT = "asm.analysis.requested"
PROGRESS_EVENT = "asm.analysis.progress"
REPORT_READY_EVENT = "asm.analysis.report.ready"
COMPLETED_EVENT = "asm.analysis.completed"
FAILED_EVENT = "asm.analysis.failed"

SCOPE_NORMALIZER = "asm-scope-normalizer"
DISCOVERY_OPERATOR = "asm-discovery-operator"
LEAD_ENRICHER = "asm-lead-enricher"
GADGET_CLUSTERER = "asm-gadget-clusterer"
FINAL_REVIEWER = "asm-final-reviewer"
FINDING_VALIDATOR = "asm-finding-validator"
REPORT_SYNTHESIZER = "asm-report-synthesizer"

RECORD_ASM_FINDING_TOOL = "record_asm_finding"

DEFAULT_MAX_STEPS = 240
DEFAULT_VALIDATOR_CONCURRENCY = 2
REPORT_TRUNCATE_CHARS = 24_000
AGENT_TURN_TIMEOUT_SECONDS = 45

worker = Worker(name="coordinator")


@worker.on_event(REQUEST_EVENT)
async def analyze_attack_surface(event: EventEnvelope, client: RuntimeClient) -> None:
    """Run one ASM pipeline end to end."""
    payload = event.payload or {}
    run_id = str(payload.get("run_id") or uuid4())
    model = payload.get("model") or None
    max_steps = int(payload.get("max_steps") or DEFAULT_MAX_STEPS)

    try:
        scope = _normalize_scope_payload(payload)
    except ValueError as exc:
        await client.publish(
            FAILED_EVENT,
            {"run_id": run_id, "error": str(exc), "payload_keys": sorted(payload)},
        )
        return

    try:
        final_report = await _run_pipeline(
            client,
            run_id=run_id,
            scope=scope,
            model=model,
            max_steps=max_steps,
        )
    except Exception as exc:
        logger.exception("ASM analysis run failed | run_id={}", run_id)
        await client.publish(
            FAILED_EVENT,
            {
                "run_id": run_id,
                "target": scope["target"],
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return

    await client.publish(
        COMPLETED_EVENT,
        {"run_id": run_id, "target": scope["target"], "final_report": final_report},
    )


async def _run_pipeline(
    client: RuntimeClient,
    *,
    run_id: str,
    scope: dict[str, t.Any],
    model: str | None,
    max_steps: int,
) -> str:
    target = str(scope["target"])
    scope_context = _render_scope_context(scope)
    scope_steps = _stage_budget(max_steps, 6)
    discovery_steps = _stage_budget(max_steps, 8)
    enrichment_steps = _stage_budget(max_steps, 6)
    review_steps = _stage_budget(max_steps, 6)
    validator_steps = _stage_budget(max_steps, 5)

    await _publish_progress(client, run_id, "scope_started")
    scope_report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=SCOPE_NORMALIZER,
        model=model,
        max_steps=scope_steps,
        prompt=_scope_prompt(scope_context, scope_steps),
    )
    await _publish_report(client, run_id, target, SCOPE_NORMALIZER, scope_report)

    await _publish_progress(client, run_id, "discovery_started")
    discovery_report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=DISCOVERY_OPERATOR,
        model=model,
        max_steps=discovery_steps,
        prompt=_discovery_prompt(scope_context, scope_report, discovery_steps),
    )
    await _publish_report(client, run_id, target, DISCOVERY_OPERATOR, discovery_report)

    await _publish_progress(client, run_id, "enrichment_started")
    enriched_report, gadget_report = await _run_enrichment_stage(
        client,
        run_id=run_id,
        target=target,
        model=model,
        max_steps=enrichment_steps,
        scope_context=scope_context,
        scope_report=scope_report,
        discovery_report=discovery_report,
    )

    await _publish_progress(client, run_id, "final_review_started")
    final_review, final_tool_calls = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=FINAL_REVIEWER,
        model=model,
        max_steps=review_steps,
        prompt=_final_review_prompt(
            scope_context,
            scope_report,
            discovery_report,
            enriched_report,
            gadget_report,
            review_steps,
        ),
    )
    await _publish_report(client, run_id, target, FINAL_REVIEWER, final_review)

    findings = _extract_findings(final_tool_calls)
    if findings:
        await _publish_progress(
            client,
            run_id,
            "validation_started",
            f"Validating {len(findings)} high/critical ASM findings",
        )
        validation_reports = await _run_validators(
            client,
            run_id=run_id,
            target=target,
            model=model,
            max_steps=validator_steps,
            scope_context=scope_context,
            final_review=final_review,
            findings=findings,
        )
    else:
        await _publish_progress(
            client,
            run_id,
            "validation_skipped",
            "No high/critical ASM findings recorded",
        )
        validation_reports = {}

    await _publish_progress(client, run_id, "report_synthesis_started")
    synthesized_report = _fallback_synthesis_report(
        scope_context=scope_context,
        scope_report=scope_report,
        discovery_report=discovery_report,
        enriched_report=enriched_report,
        gadget_report=gadget_report,
        final_review=final_review,
        findings=findings,
        validation_reports=validation_reports,
    )
    await _publish_report(
        client, run_id, target, REPORT_SYNTHESIZER, synthesized_report
    )

    return _build_final_markdown(synthesized_report, findings, validation_reports)


async def _run_enrichment_stage(
    client: RuntimeClient,
    *,
    run_id: str,
    target: str,
    model: str | None,
    max_steps: int,
    scope_context: str,
    scope_report: str,
    discovery_report: str,
) -> tuple[str, str]:
    async def run_one(agent: str, prompt: str) -> tuple[str, str]:
        report, _ = await _run_agent_turn(
            client,
            run_id=run_id,
            target=target,
            agent=agent,
            model=model,
            max_steps=max_steps,
            prompt=prompt,
        )
        await _publish_report(client, run_id, target, agent, report)
        return agent, report

    enriched, gadgets = await asyncio.gather(
        run_one(
            LEAD_ENRICHER,
            _lead_enrichment_prompt(
                scope_context, scope_report, discovery_report, max_steps
            ),
        ),
        run_one(
            GADGET_CLUSTERER,
            _gadget_prompt(scope_context, scope_report, discovery_report, max_steps),
        ),
    )
    return enriched[1], gadgets[1]


async def _run_validators(
    client: RuntimeClient,
    *,
    run_id: str,
    target: str,
    model: str | None,
    max_steps: int,
    scope_context: str,
    final_review: str,
    findings: list[dict[str, t.Any]],
) -> dict[str, str]:
    sem = asyncio.Semaphore(DEFAULT_VALIDATOR_CONCURRENCY)
    final_review = _truncate(final_review, REPORT_TRUNCATE_CHARS)

    async def validate_one(finding: dict[str, t.Any]) -> tuple[str, str]:
        finding_id = str(finding.get("id") or "unknown-finding")
        async with sem:
            report, _ = await _run_agent_turn(
                client,
                run_id=run_id,
                target=target,
                agent=FINDING_VALIDATOR,
                model=model,
                max_steps=max_steps,
                prompt=_validator_prompt(
                    scope_context, final_review, finding, max_steps
                ),
                extra_labels={"finding_id": finding_id},
            )
        return finding_id, report

    results = await asyncio.gather(*(validate_one(finding) for finding in findings))
    return dict(results)


async def _run_agent_turn(
    client: RuntimeClient,
    *,
    run_id: str,
    target: str,
    agent: str,
    model: str | None,
    max_steps: int,
    prompt: str,
    extra_labels: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, t.Any]]]:
    labels: dict[str, list[str]] = {
        "asm_run": [run_id],
        "target": [_label_safe(target)],
        "agent_role": [agent],
    }
    if extra_labels:
        labels.update(
            {key: [_label_safe(value)] for key, value in extra_labels.items()}
        )

    session = await client.create_session(
        capability=CAPABILITY_NAME,
        agent=agent,
        model=model,
        policy={"name": "headless", "max_steps": max_steps},
        labels=labels,
    )
    await client.set_session_title(session.session_id, f"asm {run_id[:8]} · {agent}")
    try:
        result = await asyncio.wait_for(
            client.run_turn(
                session_id=session.session_id,
                message=prompt,
                agent=agent,
                model=model,
                reset=True,
            ),
            timeout=AGENT_TURN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        with contextlib.suppress(Exception):
            await client.cancel_session(session.session_id)
        return (
            f"{agent} timed out after {AGENT_TURN_TIMEOUT_SECONDS}s. "
            "Treat this stage as incomplete and continue with the evidence already available.",
            [],
        )
    response_text = str(result.get("response_text") or "").strip()
    tool_calls = result.get("tool_calls") or []
    if not isinstance(tool_calls, list):
        tool_calls = []
    if tool_calls and not response_text:
        try:
            synthesis_result = await asyncio.wait_for(
                client.run_turn(
                    session_id=session.session_id,
                    message=(
                        "Synthesize this worker stage now using the evidence already gathered. "
                        "Return concise coverage, leads, validation status, rejected noise, and next steps. "
                        "Do not end with an intention to continue."
                    ),
                    agent=agent,
                    model=model,
                    reset=False,
                ),
                timeout=AGENT_TURN_TIMEOUT_SECONDS,
            )
            response_text = str(synthesis_result.get("response_text") or "").strip()
            synthesis_tool_calls = synthesis_result.get("tool_calls") or []
            if isinstance(synthesis_tool_calls, list):
                tool_calls.extend(synthesis_tool_calls)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                await client.cancel_session(session.session_id)
            response_text = (
                f"{agent} gathered tool evidence but timed out while synthesizing it.\n\n"
                f"{_compact_tool_call_summary(tool_calls)}"
            )
    if tool_calls and not response_text:
        response_text = _compact_tool_call_summary(tool_calls)
    return response_text, tool_calls


def _normalize_scope_payload(payload: dict[str, t.Any]) -> dict[str, t.Any]:
    target = str(payload.get("target") or "").strip()
    if not target:
        raise ValueError("missing required target")

    raw_wildcards = payload.get("wildcards") or payload.get("wildcard_scope") or []
    wildcards = _coerce_string_list(raw_wildcards)
    raw_scope = payload.get("scope") or {}

    scope: dict[str, t.Any] = {
        "target": target,
        "wildcards": wildcards,
        "scope": raw_scope,
    }
    for key in (
        "graph_api_url",
        "notes",
        "excluded",
        "allowed_actions",
        "disallowed_actions",
        "max_runtime_seconds",
    ):
        if key in payload and payload[key] not in (None, ""):
            scope[key] = payload[key]
    return scope


def _coerce_string_list(value: t.Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        with contextlib.suppress(Exception):
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return [str(value).strip()]


def _extract_findings(tool_calls: list[dict[str, t.Any]]) -> list[dict[str, t.Any]]:
    findings: list[dict[str, t.Any]] = []
    suffix = f"__{RECORD_ASM_FINDING_TOOL}"
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        name = call.get("name")
        if not isinstance(name, str):
            continue
        if name != RECORD_ASM_FINDING_TOOL and not name.endswith(suffix):
            continue
        args = call.get("arguments")
        if not isinstance(args, dict):
            continue
        severity = str(args.get("severity") or "").strip().lower()
        if severity not in {"high", "critical"}:
            continue
        finding = dict(args)
        finding["severity"] = severity
        finding.setdefault("id", f"ASM-FINDING-{len(findings) + 1:03d}")
        findings.append(finding)
    return findings


def _compact_tool_call_summary(tool_calls: list[dict[str, t.Any]]) -> str:
    sections = ["Tool evidence summary:"]
    for index, call in enumerate(tool_calls[:12], start=1):
        if not isinstance(call, dict):
            continue
        name = str(call.get("name") or call.get("tool_name") or f"tool_call_{index}")
        arguments = call.get("arguments")
        result = (
            call.get("result")
            or call.get("content")
            or call.get("output")
            or call.get("response")
        )
        sections.append(f"\n{index}. {name}")
        if arguments:
            sections.append(
                f"   args: {_truncate(json.dumps(arguments, sort_keys=True, default=str), 500)}"
            )
        if result:
            sections.append(f"   result: {_truncate(str(result), 1200)}")
    if len(tool_calls) > 12:
        sections.append(
            f"\n... {len(tool_calls) - 12} additional tool calls omitted ..."
        )
    return "\n".join(sections)


def _render_scope_context(scope: dict[str, t.Any]) -> str:
    return json.dumps(scope, indent=2, sort_keys=True, default=str)


def _scope_prompt(scope_context: str, max_steps: int) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Normalize this ASM target scope for downstream agents.\n"
        "Do not call scan, web, graph, screenshot, enrichment, or recording tools in this stage. "
        "Use only the provided scope payload and produce a concise scope contract.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n"
    )


def _discovery_prompt(scope_context: str, scope_report: str, max_steps: int) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Perform ASM discovery within the normalized scope.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{scope_report}\n"
    )


def _lead_enrichment_prompt(
    scope_context: str, scope_report: str, discovery_report: str, max_steps: int
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Enrich the most promising ASM leads.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _gadget_prompt(
    scope_context: str, scope_report: str, discovery_report: str, max_steps: int
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Cluster ASM leads into plausible attack-surface gadgets.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _final_review_prompt(
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enriched_report: str,
    gadget_report: str,
    max_steps: int,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Reconcile ASM reports into findings and leads.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Enriched leads:\n{_truncate(enriched_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Gadget clusters:\n{_truncate(gadget_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _validator_prompt(
    scope_context: str,
    final_review: str,
    finding: dict[str, t.Any],
    max_steps: int,
) -> str:
    finding_json = json.dumps(finding, indent=2, sort_keys=True, default=str)
    return (
        f"{_worker_stage_guard()}\n\n"
        "Validate one ASM finding.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Finding:\n```json\n{finding_json}\n```\n\n"
        f"Final review context:\n{final_review}\n"
    )


def _report_synthesis_prompt(
    *,
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enriched_report: str,
    gadget_report: str,
    final_review: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
    max_steps: int,
) -> str:
    findings_json = json.dumps(findings, indent=2, sort_keys=True, default=str)
    validations_json = json.dumps(validation_reports, indent=2, sort_keys=True)
    return (
        f"{_worker_stage_guard()}\n\n"
        "Synthesize the final ASM operator report.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Enriched leads:\n{_truncate(enriched_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Gadget clusters:\n{_truncate(gadget_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Final review:\n{_truncate(final_review, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Recorded findings:\n```json\n{findings_json}\n```\n\n"
        f"Validator reports:\n```json\n{validations_json}\n```\n"
    )


async def _publish_progress(
    client: RuntimeClient, run_id: str, stage: str, detail: str | None = None
) -> None:
    payload: dict[str, t.Any] = {"run_id": run_id, "stage": stage}
    if detail:
        payload["detail"] = detail
    await client.publish(PROGRESS_EVENT, payload)


async def _publish_report(
    client: RuntimeClient, run_id: str, target: str, agent: str, report: str
) -> None:
    await client.publish(
        REPORT_READY_EVENT,
        {"run_id": run_id, "target": target, "agent": agent, "report": report},
    )


def _build_final_markdown(
    synthesized_report: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
) -> str:
    sections = [synthesized_report.rstrip(), "", "## Worker Validation Summary"]
    if not findings:
        sections.append(
            "No high or critical ASM findings were recorded for validator fan-out."
        )
        return "\n".join(sections).rstrip() + "\n"
    sections.append(
        f"Validated {len(validation_reports)} of {len(findings)} recorded high/critical findings."
    )
    for finding in findings:
        finding_id = str(finding.get("id") or "unknown-finding")
        title = str(finding.get("title") or "Untitled finding")
        sections.extend(["", f"### {finding_id}: {title}"])
        sections.append(
            validation_reports.get(finding_id) or "No validator report produced."
        )
    return "\n".join(sections).rstrip() + "\n"


def _fallback_synthesis_report(
    *,
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enriched_report: str,
    gadget_report: str,
    final_review: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
) -> str:
    sections = [
        "# ASM Worker Pipeline Report",
        "",
        "Deterministic synthesis of worker-stage evidence.",
        "",
        "## Discovery",
        _truncate(discovery_report or "No discovery output returned.", 8_000),
        "",
        "## Lead Enrichment",
        _truncate(enriched_report or "No lead-enrichment output returned.", 8_000),
        "",
        "## Gadget Clustering",
        _truncate(gadget_report or "No gadget-clustering output returned.", 8_000),
        "",
        "## Final Review",
        _truncate(final_review or "No final-review output returned.", 8_000),
        "",
        "## Recorded High/Critical Findings",
        json.dumps(findings, indent=2, sort_keys=True, default=str)
        if findings
        else "No high or critical findings were recorded for validator fan-out.",
        "",
        "## Validator Reports",
        json.dumps(validation_reports, indent=2, sort_keys=True, default=str)
        if validation_reports
        else "No validator reports were produced.",
        "",
        "## Scope",
        _truncate(scope_context, 2_000),
        "",
        "## Scope Normalization",
        _truncate(scope_report or "No scope-normalizer output returned.", 3_000),
        "",
        "## Recommended Next Loop",
        "Continue bounded in-scope validation of unresolved leads with direct ASM tools, prioritizing hosts with concrete DNS, HTTP, technology, screenshot, or finding evidence.",
    ]
    return "\n".join(sections).rstrip() + "\n"


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... truncated ..."


def _worker_stage_guard() -> str:
    return (
        "You are already running inside the worker-coordinated ASM pipeline. "
        "Do not call run_asm_worker_pipeline from this stage; use direct ASM "
        "scan, query, enrichment, screenshot, and recording tools as needed."
    )


def _stage_budget(max_steps: int, cap: int) -> int:
    return max(1, min(int(max_steps), cap))


def _label_safe(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value).strip())
    return value[:120] or "unknown"


if __name__ == "__main__":
    worker.run()
