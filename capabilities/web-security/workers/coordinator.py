"""Worker-coordinated web security pentest pipeline.

The worker subscribes to ``web-security.pentest.requested`` and runs a
bounded, headless multi-agent pipeline against one authorized web target. The
existing ``web-security`` interactive agent remains unchanged; this worker is a
second invocation path for repeatable pipeline runs.
"""

from __future__ import annotations

import asyncio
import json
import re
import typing as t
from uuid import uuid4

from dreadnode.capabilities.worker import EventEnvelope, RuntimeClient, Worker
from loguru import logger

CAPABILITY_NAME = "web-security"

REQUEST_EVENT = "web-security.pentest.requested"
PROGRESS_EVENT = "web-security.pentest.progress"
REPORT_READY_EVENT = "web-security.pentest.report.ready"
COMPLETED_EVENT = "web-security.pentest.completed"
FAILED_EVENT = "web-security.pentest.failed"
SKIPPED_EVENT = "web-security.pentest.skipped"

SCOPE_RESOLVER = "ws-scope-resolver"
TARGET_RECON = "ws-target-recon"
TECH_FINGERPRINTER = "ws-tech-fingerprinter"
ATTACK_SURFACE_MAPPER = "ws-attack-surface-mapper"
CHAIN_DISCOVERER = "ws-chain-discoverer"
TRIAGE_REVIEWER = "ws-triage-reviewer"
FINDING_VALIDATOR = "ws-finding-validator"
REPORT_WRITER = "ws-report-writer"

ALWAYS_SPECIALISTS: tuple[str, ...] = (
    "ws-injection-specialist",
    "ws-transport-specialist",
    "ws-ssrf-network-specialist",
    "ws-advanced-specialist",
)
CONDITIONAL_SPECIALISTS: tuple[str, ...] = (
    "ws-client-side-specialist",
    "ws-auth-access-specialist",
    "ws-file-path-specialist",
    "ws-platform-specialist",
)

DEFAULT_MAX_STEPS = 240
DEFAULT_SPECIALIST_CONCURRENCY = 2
DEFAULT_VALIDATOR_CONCURRENCY = 2
FINAL_REPORT_TRUNCATE_CHARS = 24_000
AGENT_TURN_TIMEOUT_SECONDS = 120
RECORD_FINDING_TOOL = "record_ws_finding"
RECON_SKIP_VERDICTS = {"skip", "defer"}

worker = Worker(name="coordinator")


@worker.on_event(REQUEST_EVENT)
async def run_pentest(event: EventEnvelope, client: RuntimeClient) -> None:
    """Run one web pentest pipeline and publish a terminal event."""
    payload = event.payload or {}
    run_id = str(payload.get("run_id") or uuid4())
    target_url = str(payload.get("target_url") or payload.get("url") or "").strip()
    model = payload.get("model") or None
    try:
        max_steps = _coerce_max_steps(payload.get("max_steps"))
    except ValueError as exc:
        await _safe_publish(client, FAILED_EVENT, {"run_id": run_id, "error": str(exc)})
        return

    if not _is_http_url(target_url):
        await _safe_publish(
            client,
            FAILED_EVENT,
            {"run_id": run_id, "error": "missing or invalid target_url"},
        )
        return

    try:
        result = await _run_pipeline(
            client,
            run_id=run_id,
            target_url=target_url,
            payload=payload,
            model=model,
            max_steps=max_steps,
        )
    except Exception as exc:
        logger.exception("web-security pentest failed | run_id={}", run_id)
        await _safe_publish(
            client,
            FAILED_EVENT,
            {
                "run_id": run_id,
                "target_url": target_url,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return

    if isinstance(result, tuple):
        report, verdict = result
        await _safe_publish(
            client,
            SKIPPED_EVENT,
            {
                "run_id": run_id,
                "target_url": target_url,
                "verdict": verdict,
                "recon_report": report,
            },
        )
        return

    await _safe_publish(
        client,
        COMPLETED_EVENT,
        {"run_id": run_id, "target_url": target_url, "final_report": result},
    )


async def _run_pipeline(
    client: RuntimeClient,
    *,
    run_id: str,
    target_url: str,
    payload: dict[str, t.Any],
    model: str | None,
    max_steps: int,
) -> str | tuple[str, str]:
    """Run the nine-stage web-security pipeline."""
    await _publish_progress(client, run_id, "scope_started")
    scope_context, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=SCOPE_RESOLVER,
        model=model,
        max_steps=_stage_budget(max_steps, 6),
        prompt=_scope_prompt(target_url, payload, max_steps),
    )
    await _publish_report(client, run_id, target_url, SCOPE_RESOLVER, scope_context)

    await _publish_progress(client, run_id, "recon_started")
    recon_report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=TARGET_RECON,
        model=model,
        max_steps=_stage_budget(max_steps, 8),
        prompt=_recon_prompt(target_url, max_steps, scope_context),
    )
    await _publish_report(client, run_id, target_url, TARGET_RECON, recon_report)
    verdict = _extract_recon_verdict(recon_report)
    if verdict in RECON_SKIP_VERDICTS:
        return recon_report, verdict

    await _publish_progress(client, run_id, "fingerprint_started")
    tech_profile, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=TECH_FINGERPRINTER,
        model=model,
        max_steps=_stage_budget(max_steps, 10),
        prompt=_fingerprint_prompt(target_url, max_steps, scope_context, recon_report),
    )
    await _publish_report(client, run_id, target_url, TECH_FINGERPRINTER, tech_profile)
    session_snapshot = _extract_session_snapshot(tech_profile)

    await _publish_progress(client, run_id, "mapping_started")
    attack_surface, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=ATTACK_SURFACE_MAPPER,
        model=model,
        max_steps=_stage_budget(max_steps, 12),
        prompt=_mapper_prompt(
            target_url,
            max_steps,
            scope_context,
            recon_report,
            tech_profile,
            session_snapshot,
        ),
    )
    await _publish_report(
        client, run_id, target_url, ATTACK_SURFACE_MAPPER, attack_surface
    )

    specialists = _select_specialists(tech_profile, attack_surface)
    await _publish_progress(
        client,
        run_id,
        "specialists_started",
        f"Running {len(specialists)} specialists",
    )
    specialist_reports = await _run_specialists(
        client,
        run_id=run_id,
        target_url=target_url,
        model=model,
        max_steps=_stage_budget(max_steps, _specialist_budget(max_steps, specialists)),
        specialists=specialists,
        scope_context=scope_context,
        recon_report=recon_report,
        tech_profile=tech_profile,
        attack_surface=attack_surface,
        session_snapshot=session_snapshot,
    )

    await _publish_progress(client, run_id, "chain_discovery_started")
    chain_report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=CHAIN_DISCOVERER,
        model=model,
        max_steps=_stage_budget(max_steps, 8),
        prompt=_chain_prompt(
            target_url,
            max_steps,
            specialist_reports,
            attack_surface,
            session_snapshot,
        ),
    )
    await _publish_report(client, run_id, target_url, CHAIN_DISCOVERER, chain_report)

    await _publish_progress(client, run_id, "triage_started")
    triage_report, triage_tool_calls = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=TRIAGE_REVIEWER,
        model=model,
        max_steps=_stage_budget(max_steps, 10),
        prompt=_triage_prompt(
            target_url,
            max_steps,
            specialist_reports,
            chain_report,
            attack_surface,
            session_snapshot,
        ),
    )
    await _publish_report(client, run_id, target_url, TRIAGE_REVIEWER, triage_report)

    findings = _extract_findings(triage_tool_calls)
    if findings:
        await _publish_progress(
            client,
            run_id,
            "validation_started",
            f"Validating {len(findings)} high/critical findings",
        )
        validation_reports = await _run_validators(
            client,
            run_id=run_id,
            target_url=target_url,
            model=model,
            max_steps=_stage_budget(max_steps, 6),
            findings=findings,
            triage_report=triage_report,
            session_snapshot=session_snapshot,
        )
    else:
        await _publish_progress(
            client,
            run_id,
            "validation_skipped",
            "No high/critical findings recorded",
        )
        validation_reports = {}

    await _publish_progress(client, run_id, "report_started")
    report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target_url=target_url,
        agent=REPORT_WRITER,
        model=model,
        max_steps=_stage_budget(max_steps, 6),
        prompt=_report_prompt(
            target_url,
            max_steps,
            scope_context,
            recon_report,
            tech_profile,
            attack_surface,
            specialist_reports,
            chain_report,
            triage_report,
            findings,
            validation_reports,
        ),
    )
    await _publish_report(client, run_id, target_url, REPORT_WRITER, report)
    return report or _fallback_synthesis_report(
        triage_report, findings, validation_reports
    )


async def _run_specialists(
    client: RuntimeClient,
    *,
    run_id: str,
    target_url: str,
    model: str | None,
    max_steps: int,
    specialists: tuple[str, ...],
    scope_context: str,
    recon_report: str,
    tech_profile: str,
    attack_surface: str,
    session_snapshot: dict[str, t.Any] | None,
) -> dict[str, str]:
    sem = asyncio.Semaphore(DEFAULT_SPECIALIST_CONCURRENCY)

    async def run_one(agent: str) -> tuple[str, str]:
        async with sem:
            report, _ = await _run_agent_turn(
                client,
                run_id=run_id,
                target_url=target_url,
                agent=agent,
                model=model,
                max_steps=max_steps,
                prompt=_specialist_prompt(
                    agent,
                    target_url,
                    max_steps,
                    scope_context,
                    recon_report,
                    tech_profile,
                    attack_surface,
                    session_snapshot,
                ),
            )
        await _publish_report(client, run_id, target_url, agent, report)
        return agent, report

    results = await asyncio.gather(
        *(run_one(agent) for agent in specialists), return_exceptions=True
    )
    reports: dict[str, str] = {}
    for agent, result in zip(specialists, results, strict=True):
        if isinstance(result, Exception):
            logger.exception(
                "specialist stage failed | agent={} run_id={}", agent, run_id
            )
            reports[agent] = f"{agent} failed: {type(result).__name__}: {result}"
            continue
        reports[result[0]] = result[1]
    return reports


async def _run_validators(
    client: RuntimeClient,
    *,
    run_id: str,
    target_url: str,
    model: str | None,
    max_steps: int,
    findings: list[dict[str, t.Any]],
    triage_report: str,
    session_snapshot: dict[str, t.Any] | None,
) -> dict[str, str]:
    sem = asyncio.Semaphore(DEFAULT_VALIDATOR_CONCURRENCY)
    truncated_report = _truncate(triage_report, FINAL_REPORT_TRUNCATE_CHARS)

    async def validate_one(finding: dict[str, t.Any]) -> tuple[str, str]:
        finding_id = str(finding.get("id") or "unknown-finding")
        async with sem:
            report, _ = await _run_agent_turn(
                client,
                run_id=run_id,
                target_url=target_url,
                agent=FINDING_VALIDATOR,
                model=model,
                max_steps=max_steps,
                prompt=_validator_prompt(
                    target_url,
                    max_steps,
                    finding,
                    truncated_report,
                    session_snapshot,
                ),
                extra_labels={"finding_id": finding_id},
            )
        return finding_id, report

    results = await asyncio.gather(
        *(validate_one(finding) for finding in findings), return_exceptions=True
    )
    reports: dict[str, str] = {}
    for finding, result in zip(findings, results, strict=True):
        finding_id = str(finding.get("id") or "unknown-finding")
        if isinstance(result, Exception):
            logger.exception(
                "validator stage failed | finding_id={} run_id={}", finding_id, run_id
            )
            reports[finding_id] = f"Validator failed: {type(result).__name__}: {result}"
            continue
        reports[result[0]] = result[1]
    return reports


async def _run_agent_turn(
    client: RuntimeClient,
    *,
    run_id: str,
    target_url: str,
    agent: str,
    model: str | None,
    max_steps: int,
    prompt: str,
    extra_labels: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, t.Any]]]:
    labels: dict[str, list[str]] = {
        "web_security_run": [_label_safe(run_id)],
        "target_url": [_label_safe(target_url)],
        "agent_role": [_label_safe(agent)],
    }
    if extra_labels:
        for key, value in extra_labels.items():
            labels[_label_safe(key)] = [_label_safe(value)]

    session = await client.create_session(
        capability=CAPABILITY_NAME,
        agent=agent,
        model=model,
        policy={"name": "headless", "max_steps": max_steps},
        labels=labels,
    )
    try:
        await client.set_session_title(
            session.session_id, f"web-security {run_id[:8]} · {agent}"
        )
    except Exception as exc:
        logger.warning(
            "set_session_title failed | agent={} run_id={} error={}", agent, run_id, exc
        )
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
        logger.warning("agent turn timed out | agent={} run_id={}", agent, run_id)
        await _cancel_session_best_effort(
            client, session.session_id, agent=agent, run_id=run_id
        )
        return (
            f"{agent} timed out after {AGENT_TURN_TIMEOUT_SECONDS}s. "
            "Treat this stage as incomplete and continue with available evidence.",
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
                        "Do not call worker pipeline launch tools. Do not end with an intention to continue."
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
            logger.warning(
                "agent synthesis timed out | agent={} run_id={}", agent, run_id
            )
            await _cancel_session_best_effort(
                client, session.session_id, agent=agent, run_id=run_id
            )
            response_text = (
                f"{agent} gathered tool evidence but timed out while synthesizing it.\n\n"
                f"{_compact_tool_call_summary(tool_calls)}"
            )

    if tool_calls and not response_text:
        response_text = _compact_tool_call_summary(tool_calls)
    return response_text, tool_calls


def _scope_prompt(target_url: str, payload: dict[str, t.Any], max_steps: int) -> str:
    payload_json = json.dumps(_safe_payload(payload), indent=2, sort_keys=True)
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Resolve testing scope for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Request payload:\n```json\n{payload_json}\n```\n"
    )


def _recon_prompt(target_url: str, max_steps: int, scope_context: str) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Run non-invasive target reconnaissance for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope context:\n{_truncate(scope_context, 12_000)}\n"
    )


def _fingerprint_prompt(
    target_url: str, max_steps: int, scope_context: str, recon_report: str
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Fingerprint technology and bootstrap any provided session for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Scope context:\n{_truncate(scope_context, 8_000)}\n\n"
        f"Recon report:\n{_truncate(recon_report, 8_000)}\n"
    )


def _mapper_prompt(
    target_url: str,
    max_steps: int,
    scope_context: str,
    recon_report: str,
    tech_profile: str,
    session_snapshot: dict[str, t.Any] | None,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Map the application attack surface for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Session snapshot:\n{_json_block(session_snapshot)}\n\n"
        f"Scope context:\n{_truncate(scope_context, 8_000)}\n\n"
        f"Recon report:\n{_truncate(recon_report, 8_000)}\n\n"
        f"Technology profile:\n{_truncate(tech_profile, 8_000)}\n"
    )


def _specialist_prompt(
    agent: str,
    target_url: str,
    max_steps: int,
    scope_context: str,
    recon_report: str,
    tech_profile: str,
    attack_surface: str,
    session_snapshot: dict[str, t.Any] | None,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Analyze {target_url} as {agent}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Session snapshot:\n{_json_block(session_snapshot)}\n\n"
        f"Attack surface map (leads, not conclusions):\n"
        f"{_truncate(attack_surface, 16_000)}\n\n"
        f"Technology profile:\n{_truncate(tech_profile, 8_000)}\n\n"
        f"Recon report:\n{_truncate(recon_report, 4_000)}\n\n"
        f"Scope context:\n{_truncate(scope_context, 4_000)}\n"
    )


def _chain_prompt(
    target_url: str,
    max_steps: int,
    specialist_reports: dict[str, str],
    attack_surface: str,
    session_snapshot: dict[str, t.Any] | None,
) -> str:
    rendered = _render_reports(specialist_reports)
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Discover cross-specialist exploit chains for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Session snapshot:\n{_json_block(session_snapshot)}\n\n"
        f"Attack surface map:\n{_truncate(attack_surface, 12_000)}\n\n"
        f"Specialist reports:\n{rendered}\n"
    )


def _triage_prompt(
    target_url: str,
    max_steps: int,
    specialist_reports: dict[str, str],
    chain_report: str,
    attack_surface: str,
    session_snapshot: dict[str, t.Any] | None,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Triage and final-review web security leads for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Record every confirmed high/critical finding with record_ws_finding().\n\n"
        f"Session snapshot:\n{_json_block(session_snapshot)}\n\n"
        f"Attack surface map:\n{_truncate(attack_surface, 12_000)}\n\n"
        f"Chain discovery report:\n{_truncate(chain_report, 12_000)}\n\n"
        f"Specialist reports:\n{_render_reports(specialist_reports)}\n"
    )


def _validator_prompt(
    target_url: str,
    max_steps: int,
    finding: dict[str, t.Any],
    triage_report: str,
    session_snapshot: dict[str, t.Any] | None,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Validate one web-security finding for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Session snapshot:\n{_json_block(session_snapshot)}\n\n"
        f"Finding to validate:\n```json\n"
        f"{json.dumps(finding, indent=2, sort_keys=True)}\n```\n\n"
        f"Triage context:\n{triage_report}\n"
    )


def _report_prompt(
    target_url: str,
    max_steps: int,
    scope_context: str,
    recon_report: str,
    tech_profile: str,
    attack_surface: str,
    specialist_reports: dict[str, str],
    chain_report: str,
    triage_report: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        f"Write the final web-security report for {target_url}.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Recorded findings:\n```json\n"
        f"{json.dumps(findings, indent=2, sort_keys=True)}\n```\n\n"
        f"Validation reports:\n{_render_reports(validation_reports)}\n\n"
        f"Triage report:\n{_truncate(triage_report, 16_000)}\n\n"
        f"Chain discovery report:\n{_truncate(chain_report, 8_000)}\n\n"
        f"Specialist reports:\n{_render_reports(specialist_reports)}\n\n"
        f"Attack surface map:\n{_truncate(attack_surface, 8_000)}\n\n"
        f"Technology profile:\n{_truncate(tech_profile, 6_000)}\n\n"
        f"Recon report:\n{_truncate(recon_report, 6_000)}\n\n"
        f"Scope context:\n{_truncate(scope_context, 6_000)}\n"
    )


def _extract_recon_verdict(recon_report: str) -> str:
    heading = re.search(r"##\s*Verdict[:\s]*([^\n]+)", recon_report, re.IGNORECASE)
    if heading:
        line = heading.group(1).strip().lower().replace(" ", "_")
        for keyword in ("skip", "defer", "proceed_with_caution", "proceed"):
            if keyword in line:
                return keyword

    inline = re.search(
        r"verdict\s*[:—]\s*(skip|defer|proceed[_ ]with[_ ]caution|proceed)\b",
        recon_report,
        re.IGNORECASE,
    )
    if inline:
        return inline.group(1).strip().lower().replace(" ", "_")
    return "proceed"


def _select_specialists(tech_profile: str, attack_surface: str) -> tuple[str, ...]:
    """Choose specialists from stage context. Fail open for core specialists."""
    text = f"{tech_profile}\n{attack_surface}".lower()
    selected = list(ALWAYS_SPECIALISTS)

    if _mentions_any(
        text, ("javascript", "script", "dom", "csp", "react", "vue", "angular")
    ):
        selected.append("ws-client-side-specialist")
    if _mentions_any(
        text, ("auth", "login", "oauth", "session", "jwt", "role", "permission")
    ):
        selected.append("ws-auth-access-specialist")
    if _mentions_any(text, ("upload", "download", "file", "archive", "path", "mime")):
        selected.append("ws-file-path-specialist")
    if _mentions_any(text, ("aem", "sling", "salesforce", "aura", "grpc", "apache")):
        selected.append("ws-platform-specialist")

    return tuple(dict.fromkeys(selected))


def _extract_session_snapshot(text: str) -> dict[str, t.Any] | None:
    """Extract the first JSON block with session-like keys from agent output."""
    for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError as exc:
            logger.warning("session snapshot JSON parse failed: {}", exc)
            continue
        if isinstance(data, dict) and _looks_like_session_snapshot(data):
            return data
    return None


def _extract_findings(tool_calls: list[dict[str, t.Any]]) -> list[dict[str, t.Any]]:
    findings: list[dict[str, t.Any]] = []
    suffix = f"__{RECORD_FINDING_TOOL}"
    for call in tool_calls:
        if not isinstance(call, dict):
            logger.warning("ignored malformed tool call: not a dict")
            continue
        name = call.get("name") or ""
        if not isinstance(name, str):
            logger.warning("ignored malformed tool call with non-string name: {}", name)
            continue
        if name != RECORD_FINDING_TOOL and not name.endswith(suffix):
            continue
        args = call.get("arguments")
        if not isinstance(args, dict):
            logger.warning("ignored {} call with non-dict arguments", name)
            continue
        severity = str(args.get("severity") or "").strip().lower()
        if severity not in {"high", "critical"}:
            logger.warning(
                "ignored {} call with non-validator severity: {}", name, severity
            )
            continue
        finding = dict(args)
        finding["severity"] = severity
        finding.setdefault("id", f"WS-FINDING-{len(findings) + 1:03d}")
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


def _is_http_url(url: str) -> bool:
    return bool(re.match(r"^https?://[^\s/$.?#][^\s]*$", url))


def _mentions_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _looks_like_session_snapshot(data: dict[str, t.Any]) -> bool:
    keys = {str(key).lower() for key in data}
    return bool(
        keys
        & {"cookies", "headers", "authorization", "base_url", "auth_type", "user_role"}
    )


def _stage_budget(max_steps: int, preferred: int) -> int:
    return max(1, min(max_steps, preferred))


def _coerce_max_steps(value: t.Any) -> int:
    if value in (None, ""):
        return DEFAULT_MAX_STEPS
    try:
        max_steps = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid max_steps; expected integer") from exc
    return max(1, max_steps)


def _specialist_budget(max_steps: int, specialists: tuple[str, ...]) -> int:
    reserved = 6 + 8 + 10 + 12 + 8 + 10 + 6
    remaining = max(max_steps - reserved, len(specialists) * 6)
    return max(6, remaining // max(1, len(specialists)))


def _safe_payload(payload: dict[str, t.Any]) -> dict[str, t.Any]:
    return t.cast(dict[str, t.Any], _redact_secrets(payload))


def _redact_secrets(value: t.Any) -> t.Any:
    hidden = {
        "password",
        "token",
        "secret",
        "api_key",
        "authorization",
        "credential",
        "cookie",
        "session",
        "bearer",
    }
    if isinstance(value, dict):
        redacted: dict[str, t.Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(part in key_text.lower() for part in hidden):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


def _json_block(data: dict[str, t.Any] | None) -> str:
    if not data:
        return "```json\n{}\n```"
    return f"```json\n{json.dumps(data, indent=2, sort_keys=True)}\n```"


def _render_reports(reports: dict[str, str]) -> str:
    return "\n\n".join(
        f"# {name}\n{_truncate(report, FINAL_REPORT_TRUNCATE_CHARS)}"
        for name, report in reports.items()
    )


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... truncated ..."


def _worker_stage_guard() -> str:
    return (
        "You are already running inside the worker-coordinated web-security pipeline. "
        "Do not call tools or workflows that launch another web-security worker pipeline from this stage; "
        "use direct HTTP, browser, proxy, credential, callback, and reporting tools only as appropriate."
    )


async def _safe_publish(
    client: RuntimeClient, event: str, payload: dict[str, t.Any]
) -> None:
    try:
        await client.publish(event, payload)
    except Exception as exc:
        logger.warning("event publish failed | event={} error={}", event, exc)


async def _cancel_session_best_effort(
    client: RuntimeClient, session_id: str, *, agent: str, run_id: str
) -> None:
    try:
        await client.cancel_session(session_id)
    except Exception as exc:
        logger.warning(
            "cancel_session failed | agent={} run_id={} session_id={} error={}",
            agent,
            run_id,
            session_id,
            exc,
        )


def _label_safe(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value).strip())
    return text[:120] or "unknown"


async def _publish_progress(
    client: RuntimeClient, run_id: str, stage: str, detail: str | None = None
) -> None:
    payload: dict[str, t.Any] = {"run_id": run_id, "stage": stage}
    if detail:
        payload["detail"] = detail
    await _safe_publish(client, PROGRESS_EVENT, payload)


async def _publish_report(
    client: RuntimeClient, run_id: str, target_url: str, agent: str, report: str
) -> None:
    await _safe_publish(
        client,
        REPORT_READY_EVENT,
        {"run_id": run_id, "target_url": target_url, "agent": agent, "report": report},
    )


def _fallback_synthesis_report(
    triage_report: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
) -> str:
    sections = [triage_report.rstrip(), "", "## Validator Results"]
    if not findings:
        sections.append(
            "No high or critical findings recorded; validators were not run."
        )
    for finding in findings:
        finding_id = str(finding.get("id") or "unknown-finding")
        title = str(finding.get("title") or "Untitled finding")
        sections.extend(["", f"### {finding_id}: {title}"])
        sections.append(
            validation_reports.get(finding_id)
            or "Validator report was not produced for this finding."
        )
    return "\n".join(sections).rstrip() + "\n"


if __name__ == "__main__":
    worker.run()
