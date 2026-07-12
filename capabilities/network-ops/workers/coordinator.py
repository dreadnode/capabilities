"""Multi-agent network operations pipeline coordinator.

Subscribes to ``netops.engagement.requested`` and runs a progressive
AD exploitation pipeline:

    scope normalization
        │
        ▼
    network discovery
        │
        ▼
    AD enumeration
        │
        ▼
    exploitation (initial access + privilege escalation)
        │
        ▼
    credential harvesting
        │
        ▼
    report synthesis

The existing ``network-ops-agent`` remains available for single-agent runs.
This worker is an additive path for long-horizon engagements where each
phase should be handled by a specialized agent.
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

CAPABILITY_NAME = "network-ops"

REQUEST_EVENT = "netops.engagement.requested"
PROGRESS_EVENT = "netops.engagement.progress"
REPORT_READY_EVENT = "netops.engagement.report.ready"
COMPLETED_EVENT = "netops.engagement.completed"
FAILED_EVENT = "netops.engagement.failed"

SCOPE_NORMALIZER = "netops-scope-normalizer"
DISCOVERY_OPERATOR = "netops-discovery-operator"
AD_ENUMERATOR = "netops-ad-enumerator"
EXPLOIT_OPERATOR = "netops-exploit-operator"
CREDENTIAL_HARVESTER = "netops-credential-harvester"
REPORT_SYNTHESIZER = "netops-report-synthesizer"

REPORT_ITEM_TOOL = "report_item"

DEFAULT_MAX_STEPS = 240
REPORT_TRUNCATE_CHARS = 24_000
AGENT_TURN_TIMEOUT_SECONDS = 300
MAX_TOOL_CALLS_IN_SUMMARY = 12
_TIMEOUT_SENTINEL = "[NETOPS_STAGE_TIMEOUT]"

worker = Worker(name="coordinator")


@worker.on_event(REQUEST_EVENT)
async def run_engagement(event: EventEnvelope, client: RuntimeClient) -> None:
    """Run one network operations engagement pipeline end to end."""
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
        logger.exception("Network ops engagement failed | run_id={}", run_id)
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
    discovery_steps = _stage_budget(max_steps, 30)
    enumeration_steps = _stage_budget(max_steps, 40)
    exploit_steps = _stage_budget(max_steps, 50)
    harvest_steps = _stage_budget(max_steps, 30)
    synthesis_steps = _stage_budget(max_steps, 10)

    # --- Stage 1: Scope Normalization ---
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

    # --- Stage 2: Network Discovery ---
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

    # --- Stage 3: AD Enumeration ---
    await _publish_progress(client, run_id, "enumeration_started")
    enumeration_report, enumeration_tool_calls = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=AD_ENUMERATOR,
        model=model,
        max_steps=enumeration_steps,
        prompt=_enumeration_prompt(
            scope_context, scope_report, discovery_report, enumeration_steps
        ),
    )
    await _publish_report(client, run_id, target, AD_ENUMERATOR, enumeration_report)

    # --- Stage 4: Exploitation ---
    await _publish_progress(client, run_id, "exploitation_started")
    exploit_report, exploit_tool_calls = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=EXPLOIT_OPERATOR,
        model=model,
        max_steps=exploit_steps,
        prompt=_exploit_prompt(
            scope_context,
            scope_report,
            discovery_report,
            enumeration_report,
            exploit_steps,
        ),
    )
    await _publish_report(client, run_id, target, EXPLOIT_OPERATOR, exploit_report)

    # --- Stage 5: Credential Harvesting ---
    await _publish_progress(client, run_id, "harvesting_started")
    harvest_report, harvest_tool_calls = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=CREDENTIAL_HARVESTER,
        model=model,
        max_steps=harvest_steps,
        prompt=_harvest_prompt(
            scope_context,
            scope_report,
            discovery_report,
            enumeration_report,
            exploit_report,
            harvest_steps,
        ),
    )
    await _publish_report(
        client, run_id, target, CREDENTIAL_HARVESTER, harvest_report
    )

    # --- Stage 6: Report Synthesis ---
    await _publish_progress(client, run_id, "report_synthesis_started")

    all_tool_calls = enumeration_tool_calls + exploit_tool_calls + harvest_tool_calls
    findings = _extract_findings(all_tool_calls)

    synthesis_report, _ = await _run_agent_turn(
        client,
        run_id=run_id,
        target=target,
        agent=REPORT_SYNTHESIZER,
        model=model,
        max_steps=synthesis_steps,
        prompt=_synthesis_prompt(
            scope_context=scope_context,
            scope_report=scope_report,
            discovery_report=discovery_report,
            enumeration_report=enumeration_report,
            exploit_report=exploit_report,
            harvest_report=harvest_report,
            findings=findings,
            max_steps=synthesis_steps,
        ),
    )

    if not synthesis_report or _TIMEOUT_SENTINEL in synthesis_report:
        synthesis_report = _fallback_synthesis_report(
            scope_context=scope_context,
            scope_report=scope_report,
            discovery_report=discovery_report,
            enumeration_report=enumeration_report,
            exploit_report=exploit_report,
            harvest_report=harvest_report,
            findings=findings,
        )

    await _publish_report(
        client, run_id, target, REPORT_SYNTHESIZER, synthesis_report
    )

    return synthesis_report


# ---------------------------------------------------------------------------
# Agent turn execution
# ---------------------------------------------------------------------------


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
    """Run a single agent turn and return ``(response_text, tool_calls)``.

    If the agent produces tool calls but no response text, a second
    synthesis turn is attempted.  If that also times out, tool calls are
    compacted into a text summary so downstream stages still have evidence.
    """
    labels: dict[str, list[str]] = {
        "netops_run": [run_id],
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
    await client.set_session_title(
        session.session_id, f"netops {run_id[:8]} · {agent}"
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
        with contextlib.suppress(Exception):
            await client.cancel_session(session.session_id)
        return (
            f"{_TIMEOUT_SENTINEL} {agent} timed out after "
            f"{AGENT_TURN_TIMEOUT_SECONDS}s. Treat this stage as incomplete "
            "and continue with the evidence already available.",
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
                        "Synthesize this stage now using the evidence already "
                        "gathered. Return concise findings, credentials, access "
                        "gained, and next steps. Do not end with an intention "
                        "to continue."
                    ),
                    agent=agent,
                    model=model,
                    reset=False,
                ),
                timeout=AGENT_TURN_TIMEOUT_SECONDS,
            )
            response_text = str(
                synthesis_result.get("response_text") or ""
            ).strip()
            synthesis_tool_calls = synthesis_result.get("tool_calls") or []
            if isinstance(synthesis_tool_calls, list):
                tool_calls.extend(synthesis_tool_calls)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                await client.cancel_session(session.session_id)
            response_text = (
                f"{_TIMEOUT_SENTINEL} {agent} gathered tool evidence but "
                f"timed out while synthesizing it.\n\n"
                f"{_compact_tool_call_summary(tool_calls)}"
            )

    if tool_calls and not response_text:
        response_text = _compact_tool_call_summary(tool_calls)

    return response_text, tool_calls


# ---------------------------------------------------------------------------
# Scope handling
# ---------------------------------------------------------------------------


def _normalize_scope_payload(payload: dict[str, t.Any]) -> dict[str, t.Any]:
    """Validate and extract scope fields from the event payload."""
    target = str(payload.get("target") or "").strip()
    if not target:
        raise ValueError("missing required target")

    scope: dict[str, t.Any] = {"target": target}

    for key in (
        "network_ranges",
        "domain",
        "domains",
        "credentials",
        "initial_credentials",
        "exclusions",
        "rules_of_engagement",
        "notes",
        "dc_ips",
        "max_runtime_seconds",
    ):
        if key in payload and payload[key] not in (None, ""):
            scope[key] = payload[key]

    return scope


# ---------------------------------------------------------------------------
# Finding extraction
# ---------------------------------------------------------------------------


_HIGH_VALUE_FIELDS: frozenset[str] = frozenset({
    # Credential model fields
    "text",
    # Hash model fields
    "hash_value",
    # Weakness model fields
    "severity",
})


def _extract_findings(
    tool_calls: list[dict[str, t.Any]],
) -> list[dict[str, t.Any]]:
    """Extract high-value report_item calls (credentials, hashes, weaknesses).

    Enumeration items (targets, users, shares, DCs) are already captured in
    stage report prose.  Only attack results are extracted as structured
    findings for the synthesis prompt.
    """
    findings: list[dict[str, t.Any]] = []
    suffix = f"__{REPORT_ITEM_TOOL}"
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        name = call.get("name")
        if not isinstance(name, str):
            continue
        if name != REPORT_ITEM_TOOL and not name.endswith(suffix):
            continue
        args = call.get("arguments")
        if not isinstance(args, dict):
            continue
        # The item field may be a nested dict (union discriminator) or flat.
        item = args.get("item") if "item" in args else args
        if not isinstance(item, dict):
            continue
        if not _HIGH_VALUE_FIELDS & item.keys():
            continue
        finding = dict(item)
        finding.setdefault("id", f"NETOPS-FINDING-{len(findings) + 1:03d}")
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------


def _scope_prompt(scope_context: str, max_steps: int) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Normalize this engagement scope for downstream agents.\n"
        "Do not perform scanning or active testing in this stage. "
        "Parse the provided payload and produce a scope operating brief.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n"
    )


def _discovery_prompt(
    scope_context: str, scope_report: str, max_steps: int
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Perform network discovery within the normalized scope.\n"
        "Use Nmap to scan for hosts, ports, and services. Report findings "
        "using the reporting tool.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{scope_report}\n"
    )


def _enumeration_prompt(
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    max_steps: int,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Enumerate the Active Directory environment using discovered hosts "
        "and available credentials.\n"
        "Use netexec, SharpView, smbclient, and Certipy find. Report "
        "findings using the reporting tool.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _exploit_prompt(
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enumeration_report: str,
    max_steps: int,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Execute AD attack chains based on enumeration findings.\n"
        "Prioritize: Kerberoasting, AS-REP roasting, credential spraying, "
        "AD CS exploitation, ACL abuse, delegation abuse. Verify every "
        "credential via netexec auth checks. Report all credentials, hashes, "
        "and weaknesses using the reporting tool.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Enumeration report:\n{_truncate(enumeration_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _harvest_prompt(
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enumeration_report: str,
    exploit_report: str,
    max_steps: int,
) -> str:
    return (
        f"{_worker_stage_guard()}\n\n"
        "Harvest credentials from compromised hosts.\n"
        "Run secretsdump on hosts with confirmed admin access, crack "
        "recovered hashes, and verify all credentials via netexec auth "
        "checks. Report all credentials and hashes using the reporting "
        "tool.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, 8_000)}\n\n"
        f"Enumeration report:\n{_truncate(enumeration_report, 8_000)}\n\n"
        f"Exploitation report:\n{_truncate(exploit_report, REPORT_TRUNCATE_CHARS)}\n"
    )


def _synthesis_prompt(
    *,
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enumeration_report: str,
    exploit_report: str,
    harvest_report: str,
    findings: list[dict[str, t.Any]],
    max_steps: int,
) -> str:
    findings_json = json.dumps(findings, indent=2, sort_keys=True, default=str)
    return (
        f"{_worker_stage_guard()}\n\n"
        "Synthesize the final engagement report from all pipeline stages.\n"
        "Do not perform any scanning, enumeration, or exploitation. Only "
        "consolidate the evidence already gathered.\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Engagement payload:\n```json\n{scope_context}\n```\n\n"
        f"Scope normalization:\n{_truncate(scope_report, 8_000)}\n\n"
        f"Discovery report:\n{_truncate(discovery_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Enumeration report:\n{_truncate(enumeration_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Exploitation report:\n{_truncate(exploit_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Credential harvesting report:\n{_truncate(harvest_report, REPORT_TRUNCATE_CHARS)}\n\n"
        f"Recorded findings:\n```json\n{findings_json}\n```\n"
    )


# ---------------------------------------------------------------------------
# Report synthesis (deterministic fallback)
# ---------------------------------------------------------------------------


def _fallback_synthesis_report(
    *,
    scope_context: str,
    scope_report: str,
    discovery_report: str,
    enumeration_report: str,
    exploit_report: str,
    harvest_report: str,
    findings: list[dict[str, t.Any]],
) -> str:
    sections = [
        "# Network Operations Engagement Report",
        "",
        "Deterministic synthesis of pipeline stage evidence.",
        "",
        "## Scope",
        _truncate(scope_context, 2_000),
        "",
        "## Scope Normalization",
        _truncate(scope_report or "No scope normalizer output.", 3_000),
        "",
        "## Network Discovery",
        _truncate(discovery_report or "No discovery output.", 8_000),
        "",
        "## AD Enumeration",
        _truncate(enumeration_report or "No enumeration output.", 8_000),
        "",
        "## Exploitation",
        _truncate(exploit_report or "No exploitation output.", 8_000),
        "",
        "## Credential Harvesting",
        _truncate(harvest_report or "No harvesting output.", 8_000),
        "",
        "## Recorded Findings",
        json.dumps(findings, indent=2, sort_keys=True, default=str)
        if findings
        else "No findings were recorded via report_item tool calls.",
        "",
        "## Recommended Next Steps",
        "Continue with manual validation of unresolved attack paths and "
        "credential verification against remaining hosts.",
    ]
    return "\n".join(sections).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Event publishing helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _render_scope_context(scope: dict[str, t.Any]) -> str:
    return json.dumps(scope, indent=2, sort_keys=True, default=str)


def _compact_tool_call_summary(tool_calls: list[dict[str, t.Any]]) -> str:
    """Build a readable text summary when an agent produces tools but no prose."""
    sections = ["Tool evidence summary:"]
    for index, call in enumerate(tool_calls[:MAX_TOOL_CALLS_IN_SUMMARY], start=1):
        if not isinstance(call, dict):
            continue
        name = str(
            call.get("name") or call.get("tool_name") or f"tool_call_{index}"
        )
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
    if len(tool_calls) > MAX_TOOL_CALLS_IN_SUMMARY:
        sections.append(
            f"\n... {len(tool_calls) - MAX_TOOL_CALLS_IN_SUMMARY} additional tool calls omitted ..."
        )
    return "\n".join(sections)


def _worker_stage_guard() -> str:
    return (
        "You are running inside the worker-coordinated network operations "
        "pipeline. Do not call run_netops_pipeline from this stage. "
        "Use only the tools appropriate for your stage as described in "
        "your agent instructions."
    )


def _stage_budget(max_steps: int, cap: int) -> int:
    return max(1, min(int(max_steps), cap))


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... truncated ..."


def _label_safe(raw: str) -> str:
    """Sanitize a string for use as a session label value."""
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(raw).strip())
    return cleaned[:120] or "unknown"


if __name__ == "__main__":
    worker.run()
