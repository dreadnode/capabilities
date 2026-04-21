#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "dreadnode>=2.0,<3.0",
#   "mythic>=0.2",
#   "loguru>=0.7",
# ]
# ///
"""mythic-c2 reactor — subprocess worker that watches completed tasks
and writes AI findings onto Mythic's own surfaces.

Each tick:
    1. pull the operation's completed tasks
    2. for each new one, run the task-analyzer agent against its decoded output
    3. if the analyzer returns a finding, write it: ensure tagtypes → apply
       severity + category tags → event log (optional) → task.comment last

The ``[dreadnode ...]`` marker in task.comment is the dedup signal. Writing
it last means a partial failure raises before the marker lands, and the next
tick safely retries.

Auth (pick one):
    MYTHIC_API_TOKEN
    MYTHIC_USERNAME + MYTHIC_PASSWORD
"""

from __future__ import annotations

import asyncio
import base64
import json
import typing as t
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from dreadnode.capabilities.worker import (
    RuntimeClient,
    TurnCancelledError,
    TurnFailedError,
    Worker,
)
from lib.mythic_api import ensure_connected, gql
from loguru import logger
from mythic import mythic as mythic_sdk
from mythic.mythic_classes import Mythic

# ── Constants ───────────────────────────────────────────────────────

TICK_SECONDS = 60
CORRELATOR_TICK_SECONDS = 300
OUTPUT_CHAR_BUDGET = 20_000
COMMENT_CAP = 3_000

MARKER_PREFIX = "[dreadnode"
SOURCE_TAG = "dreadnode"
TRAIL_PREFIX = "ai:trail:"
TRAIL_COLOR = "#283593"

ANALYZER_AGENT = "task-analyzer"
CORRELATOR_AGENT = "correlator"
_SESSION_NS = uuid5(NAMESPACE_URL, "mythic-c2/task-output-finder")
_CORRELATOR_NS = uuid5(NAMESPACE_URL, "mythic-c2/correlator")

CORRELATOR_FINDINGS_LIMIT = 50
CORRELATOR_CALLBACKS_LIMIT = 100
CORRELATOR_CREDENTIALS_LIMIT = 100
CORRELATOR_BODY_PREVIEW = 300

COMPLETED_TASK_ATTRS = (
    "id,display_id,command_name,status,completed,timestamp,comment,"
    "original_params,display_params,callback{display_id,host}"
)

SEVERITY_COLORS = {
    "critical": "#b71c1c",
    "high": "#d32f2f",
    "medium": "#f57c00",
    "low": "#0288d1",
    "info": "#455a64",
}

CATEGORY_COLORS = {
    "credential": "#ed6c02",
    "opsec": "#c2185b",
    "privilege": "#6a1b9a",
    "lateral": "#1565c0",
    "anomaly": "#00695c",
    "summary": "#5d4037",
}

CATEGORY_DESCRIPTIONS = {
    "credential": "AI finding: credential exposure",
    "opsec": "AI finding: operational-security concern",
    "privilege": "AI finding: privilege / integrity change",
    "lateral": "AI finding: lateral-movement opportunity",
    "anomaly": "AI finding: anomalous behavior",
    "summary": "AI finding: situational summary",
}


# ── Mythic reads (tasks + output) ───────────────────────────────────


async def fetch_completed(mythic: Mythic) -> list[dict[str, t.Any]]:
    rows = await mythic_sdk.get_all_tasks(
        mythic, custom_return_attributes=COMPLETED_TASK_ATTRS
    )
    return [r for r in rows if r.get("completed")]


async def fetch_decoded_output(mythic: Mythic, display_id: int) -> str:
    responses = await mythic_sdk.get_all_task_and_subtask_output_by_id(
        mythic=mythic, task_display_id=display_id
    )
    parts: list[str] = []
    for row in responses or []:
        raw = row.get("response_text") or row.get("response") or ""
        if not raw:
            continue
        try:
            parts.append(base64.b64decode(raw).decode("utf-8", errors="replace"))
        except Exception:
            parts.append(str(raw))
    joined = "\n".join(parts)
    if len(joined) > OUTPUT_CHAR_BUDGET:
        joined = joined[:OUTPUT_CHAR_BUDGET] + "\n[output truncated for analyzer]"
    return joined


# ── Writer (tags + event log + comment) ─────────────────────────────


async def _task_by_display_id(display_id: int) -> dict[str, t.Any] | None:
    data = await gql(
        "query GetTask($display_id: Int!) {"
        "  task(where: {display_id: {_eq: $display_id}}, limit: 1) {"
        "    id display_id comment"
        "  }"
        "}",
        {"display_id": display_id},
    )
    rows = data.get("task") or []
    return rows[0] if rows else None


async def _ensure_tagtype(name: str, color: str, description: str) -> int:
    data = await gql(
        "query FindTagType($name: String!) { tagtype(where: {name: {_eq: $name}}) { id } }",
        {"name": name},
    )
    if data["tagtype"]:
        return int(data["tagtype"][0]["id"])
    data = await gql(
        "mutation CreateTagType($name: String!, $color: String!, $description: String!) {"
        "  insert_tagtype_one(object: {name: $name, color: $color, description: $description}) { id }"
        "}",
        {"name": name, "color": color, "description": description},
    )
    return int(data["insert_tagtype_one"]["id"])


async def _apply_task_tag(tagtype_id: int, *, task_id: int, note: str) -> None:
    await gql(
        "mutation ApplyTaskTag($tagtype_id: Int!, $task_id: Int!, $data: jsonb!, $source: String!) {"
        "  insert_tag_one(object: {"
        '    tagtype_id: $tagtype_id, task_id: $task_id, data: $data, source: $source, url: ""'
        "  }) { id }"
        "}",
        {
            "tagtype_id": tagtype_id,
            "task_id": task_id,
            "data": {"note": note} if note else {},
            "source": SOURCE_TAG,
        },
    )


async def _apply_callback_tag(tagtype_id: int, *, callback_id: int, note: str) -> None:
    await gql(
        "mutation ApplyCallbackTag($tagtype_id: Int!, $callback_id: Int!, $data: jsonb!, $source: String!) {"
        "  insert_tag_one(object: {"
        '    tagtype_id: $tagtype_id, callback_id: $callback_id, data: $data, source: $source, url: ""'
        "  }) { id }"
        "}",
        {
            "tagtype_id": tagtype_id,
            "callback_id": callback_id,
            "data": {"note": note} if note else {},
            "source": SOURCE_TAG,
        },
    )


async def _apply_credential_tag(
    tagtype_id: int, *, credential_id: int, note: str
) -> None:
    await gql(
        "mutation ApplyCredentialTag($tagtype_id: Int!, $credential_id: Int!, $data: jsonb!, $source: String!) {"
        "  insert_tag_one(object: {"
        '    tagtype_id: $tagtype_id, credential_id: $credential_id, data: $data, source: $source, url: ""'
        "  }) { id }"
        "}",
        {
            "tagtype_id": tagtype_id,
            "credential_id": credential_id,
            "data": {"note": note} if note else {},
            "source": SOURCE_TAG,
        },
    )


async def _callback_by_display_id(display_id: int) -> dict[str, t.Any] | None:
    data = await gql(
        "query GetCallback($display_id: Int!) {"
        "  callback(where: {display_id: {_eq: $display_id}}, limit: 1) { id display_id }"
        "}",
        {"display_id": display_id},
    )
    rows = data.get("callback") or []
    return rows[0] if rows else None


async def _create_event_log(message: str, level: str) -> None:
    await gql(
        "mutation CreateEventLog($message: String!, $level: String!) {"
        "  insert_operationeventlog_one(object: {message: $message, level: $level}) { id }"
        "}",
        {"message": message, "level": level},
    )


async def _update_task_comment(task_id: int, comment: str) -> None:
    await gql(
        "mutation SetTaskComment($id: Int!, $comment: String!) {"
        "  update_task_by_pk(pk_columns: {id: $id}, _set: {comment: $comment}) { id }"
        "}",
        {"id": task_id, "comment": comment},
    )


def _format_comment(
    *, body: str, category: str, severity: str, citations: list[str], existing: str
) -> str:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    header = f"{MARKER_PREFIX} {stamp} | {category} | {severity}]"
    cites = "\nCites: " + "; ".join(citations[:4]) if citations else ""
    ai_section = f"{header}\n{body}{cites}"
    if len(ai_section) > COMMENT_CAP:
        ai_section = ai_section[: COMMENT_CAP - 1] + "…"
    if existing and MARKER_PREFIX not in existing:
        return f"{ai_section}\n---\n{existing}"
    return ai_section


async def write_finding(
    *,
    display_id: int,
    body: str,
    category: str,
    severity: str,
    citations: list[str],
    summary: str | None,
) -> None:
    task = await _task_by_display_id(display_id)
    if task is None:
        raise RuntimeError(f"task display_id={display_id} not visible")
    task_id = int(task["id"])
    prior = task.get("comment") or ""

    # Race guard: analyze_task checked the marker against the polled snapshot.
    # If a parallel worker landed its comment between then and now, bail before
    # any surface mutation so we don't double-tag or re-write.
    if MARKER_PREFIX in prior:
        logger.info(
            "writer: task {} already has [dreadnode] marker — skipping",
            display_id,
        )
        return

    sev_tt = await _ensure_tagtype(
        f"ai:severity:{severity}",
        SEVERITY_COLORS[severity],
        f"AI finding: {severity} severity",
    )
    cat_tt = await _ensure_tagtype(
        f"ai:category:{category}",
        CATEGORY_COLORS[category],
        CATEGORY_DESCRIPTIONS[category],
    )
    await _apply_task_tag(sev_tt, task_id=task_id, note=category)
    await _apply_task_tag(cat_tt, task_id=task_id, note=severity)

    if summary:
        level = "warning" if severity in ("critical", "high") else "info"
        await _create_event_log(f"[dreadnode] {summary}", level=level)

    await _update_task_comment(
        task_id,
        _format_comment(
            body=body,
            category=category,
            severity=severity,
            citations=citations,
            existing=prior,
        ),
    )


# ── Trail writer (cross-object correlator) ─────────────────────────


async def _existing_trails() -> set[str]:
    data = await gql(
        "query TrailTagTypes($prefix: String!) {"
        "  tagtype(where: {name: {_like: $prefix}}) { name }"
        "}",
        {"prefix": f"{TRAIL_PREFIX}%"},
    )
    return {row["name"] for row in (data.get("tagtype") or [])}


def _trail_uuid8(resolved: list[tuple[str, int]]) -> str:
    sig = json.dumps(sorted(resolved), separators=(",", ":"))
    return uuid5(NAMESPACE_URL, sig).hex[:8]


async def _resolve_related(
    related: list[dict[str, t.Any]],
) -> list[tuple[str, int]]:
    resolved: list[tuple[str, int]] = []
    for item in related:
        kind = item.get("kind")
        if kind == "task":
            display_id = int(item.get("display_id") or 0)
            if not display_id:
                continue
            task = await _task_by_display_id(display_id)
            if task is not None:
                resolved.append(("task", int(task["id"])))
        elif kind == "callback":
            display_id = int(item.get("display_id") or 0)
            if not display_id:
                continue
            cb = await _callback_by_display_id(display_id)
            if cb is not None:
                resolved.append(("callback", int(cb["id"])))
        elif kind == "credential":
            cred_id = int(item.get("id") or 0)
            if cred_id:
                resolved.append(("credential", cred_id))
    # De-duplicate (same kind/id listed twice) while preserving order
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for pair in resolved:
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out


async def write_trail(
    *,
    related: list[dict[str, t.Any]],
    severity: str,
    body: str,
    summary: str | None,
) -> str | None:
    """Link ≥2 related objects under one ``ai:trail:<uuid8>`` tag.

    Resolves display_ids to primary ids, keys the tagtype off the sorted
    related-set so the same link is idempotent across ticks, applies the
    tag to every object, and drops one event-log entry. Returns the
    trail uuid, or ``None`` if the trail was dedup-skipped or under-sized.
    """
    if severity not in SEVERITY_COLORS:
        logger.warning("correlator: invalid trail severity {!r}", severity)
        return None

    resolved = await _resolve_related(related)
    if len(resolved) < 2:
        logger.info(
            "correlator: trail collapsed to <2 objects after resolve — skipping"
        )
        return None

    trail_id = _trail_uuid8(resolved)
    name = f"{TRAIL_PREFIX}{trail_id}"
    description = (summary or body)[:240]
    tagtype_id = await _ensure_tagtype(name, TRAIL_COLOR, description)

    for kind, rid in resolved:
        try:
            if kind == "task":
                await _apply_task_tag(tagtype_id, task_id=rid, note="trail")
            elif kind == "callback":
                await _apply_callback_tag(tagtype_id, callback_id=rid, note="trail")
            elif kind == "credential":
                await _apply_credential_tag(tagtype_id, credential_id=rid, note="trail")
        except Exception:
            logger.opt(exception=True).warning(
                "correlator: tag apply failed for {}={} on trail {}",
                kind,
                rid,
                trail_id,
            )

    if summary:
        level = "warning" if severity in ("critical", "high") else "info"
        await _create_event_log(f"[dreadnode] trail {trail_id}: {summary}", level=level)

    logger.info(
        "correlator: wrote trail {} over {} objects ({})",
        trail_id,
        len(resolved),
        ", ".join(f"{k}={i}" for k, i in resolved),
    )
    return trail_id


# ── Correlator dispatch ─────────────────────────────────────────────


async def _fetch_findings_for_correlator() -> list[dict[str, t.Any]]:
    data = await gql(
        "query FindingsOnTasks($prefix: String!, $limit: Int!) {"
        "  task(where: {comment: {_like: $prefix}}, "
        "       order_by: {id: desc}, limit: $limit) {"
        "    id display_id command_name comment"
        "    callback { display_id host user }"
        "  }"
        "}",
        {"prefix": f"{MARKER_PREFIX}%", "limit": CORRELATOR_FINDINGS_LIMIT},
    )
    return data.get("task") or []


async def _fetch_active_callbacks_for_correlator() -> list[dict[str, t.Any]]:
    data = await gql(
        "query ActiveCallbacks($limit: Int!) {"
        "  callback(where: {active: {_eq: true}}, limit: $limit) {"
        "    id display_id host user integrity_level pid process_name domain"
        "  }"
        "}",
        {"limit": CORRELATOR_CALLBACKS_LIMIT},
    )
    return data.get("callback") or []


async def _fetch_credentials_for_correlator() -> list[dict[str, t.Any]]:
    data = await gql(
        "query AllCredentials($limit: Int!) {"
        "  credential(order_by: {id: desc}, limit: $limit) {"
        "    id type realm account credential_text comment"
        "    task { display_id callback { display_id host } }"
        "  }"
        "}",
        {"limit": CORRELATOR_CREDENTIALS_LIMIT},
    )
    return data.get("credential") or []


def _build_correlator_message(
    findings: list[dict[str, t.Any]],
    callbacks: list[dict[str, t.Any]],
    credentials: list[dict[str, t.Any]],
    existing_trail_names: set[str],
) -> str:
    parts: list[str] = [
        "Correlate findings, callbacks, and credentials for the current "
        "Mythic operation. Each entry below includes its identifier — use "
        "those exact values when you propose trails."
    ]

    if existing_trail_names:
        parts.append("")
        parts.append(
            f"Existing trails ({len(existing_trail_names)}) — already tagged; "
            "do NOT re-propose the same related-set (the writer will dedup "
            "these anyway, but you waste tokens):"
        )
        parts.extend(f"  - {name}" for name in sorted(existing_trail_names))

    parts.append("")
    parts.append(f"Findings ({len(findings)}) — prior AI comments on tasks:")
    for r in findings:
        body_preview = (r.get("comment") or "").replace("\n", " ")[
            :CORRELATOR_BODY_PREVIEW
        ]
        cb = r.get("callback") or {}
        parts.append(
            f"  task display_id={r.get('display_id')} "
            f"cmd={r.get('command_name')} "
            f"callback={cb.get('display_id')}@{cb.get('host')}/"
            f"{cb.get('user')} : {body_preview}"
        )

    parts.append("")
    parts.append(f"Active callbacks ({len(callbacks)}):")
    for cb in callbacks:
        parts.append(
            f"  callback display_id={cb.get('display_id')} "
            f"host={cb.get('host')} user={cb.get('user')} "
            f"domain={cb.get('domain')} integrity={cb.get('integrity_level')} "
            f"process={cb.get('process_name')} pid={cb.get('pid')}"
        )

    parts.append("")
    parts.append(f"Credentials ({len(credentials)}):")
    for c in credentials:
        task = c.get("task") or {}
        cb = task.get("callback") or {}
        text_preview = (c.get("credential_text") or "")[:80]
        parts.append(
            f"  credential id={c.get('id')} type={c.get('type')} "
            f"account={c.get('account')} realm={c.get('realm')} "
            f"text={text_preview!r} "
            f"from task={task.get('display_id')} "
            f"callback={cb.get('display_id')}@{cb.get('host')}"
        )

    return "\n".join(parts)


def _parse_trails(response_text: str) -> list[dict[str, t.Any]]:
    text = response_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("correlator: response not valid JSON: {!r}", response_text[:400])
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("trails"), list):
        return parsed["trails"]
    return []


async def run_correlator(client: RuntimeClient) -> int:
    findings = await _fetch_findings_for_correlator()
    callbacks = await _fetch_active_callbacks_for_correlator()
    credentials = await _fetch_credentials_for_correlator()

    non_empty = sum(1 for s in (findings, callbacks, credentials) if s)
    if non_empty < 2:
        logger.debug(
            "correlator: only {} source(s) non-empty — skipping tick", non_empty
        )
        return 0

    existing = await _existing_trails()
    user_message = _build_correlator_message(findings, callbacks, credentials, existing)

    session_id = str(_CORRELATOR_NS)
    await _ensure_session(client, session_id, CORRELATOR_AGENT)

    try:
        result = await client.run_turn(
            session_id=session_id, message=user_message, reset=True
        )
    except (TurnCancelledError, TurnFailedError) as exc:
        logger.warning("correlator: turn failed: {}", exc)
        return 0

    trails = _parse_trails((result.get("response_text") or "").strip())
    if not trails:
        return 0

    written = 0
    for trail in trails:
        related = trail.get("related") or []
        severity = trail.get("severity")
        body = (trail.get("body") or "").strip()
        summary_raw = trail.get("summary")
        summary = (
            summary_raw.strip()
            if isinstance(summary_raw, str) and summary_raw.strip()
            else None
        )
        if not body or severity not in SEVERITY_COLORS or not related:
            logger.warning(
                "correlator: dropping malformed trail proposal: "
                "severity={!r} body_len={} related_len={}",
                severity,
                len(body),
                len(related) if isinstance(related, list) else -1,
            )
            continue
        try:
            tid = await write_trail(
                related=related,
                severity=severity,
                body=body,
                summary=summary,
            )
        except Exception:
            logger.opt(exception=True).warning("correlator: write_trail raised")
            continue
        if tid:
            written += 1
    return written


# ── Analyzer dispatch ───────────────────────────────────────────────


def _build_user_message(task: dict[str, t.Any], decoded: str) -> str:
    lines = [
        f"Task display_id: {task.get('display_id')}",
        f"Command: {task.get('command_name')}",
    ]
    params = task.get("original_params") or task.get("display_params")
    if params:
        lines.append(f"Arguments: {params}")
    lines.append("")
    if decoded:
        lines.append("Decoded output (line-numbered):")
        lines.append(
            "\n".join(
                f"{i + 1:>5}: {line}" for i, line in enumerate(decoded.split("\n"))
            )
        )
    else:
        lines.append("(no decoded output returned from Mythic)")
    return "\n".join(lines)


def _parse_finding(response_text: str) -> dict[str, t.Any] | None:
    text = response_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("analyzer: response not valid JSON: {!r}", response_text[:400])
        return None
    if not isinstance(parsed, dict) or not parsed.get("finding"):
        return None

    severity = parsed.get("severity")
    category = parsed.get("category")
    body = (parsed.get("body") or "").strip()
    citations = [
        str(c).strip() for c in (parsed.get("citations") or []) if str(c).strip()
    ]
    if severity not in SEVERITY_COLORS:
        logger.warning("analyzer: invalid severity {!r}", severity)
        return None
    if category not in CATEGORY_COLORS:
        logger.warning("analyzer: invalid category {!r}", category)
        return None
    if not body:
        logger.warning("analyzer: empty body on finding")
        return None
    if not citations:
        logger.warning("analyzer: finding without citations — rejecting")
        return None

    summary = parsed.get("summary")
    summary = summary.strip() if isinstance(summary, str) and summary.strip() else None
    return {
        "body": body,
        "category": category,
        "severity": severity,
        "citations": citations,
        "summary": summary,
    }


async def _ensure_session(client: RuntimeClient, session_id: str, agent: str) -> None:
    try:
        await client.create_session(
            capability="mythic-c2", agent=agent, session_id=session_id
        )
    except Exception as exc:
        msg = str(exc).lower()
        if not any(s in msg for s in ("exist", "already", "duplicate")):
            raise


async def analyze_task(
    client: RuntimeClient, mythic: Mythic, task: dict[str, t.Any]
) -> bool:
    display_id = int(task.get("display_id") or 0)
    if display_id == 0:
        return False
    if MARKER_PREFIX in (task.get("comment") or ""):
        return False

    decoded = await fetch_decoded_output(mythic, display_id)
    user_message = _build_user_message(task, decoded)

    session_id = str(uuid5(_SESSION_NS, f"task:{task['id']}"))
    await _ensure_session(client, session_id, ANALYZER_AGENT)

    try:
        result = await client.run_turn(
            session_id=session_id, message=user_message, reset=True
        )
    except (TurnCancelledError, TurnFailedError) as exc:
        logger.warning("analyzer: turn failed for task {}: {}", display_id, exc)
        return False

    response_text = (result.get("response_text") or "").strip()
    if not response_text:
        return False

    finding = _parse_finding(response_text)
    if finding is None:
        return False

    await write_finding(display_id=display_id, **finding)
    logger.info(
        "analyzer: wrote {}/{} finding on task {}",
        finding["category"],
        finding["severity"],
        display_id,
    )
    return True


# ── Worker lifecycle ────────────────────────────────────────────────


worker = Worker(name="reactor")


@worker.on_startup
async def startup(client: RuntimeClient) -> None:
    mythic = await ensure_connected()
    worker.state["mythic"] = mythic

    me = await mythic_sdk.get_me(mythic=mythic)
    current_op = (me or {}).get("meHook", {}).get("current_operation", "unknown")

    seed: set[int] = set()
    try:
        completed = await fetch_completed(mythic)
        seed = {int(t_["id"]) for t_ in completed if t_.get("id") is not None}
    except Exception:
        logger.opt(exception=True).warning("reactor seed failed — poll will self-heal")
    worker.state["known_task_ids"] = seed

    logger.info(
        "mythic-c2 reactor ready | operation={} | seeded {} completed tasks",
        current_op,
        len(seed),
    )


@worker.on_shutdown
async def shutdown(client: RuntimeClient) -> None:
    mythic: Mythic | None = worker.state.get("mythic")
    if mythic is None:
        return
    session = getattr(mythic, "http_session", None)
    if session is None or session.closed:
        return
    try:
        await asyncio.wait_for(session.close(), timeout=3)
    except (TimeoutError, Exception):
        logger.opt(exception=True).debug("reactor shutdown: mythic client close failed")


@worker.every(seconds=TICK_SECONDS)
async def poll_and_analyze(client: RuntimeClient) -> None:
    mythic: Mythic = worker.state["mythic"]
    try:
        completed = await fetch_completed(mythic)
    except Exception:
        logger.opt(exception=True).warning("reactor: poll failed")
        return

    known: set[int] = worker.state["known_task_ids"]
    fresh = [
        t_ for t_ in completed if int(t_.get("id") or 0) and int(t_["id"]) not in known
    ]
    if not fresh:
        return

    logger.info("reactor: {} fresh completed task(s) this tick", len(fresh))
    for task in fresh:
        tid = int(task["id"])
        try:
            await analyze_task(client, mythic, task)
        except Exception:
            # Transient failure: leave out of `known` so the next tick retries.
            # The `[dreadnode]` marker in task.comment is the real dedup if a
            # write partially landed.
            logger.opt(exception=True).warning(
                "reactor: analyze_task failed for display_id={} — will retry next tick",
                task.get("display_id"),
            )
            continue
        known.add(tid)


@worker.every(seconds=CORRELATOR_TICK_SECONDS)
async def correlate(client: RuntimeClient) -> None:
    try:
        written = await run_correlator(client)
    except Exception:
        logger.opt(exception=True).warning("correlator: tick failed")
        return
    if written:
        logger.info("correlator: wrote {} new trail(s) this tick", written)


if __name__ == "__main__":
    worker.run()
