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
import os
import sys
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


async def _run_analyzer(
    client: RuntimeClient, *, session_key: str, user_message: str
) -> dict[str, t.Any] | None:
    """Shared path: run the task-analyzer agent and return a validated finding.

    Returns ``None`` on turn failure, empty response, malformed JSON, or any
    validation rejection. Finders pass their own ``session_key`` so the log
    trail reflects which finder called it (task-output vs keylog vs file).
    """
    session_id = str(uuid5(_SESSION_NS, session_key))
    await _ensure_session(client, session_id, ANALYZER_AGENT)
    try:
        result = await client.run_turn(
            session_id=session_id, message=user_message, reset=True
        )
    except (TurnCancelledError, TurnFailedError) as exc:
        logger.warning("analyzer: turn failed for {}: {}", session_key, exc)
        return None
    response_text = (result.get("response_text") or "").strip()
    if not response_text:
        return None
    return _parse_finding(response_text)


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

    finding = await _run_analyzer(
        client,
        session_key=f"task:{task['id']}",
        user_message=user_message,
    )
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


# ── Keylog finder ───────────────────────────────────────────────────


async def fetch_recent_keylogs(limit: int = 500) -> list[dict[str, t.Any]]:
    data = await gql(
        "query RecentKeylogs($limit: Int!) {"
        "  keylog(order_by: {id: desc}, limit: $limit) {"
        "    id keystrokes_text window user timestamp"
        "    task { id display_id command_name comment"
        "           callback { display_id host } }"
        "  }"
        "}",
        {"limit": limit},
    )
    return data.get("keylog") or []


def _build_keylog_message(task: dict[str, t.Any], rows: list[dict[str, t.Any]]) -> str:
    cb = task.get("callback") or {}
    lines = [
        f"Task display_id: {task.get('display_id')}",
        f"Command: {task.get('command_name')}",
        f"Callback: display_id={cb.get('display_id')} host={cb.get('host')}",
        "",
        "This input is keylog data captured by the task. Each entry lists the",
        "window title and user at the time of capture, then the keystrokes.",
        "Look for credentials typed into login dialogs, command-line prompts,",
        "or pasted into text fields — not routine navigation keystrokes.",
        "Cite by window/user + the quoted substring.",
        "",
        "Keylog entries (oldest first):",
    ]
    rows_sorted = sorted(rows, key=lambda r: int(r.get("id") or 0))
    for r in rows_sorted:
        window = r.get("window") or "?"
        user = r.get("user") or "?"
        keys = r.get("keystrokes_text") or ""
        keys_one_line = keys.replace("\n", "\\n").replace("\r", "\\r")
        lines.append(
            f"  id={r.get('id')} user={user} window={window!r}: {keys_one_line}"
        )
    return "\n".join(lines)


async def analyze_keylog_batch(
    client: RuntimeClient, task: dict[str, t.Any], rows: list[dict[str, t.Any]]
) -> bool:
    display_id = int(task.get("display_id") or 0)
    if display_id == 0:
        return False
    if MARKER_PREFIX in (task.get("comment") or ""):
        return False
    if not rows:
        return False

    user_message = _build_keylog_message(task, rows)
    finding = await _run_analyzer(
        client,
        session_key=f"keylog:task:{task['id']}",
        user_message=user_message,
    )
    if finding is None:
        return False

    await write_finding(display_id=display_id, **finding)
    logger.info(
        "keylog finder: wrote {}/{} finding on task {} ({} keylog row(s))",
        finding["category"],
        finding["severity"],
        display_id,
        len(rows),
    )
    return True


# ── File finder ─────────────────────────────────────────────────────


FILE_SIZE_CAP_BYTES = 256 * 1024
FILE_PRINTABLE_RATIO = 0.85


async def fetch_recent_downloads(limit: int = 100) -> list[dict[str, t.Any]]:
    data = await gql(
        "query RecentDownloads($limit: Int!) {"
        "  filemeta(where: {"
        "    is_download_from_agent: {_eq: true},"
        "    complete: {_eq: true},"
        "    is_payload: {_eq: false}"
        "  }, order_by: {id: desc}, limit: $limit) {"
        "    id agent_file_id filename_utf8 full_remote_path_utf8 host"
        "    md5 sha1 timestamp"
        "    task { id display_id command_name comment"
        "           callback { display_id host } }"
        "  }"
        "}",
        {"limit": limit},
    )
    return data.get("filemeta") or []


def _is_textual(body: bytes) -> bool:
    if not body:
        return False
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t\r ")
    return (printable / max(len(text), 1)) >= FILE_PRINTABLE_RATIO


def _decode_filename(raw: str | None) -> str:
    """filename_utf8 and full_remote_path_utf8 arrive as JSON-encoded strings."""
    if not raw:
        return ""
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return str(raw)
    return (
        str(decoded) if not isinstance(decoded, list) else "/".join(map(str, decoded))
    )


def _build_file_message(
    task: dict[str, t.Any], file: dict[str, t.Any], body: str
) -> str:
    cb = task.get("callback") or {}
    filename = _decode_filename(file.get("filename_utf8"))
    remote_path = _decode_filename(file.get("full_remote_path_utf8"))
    lines = [
        f"Task display_id: {task.get('display_id')}",
        f"Command: {task.get('command_name')}",
        f"Callback: display_id={cb.get('display_id')} host={cb.get('host')}",
        f"Downloaded file: {filename or '<unnamed>'}",
        f"Remote path: {remote_path or '<unknown>'}",
        f"Host: {file.get('host')}",
        f"Size: {len(body)} bytes (may be truncated for analysis)",
        f"md5: {file.get('md5')}",
        "",
        "This input is the textual contents of a file downloaded from a",
        "compromised host. Look for secrets the file contains — credentials,",
        "tokens, keys, or sensitive configuration. Cite by line number.",
        "",
        "File contents (line-numbered):",
    ]
    lines.append(
        "\n".join(f"{i + 1:>5}: {line}" for i, line in enumerate(body.split("\n")))
    )
    return "\n".join(lines)


async def analyze_file(
    client: RuntimeClient, mythic: Mythic, file: dict[str, t.Any]
) -> bool:
    task = file.get("task") or {}
    display_id = int(task.get("display_id") or 0)
    if display_id == 0:
        return False
    if MARKER_PREFIX in (task.get("comment") or ""):
        return False

    agent_file_id = file.get("agent_file_id")
    if not agent_file_id:
        return False

    try:
        data = await mythic_sdk.download_file(mythic=mythic, file_uuid=agent_file_id)
    except Exception:
        logger.opt(exception=True).debug(
            "file finder: download failed for agent_file_id={}", agent_file_id
        )
        return False
    if not data:
        return False

    body_bytes = data[:FILE_SIZE_CAP_BYTES]
    if not _is_textual(body_bytes):
        logger.debug(
            "file finder: skipping non-textual or too-sparse file id={} size={}",
            file.get("id"),
            len(data),
        )
        return False

    body = body_bytes.decode("utf-8", errors="replace")
    if len(data) > FILE_SIZE_CAP_BYTES:
        body += f"\n[file truncated from {len(data)} bytes for analyzer]"

    user_message = _build_file_message(task, file, body)
    finding = await _run_analyzer(
        client,
        session_key=f"file:{file.get('id')}",
        user_message=user_message,
    )
    if finding is None:
        return False

    await write_finding(display_id=display_id, **finding)
    logger.info(
        "file finder: wrote {}/{} finding on task {} ({} bytes of {})",
        finding["category"],
        finding["severity"],
        display_id,
        len(body_bytes),
        _decode_filename(file.get("filename_utf8")) or agent_file_id,
    )
    return True


# ── Worker lifecycle ────────────────────────────────────────────────


worker = Worker(name="reactor")

_bootstrap_lock = asyncio.Lock()


async def _ensure_bootstrapped() -> Mythic | None:
    """Lazily connect to Mythic and seed known-ID sets on the first success.

    Called by every poll tick instead of ``on_startup`` so a transient Mythic
    outage (container restart, credential rotation, network blip) doesn't
    terminally wedge the reactor. Returns ``None`` when Mythic is unreachable
    — the caller is expected to log and return so the next tick tries again.

    Idempotent via ``_bootstrap_lock``: once one tick seeds state, every
    subsequent call returns the cached Mythic client.
    """
    mythic = worker.state.get("mythic")
    if mythic is not None:
        return mythic

    async with _bootstrap_lock:
        mythic = worker.state.get("mythic")
        if mythic is not None:
            return mythic

        try:
            mythic = await ensure_connected()
        except Exception as exc:
            logger.warning(
                "reactor: Mythic unreachable ({}) — retrying on next tick", exc
            )
            return None

        seed_tasks: set[int] = set()
        try:
            completed = await fetch_completed(mythic)
            seed_tasks = {int(t_["id"]) for t_ in completed if t_.get("id") is not None}
        except Exception:
            logger.opt(exception=True).warning(
                "reactor seed (tasks) failed — poll will self-heal"
            )

        seed_keylogs: set[int] = set()
        try:
            rows = await fetch_recent_keylogs()
            seed_keylogs = {int(r["id"]) for r in rows if r.get("id") is not None}
        except Exception:
            logger.opt(exception=True).warning(
                "reactor seed (keylogs) failed — poll will self-heal"
            )

        seed_files: set[int] = set()
        try:
            rows = await fetch_recent_downloads()
            seed_files = {int(r["id"]) for r in rows if r.get("id") is not None}
        except Exception:
            logger.opt(exception=True).warning(
                "reactor seed (downloads) failed — poll will self-heal"
            )

        current_op = "unknown"
        try:
            me = await mythic_sdk.get_me(mythic=mythic)
            current_op = (
                (me or {}).get("meHook", {}).get("current_operation", "unknown")
            )
        except Exception:
            logger.opt(exception=True).debug("reactor: get_me failed at bootstrap")

        worker.state["known_task_ids"] = seed_tasks
        worker.state["known_keylog_ids"] = seed_keylogs
        worker.state["known_file_ids"] = seed_files
        worker.state["mythic"] = mythic

        logger.info(
            "mythic-c2 reactor connected | operation={} | "
            "seeded {} tasks / {} keylogs / {} files",
            current_op,
            len(seed_tasks),
            len(seed_keylogs),
            len(seed_files),
        )
        return mythic


@worker.on_startup
async def startup(client: RuntimeClient) -> None:
    """Non-fatal startup. Mythic connect is deferred to the first poll tick so
    a transient outage doesn't exit the reactor terminally."""
    worker.state["mythic"] = None
    worker.state["known_task_ids"] = set()
    worker.state["known_keylog_ids"] = set()
    worker.state["known_file_ids"] = set()
    logger.info("mythic-c2 reactor starting — Mythic connect will happen on first tick")


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
    mythic = await _ensure_bootstrapped()
    if mythic is None:
        return
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


@worker.every(seconds=TICK_SECONDS)
async def poll_keylogs(client: RuntimeClient) -> None:
    if await _ensure_bootstrapped() is None:
        return
    try:
        rows = await fetch_recent_keylogs()
    except Exception:
        logger.opt(exception=True).warning("keylog finder: poll failed")
        return

    known: set[int] = worker.state["known_keylog_ids"]
    fresh = [r for r in rows if int(r.get("id") or 0) and int(r["id"]) not in known]
    if not fresh:
        return

    # Group by owning task so we analyze a task's keystrokes as one batch.
    by_task: dict[int, tuple[dict[str, t.Any], list[dict[str, t.Any]]]] = {}
    for row in fresh:
        task = row.get("task") or {}
        task_id = int(task.get("id") or 0)
        if not task_id:
            continue
        bucket = by_task.setdefault(task_id, (task, []))
        bucket[1].append(row)

    logger.info(
        "keylog finder: {} fresh row(s) across {} task(s)",
        sum(len(v[1]) for v in by_task.values()),
        len(by_task),
    )
    for _, (task, rows_for_task) in by_task.items():
        try:
            await analyze_keylog_batch(client, task, rows_for_task)
        except Exception:
            logger.opt(exception=True).warning(
                "keylog finder: analyze failed for task display_id={}",
                task.get("display_id"),
            )
            continue
        known.update(int(r["id"]) for r in rows_for_task if r.get("id") is not None)


@worker.every(seconds=TICK_SECONDS)
async def poll_downloads(client: RuntimeClient) -> None:
    mythic = await _ensure_bootstrapped()
    if mythic is None:
        return
    try:
        rows = await fetch_recent_downloads()
    except Exception:
        logger.opt(exception=True).warning("file finder: poll failed")
        return

    known: set[int] = worker.state["known_file_ids"]
    fresh = [r for r in rows if int(r.get("id") or 0) and int(r["id"]) not in known]
    if not fresh:
        return

    logger.info("file finder: {} fresh download(s) this tick", len(fresh))
    for file in fresh:
        fid = int(file["id"])
        try:
            await analyze_file(client, mythic, file)
        except Exception:
            logger.opt(exception=True).warning(
                "file finder: analyze failed for file id={}", fid
            )
            continue
        known.add(fid)


@worker.every(seconds=CORRELATOR_TICK_SECONDS)
async def correlate(client: RuntimeClient) -> None:
    if await _ensure_bootstrapped() is None:
        return
    try:
        written = await run_correlator(client)
    except Exception:
        logger.opt(exception=True).warning("correlator: tick failed")
        return
    if written:
        logger.info("correlator: wrote {} new trail(s) this tick", written)


TRIAGE_ENV = "CAPABILITY_FLAG__MYTHIC_C2__TRIAGE"


if __name__ == "__main__":
    if os.environ.get(TRIAGE_ENV, "0") != "1":
        logger.info(
            "mythic-c2: triage flag off — annotator worker exiting cleanly. "
            "Flip the capability's 'triage' flag on to enable AI analysis "
            "of completed tasks, keylogs, downloads, and cross-object trails."
        )
        sys.exit(0)
    worker.run()
