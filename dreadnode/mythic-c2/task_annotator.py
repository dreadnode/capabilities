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
OUTPUT_CHAR_BUDGET = 20_000
COMMENT_CAP = 3_000

MARKER_PREFIX = "[dreadnode"
SOURCE_TAG = "dreadnode"
ANALYZER_AGENT = "task-analyzer"
_SESSION_NS = uuid5(NAMESPACE_URL, "mythic-c2/task-output-finder")

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


async def _ensure_session(client: RuntimeClient, session_id: str) -> None:
    try:
        await client.create_session(
            capability="mythic-c2", agent=ANALYZER_AGENT, session_id=session_id
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
    await _ensure_session(client, session_id)

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


if __name__ == "__main__":
    worker.run()
