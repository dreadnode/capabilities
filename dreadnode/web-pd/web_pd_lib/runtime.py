import json
import typing as t
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

import dreadnode as dn
from dreadnode.tracing.constants import SPAN_ATTRIBUTE_RUN_ID, SPAN_ATTRIBUTE_SESSION_ID
from dreadnode.tracing.span import current_session_id, get_current_task_span

from .constants import (
    ATTR_ARTIFACT_PATH,
    ATTR_DEDUPE_KEY,
    ATTR_EVENT_KIND,
    ATTR_JOB_ID,
    ATTR_OPPORTUNITY_KEY,
    ATTR_OPPORTUNITY_KIND,
    ATTR_OWNER,
    ATTR_PAYLOAD,
    ATTR_PRIORITY,
    ATTR_SCAN_ID,
    ATTR_SEARCH_TEXT,
    ATTR_SOURCE,
    ATTR_STATUS,
    ATTR_SUMMARY,
    ATTR_TARGET,
    ATTR_TOOL,
)
from .models import PdEvent, RuntimePaths


def new_scan_id() -> str:
    """Create a short scan identifier."""
    return f"scan-{uuid4().hex[:12]}"


def get_current_actor() -> str:
    """Return a stable actor label for journal ownership fields."""
    task = get_current_task_span()
    if task is None:
        return "agent"
    return task.name or task.task_id


def resolve_runtime_paths(
    *,
    run_id: str | None = None,
    working_dir: Path | None = None,
    fallback_key: str | None = None,
) -> RuntimePaths:
    """Resolve the run-scoped trace directory and PD projection paths."""
    task = get_current_task_span()
    resolved_run_id = run_id or (task.root_id if task is not None else None) or fallback_key or uuid4().hex
    session_id = current_session_id.get()

    instance = dn.get_default_instance()
    try:
        storage = instance.storage
    except RuntimeError:
        storage = None
    if storage is not None:
        spans_path = storage.trace_path(resolved_run_id, "spans.jsonl")
        trace_dir = spans_path.parent
    else:
        base_dir = (working_dir or Path.cwd()) / ".dreadnode" / "projects" / "local" / resolved_run_id
        base_dir.mkdir(parents=True, exist_ok=True)
        trace_dir = base_dir
        spans_path = trace_dir / "spans.jsonl"
        spans_path.parent.mkdir(parents=True, exist_ok=True)

    journal_path = trace_dir / "pd.sqlite3"
    artifact_dir = trace_dir / "pd-artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    return RuntimePaths(
        run_id=resolved_run_id,
        trace_dir=trace_dir,
        spans_path=spans_path,
        journal_path=journal_path,
        artifact_dir=artifact_dir,
        session_id=session_id,
    )


def emit_pd_event(event: PdEvent, *, paths: RuntimePaths, tags: t.Sequence[str] | None = None) -> dict[str, str]:
    """Emit a ProjectDiscovery event as a span routed into the run journal."""
    attributes: dict[str, t.Any] = {
        SPAN_ATTRIBUTE_RUN_ID: paths.run_id,
        ATTR_SCAN_ID: event.scan_id,
        ATTR_EVENT_KIND: event.event_kind,
        ATTR_TARGET: event.target or "",
        ATTR_TOOL: event.tool or "",
        ATTR_JOB_ID: event.job_id or "",
        ATTR_DEDUPE_KEY: event.dedupe_key or "",
        ATTR_OPPORTUNITY_KEY: event.opportunity_key or "",
        ATTR_OPPORTUNITY_KIND: event.opportunity_kind or "",
        ATTR_PRIORITY: event.priority or "",
        ATTR_STATUS: event.status or "",
        ATTR_OWNER: event.owner or "",
        ATTR_SOURCE: event.source or "",
        ATTR_SEARCH_TEXT: event.search_text,
        ATTR_SUMMARY: event.summary or "",
        ATTR_ARTIFACT_PATH: event.artifact_path or "",
        ATTR_PAYLOAD: event.payload,
    }
    if paths.session_id:
        attributes[SPAN_ATTRIBUTE_SESSION_ID] = paths.session_id

    with dn.span(event.name, tags=list(tags or ["projectdiscovery", event.event_kind]), attributes=attributes) as span:
        span_dict = {
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "event": json.dumps(asdict(event), sort_keys=True),
        }
    return span_dict
