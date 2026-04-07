import typing as t
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class PdEvent:
    name: str
    scan_id: str
    event_kind: str
    target: str | None = None
    tool: str | None = None
    job_id: str | None = None
    dedupe_key: str | None = None
    opportunity_key: str | None = None
    opportunity_kind: str | None = None
    priority: str | None = None
    status: str | None = None
    owner: str | None = None
    source: str | None = None
    search_text: str = ""
    summary: str | None = None
    artifact_path: str | None = None
    payload: dict[str, t.Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolResult:
    tool: str
    command: list[str]
    success: bool
    items: list[dict[str, t.Any]] = field(default_factory=list)
    raw_output: list[str] = field(default_factory=list)
    error: str | None = None
    return_code: int = 0
    elapsed_seconds: float = 0.0


@dataclass(slots=True)
class RuntimePaths:
    run_id: str
    trace_dir: Path
    spans_path: Path
    journal_path: Path
    artifact_dir: Path
    session_id: str | None = None


@dataclass(slots=True)
class OpportunityRecord:
    opportunity_key: str
    scan_id: str
    kind: str
    target: str
    priority: str
    status: str
    owner: str | None
    summary: str | None
    score: float
    source_span_id: str | None
    last_span_id: str | None
    updated_at: str | None


@dataclass(slots=True)
class EventSearchResult:
    span_id: str
    scan_id: str
    name: str
    event_kind: str
    target: str | None
    snippet: str
    search_text: str
