import json
import sqlite3
import threading
import typing as t
from dataclasses import asdict
from pathlib import Path

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
    ATTR_STATUS,
    ATTR_SUMMARY,
    ATTR_TARGET,
    ATTR_TOOL,
)
from .models import EventSearchResult, OpportunityRecord


def _json_dumps(value: t.Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)


def _maybe_json_loads(value: t.Any) -> t.Any:
    if not isinstance(value, str):
        return value
    if not value:
        return value
    if value[0] not in "{[":
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


class PdJournal:
    """Materialized SQLite projection over the run-scoped spans.jsonl journal."""

    def __init__(self, spans_path: Path, db_path: Path) -> None:
        self.spans_path = spans_path
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fts5_enabled = True
        self._init_db()

    @property
    def fts5_enabled(self) -> bool:
        """Whether the backing SQLite build supports FTS5."""
        return self._fts5_enabled

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;

                CREATE TABLE IF NOT EXISTS ingest_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                INSERT OR IGNORE INTO ingest_state (key, value) VALUES ('last_line', '0');

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    trace_id TEXT,
                    span_id TEXT NOT NULL UNIQUE,
                    parent_id TEXT,
                    name TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    target TEXT,
                    tool TEXT,
                    job_id TEXT,
                    dedupe_key TEXT,
                    opportunity_key TEXT,
                    opportunity_kind TEXT,
                    priority TEXT,
                    status TEXT,
                    owner TEXT,
                    summary TEXT,
                    artifact_path TEXT,
                    ts_start TEXT,
                    ts_end TEXT,
                    search_text TEXT NOT NULL DEFAULT '',
                    attrs_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pd_events_scan_kind
                    ON events(scan_id, event_kind, ts_start);
                CREATE INDEX IF NOT EXISTS idx_pd_events_scan_target
                    ON events(scan_id, target);
                CREATE INDEX IF NOT EXISTS idx_pd_events_job
                    ON events(scan_id, job_id);

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target TEXT,
                    dedupe_key TEXT UNIQUE,
                    status TEXT NOT NULL,
                    artifact_path TEXT,
                    last_span_id TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS opportunities (
                    opportunity_key TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT,
                    summary TEXT,
                    score REAL NOT NULL DEFAULT 0,
                    source_span_id TEXT,
                    last_span_id TEXT,
                    updated_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_pd_opportunities_scan_status
                    ON opportunities(scan_id, status, priority);

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_path TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    job_id TEXT,
                    tool TEXT,
                    created_span_id TEXT
                );
                """
            )

            try:
                conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS event_search USING fts5(
                        span_id UNINDEXED,
                        scan_id UNINDEXED,
                        name,
                        event_kind,
                        target,
                        search_text,
                        tokenize = 'unicode61'
                    )
                    """
                )
            except sqlite3.OperationalError:
                self._fts5_enabled = False
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_search (
                        span_id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        event_kind TEXT NOT NULL,
                        target TEXT,
                        search_text TEXT NOT NULL
                    )
                    """
                )

    def refresh(self) -> dict[str, int]:
        """Ingest new PD spans from spans.jsonl into SQLite."""
        if not self.spans_path.exists():
            return {"ingested": 0}

        ingested = 0
        with self._lock, self._connect() as conn:
            last_line = int(
                conn.execute(
                    "SELECT value FROM ingest_state WHERE key = 'last_line'"
                ).fetchone()[0]
            )
            with self.spans_path.open("r", encoding="utf-8") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    if line_number <= last_line:
                        continue
                    if self._ingest_line(conn, raw_line):
                        ingested += 1
                    last_line = line_number

            conn.execute(
                "UPDATE ingest_state SET value = ? WHERE key = 'last_line'",
                (str(last_line),),
            )

        return {"ingested": ingested}

    def get_job_by_dedupe(self, scan_id: str, dedupe_key: str) -> dict[str, t.Any] | None:
        """Return the latest job record for a dedupe key."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT job_id, scan_id, tool, target, dedupe_key, status, artifact_path, updated_at
                FROM jobs
                WHERE scan_id = ? AND dedupe_key = ?
                """,
                (scan_id, dedupe_key),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_facts(
        self,
        *,
        scan_id: str,
        kinds: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, t.Any]]:
        """List fact events for a scan."""
        query = """
            SELECT name, event_kind, target, tool, job_id, summary, search_text, attrs_json
            FROM events
            WHERE scan_id = ? AND event_kind LIKE 'fact.%'
        """
        params: list[t.Any] = [scan_id]
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            query += f" AND event_kind IN ({placeholders})"
            params.extend(kinds)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        facts: list[dict[str, t.Any]] = []
        for row in rows:
            payload = _maybe_json_loads(json.loads(row["attrs_json"]).get(ATTR_PAYLOAD, "{}"))
            facts.append(
                {
                    "name": row["name"],
                    "event_kind": row["event_kind"],
                    "target": row["target"],
                    "tool": row["tool"],
                    "job_id": row["job_id"],
                    "summary": row["summary"],
                    "search_text": row["search_text"],
                    "payload": payload if isinstance(payload, dict) else {},
                }
            )
        return facts

    def list_opportunities(
        self,
        *,
        scan_id: str,
        status: str | None = None,
        limit: int = 20,
    ) -> list[OpportunityRecord]:
        """List ranked opportunities for a scan."""
        query = """
            SELECT opportunity_key, scan_id, kind, target, priority, status, owner, summary,
                   score, source_span_id, last_span_id, updated_at
            FROM opportunities
            WHERE scan_id = ?
        """
        params: list[t.Any] = [scan_id]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY score DESC, updated_at DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            OpportunityRecord(
                opportunity_key=row["opportunity_key"],
                scan_id=row["scan_id"],
                kind=row["kind"],
                target=row["target"],
                priority=row["priority"],
                status=row["status"],
                owner=row["owner"],
                summary=row["summary"],
                score=float(row["score"] or 0),
                source_span_id=row["source_span_id"],
                last_span_id=row["last_span_id"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    def search(
        self,
        *,
        scan_id: str,
        query: str,
        limit: int = 20,
    ) -> list[EventSearchResult]:
        """Run a full-text search over the projected event journal."""
        with self._lock, self._connect() as conn:
            if self._fts5_enabled:
                rows = conn.execute(
                    """
                    SELECT es.span_id, es.scan_id, es.name, es.event_kind, es.target,
                           snippet(event_search, 5, '[', ']', '…', 12) AS snippet,
                           es.search_text
                    FROM event_search AS es
                    WHERE es.scan_id = ? AND event_search MATCH ?
                    LIMIT ?
                    """,
                    (scan_id, query, limit),
                ).fetchall()
            else:
                like_query = f"%{query}%"
                rows = conn.execute(
                    """
                    SELECT span_id, scan_id, name, event_kind, target, search_text AS snippet, search_text
                    FROM event_search
                    WHERE scan_id = ? AND lower(search_text) LIKE lower(?)
                    LIMIT ?
                    """,
                    (scan_id, like_query, limit),
                ).fetchall()

        return [
            EventSearchResult(
                span_id=row["span_id"],
                scan_id=row["scan_id"],
                name=row["name"],
                event_kind=row["event_kind"],
                target=row["target"],
                snippet=row["snippet"],
                search_text=row["search_text"],
            )
            for row in rows
        ]

    def get_scan_summary(self, scan_id: str) -> dict[str, t.Any]:
        """Return counts and latest opportunity state for a scan."""
        with self._lock, self._connect() as conn:
            event_counts = conn.execute(
                """
                SELECT event_kind, COUNT(*) AS count
                FROM events
                WHERE scan_id = ?
                GROUP BY event_kind
                ORDER BY event_kind
                """,
                (scan_id,),
            ).fetchall()
            status_counts = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM opportunities
                WHERE scan_id = ?
                GROUP BY status
                """,
                (scan_id,),
            ).fetchall()

        return {
            "scan_id": scan_id,
            "events": {row["event_kind"]: row["count"] for row in event_counts},
            "opportunities": {row["status"]: row["count"] for row in status_counts if row["status"]},
            "fts5_enabled": self._fts5_enabled,
            "database": str(self.db_path),
            "spans": str(self.spans_path),
        }

    def _ingest_line(self, conn: sqlite3.Connection, raw_line: str) -> bool:
        raw_line = raw_line.strip()
        if not raw_line:
            return False

        span = json.loads(raw_line)
        attrs = span.get("attributes") or {}
        scan_id = attrs.get(ATTR_SCAN_ID)
        if not isinstance(scan_id, str) or not scan_id:
            return False

        name = str(span.get("name") or "")
        event_kind = str(attrs.get(ATTR_EVENT_KIND) or name)
        span_id = str(span.get("span_id") or "")
        if not span_id:
            return False

        payload = _maybe_json_loads(attrs.get(ATTR_PAYLOAD, "{}"))
        attrs_json = _json_dumps(attrs)
        search_text = str(attrs.get(ATTR_SEARCH_TEXT) or "")
        if not search_text and isinstance(payload, dict):
            search_text = _json_dumps(payload)

        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO events (
                scan_id, trace_id, span_id, parent_id, name, event_kind, target, tool, job_id,
                dedupe_key, opportunity_key, opportunity_kind, priority, status, owner, summary,
                artifact_path, ts_start, ts_end, search_text, attrs_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                span.get("trace_id"),
                span_id,
                span.get("parent_id"),
                name,
                event_kind,
                attrs.get(ATTR_TARGET) or None,
                attrs.get(ATTR_TOOL) or None,
                attrs.get(ATTR_JOB_ID) or None,
                attrs.get(ATTR_DEDUPE_KEY) or None,
                attrs.get(ATTR_OPPORTUNITY_KEY) or None,
                attrs.get(ATTR_OPPORTUNITY_KIND) or None,
                attrs.get(ATTR_PRIORITY) or None,
                attrs.get(ATTR_STATUS) or None,
                attrs.get(ATTR_OWNER) or None,
                attrs.get(ATTR_SUMMARY) or None,
                attrs.get(ATTR_ARTIFACT_PATH) or None,
                span.get("start_time"),
                span.get("end_time"),
                search_text,
                attrs_json,
            ),
        )
        if cursor.rowcount == 0:
            return False

        self._insert_search_row(
            conn=conn,
            span_id=span_id,
            scan_id=scan_id,
            name=name,
            event_kind=event_kind,
            target=attrs.get(ATTR_TARGET) or None,
            search_text=search_text,
        )
        self._upsert_job(conn=conn, span=span, attrs=attrs)
        self._upsert_opportunity(conn=conn, span=span, attrs=attrs)
        self._upsert_artifact(conn=conn, attrs=attrs, scan_id=scan_id, span_id=span_id)
        return True

    def _insert_search_row(
        self,
        *,
        conn: sqlite3.Connection,
        span_id: str,
        scan_id: str,
        name: str,
        event_kind: str,
        target: str | None,
        search_text: str,
    ) -> None:
        if self._fts5_enabled:
            conn.execute(
                """
                INSERT INTO event_search (span_id, scan_id, name, event_kind, target, search_text)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (span_id, scan_id, name, event_kind, target, search_text),
            )
        else:
            conn.execute(
                """
                INSERT OR REPLACE INTO event_search (span_id, scan_id, name, event_kind, target, search_text)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (span_id, scan_id, name, event_kind, target, search_text),
            )

    def _upsert_job(
        self,
        *,
        conn: sqlite3.Connection,
        span: dict[str, t.Any],
        attrs: dict[str, t.Any],
    ) -> None:
        job_id = attrs.get(ATTR_JOB_ID)
        tool = attrs.get(ATTR_TOOL)
        if not isinstance(job_id, str) or not job_id or not isinstance(tool, str) or not tool:
            return
        conn.execute(
            """
            INSERT INTO jobs (job_id, scan_id, tool, target, dedupe_key, status, artifact_path, last_span_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                status = excluded.status,
                artifact_path = COALESCE(excluded.artifact_path, jobs.artifact_path),
                last_span_id = excluded.last_span_id,
                updated_at = excluded.updated_at
            """,
            (
                job_id,
                attrs.get(ATTR_SCAN_ID),
                tool,
                attrs.get(ATTR_TARGET) or None,
                attrs.get(ATTR_DEDUPE_KEY) or None,
                attrs.get(ATTR_STATUS) or "unknown",
                attrs.get(ATTR_ARTIFACT_PATH) or None,
                span.get("span_id"),
                span.get("end_time") or span.get("start_time"),
            ),
        )

    def _upsert_opportunity(
        self,
        *,
        conn: sqlite3.Connection,
        span: dict[str, t.Any],
        attrs: dict[str, t.Any],
    ) -> None:
        opportunity_key = attrs.get(ATTR_OPPORTUNITY_KEY)
        opportunity_kind = attrs.get(ATTR_OPPORTUNITY_KIND)
        target = attrs.get(ATTR_TARGET)
        if not isinstance(opportunity_key, str) or not opportunity_key:
            return
        if not isinstance(opportunity_kind, str) or not opportunity_kind:
            return
        if not isinstance(target, str) or not target:
            return

        payload = _maybe_json_loads(attrs.get(ATTR_PAYLOAD, "{}"))
        score = 0.0
        if isinstance(payload, dict):
            score = float(payload.get("score") or 0.0)

        conn.execute(
            """
            INSERT INTO opportunities (
                opportunity_key, scan_id, kind, target, priority, status, owner, summary,
                score, source_span_id, last_span_id, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(opportunity_key) DO UPDATE SET
                priority = excluded.priority,
                status = excluded.status,
                owner = CASE
                    WHEN excluded.owner IS NULL OR excluded.owner = '' THEN opportunities.owner
                    ELSE excluded.owner
                END,
                summary = CASE
                    WHEN excluded.summary IS NULL OR excluded.summary = '' THEN opportunities.summary
                    ELSE excluded.summary
                END,
                score = CASE
                    WHEN excluded.score > opportunities.score THEN excluded.score
                    ELSE opportunities.score
                END,
                last_span_id = excluded.last_span_id,
                updated_at = excluded.updated_at
            """,
            (
                opportunity_key,
                attrs.get(ATTR_SCAN_ID),
                opportunity_kind,
                target,
                attrs.get(ATTR_PRIORITY) or "medium",
                attrs.get(ATTR_STATUS) or "open",
                attrs.get(ATTR_OWNER) or None,
                attrs.get(ATTR_SUMMARY) or None,
                score,
                span.get("span_id"),
                span.get("span_id"),
                span.get("end_time") or span.get("start_time"),
            ),
        )

    def _upsert_artifact(
        self,
        *,
        conn: sqlite3.Connection,
        attrs: dict[str, t.Any],
        scan_id: str,
        span_id: str,
    ) -> None:
        artifact_path = attrs.get(ATTR_ARTIFACT_PATH)
        if not isinstance(artifact_path, str) or not artifact_path:
            return
        conn.execute(
            """
            INSERT INTO artifacts (artifact_path, scan_id, job_id, tool, created_span_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(artifact_path) DO UPDATE SET
                created_span_id = excluded.created_span_id
            """,
            (
                artifact_path,
                scan_id,
                attrs.get(ATTR_JOB_ID) or None,
                attrs.get(ATTR_TOOL) or None,
                span_id,
            ),
        )
