"""Wiki-specific loop control over the built-in Agent Output read surface.

Browsing, reading, and full-text search are provided by the platform's built-in
`list_items`, `read_item`, and `search_items` tools, which every agent in a
platform-connected session receives. This module adds only the wiki-specific
coverage signal those generic tools cannot express: a maintenance-loop stop
condition derived from page kinds and open questions.
"""

import asyncio
import collections
import re
import typing as t

from dreadnode import get_default_instance
from dreadnode.agents.tools import tool

_ITEM_TYPE = "wiki_page"
_PAGE_SIZE = 100
_MAX_SCAN = 1_000
_WIKI_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def _platform_context() -> tuple[t.Any, str, str, str]:
    instance = get_default_instance()
    if not instance.can_sync:
        raise RuntimeError(
            "LLM Wiki reads require a platform-connected runtime with an active project"
        )

    profile = instance.profile
    project = profile.project_key or profile.project_id
    if project is None:
        raise RuntimeError("LLM Wiki reads require an active project")
    return instance.api, profile.org_key, profile.workspace_key, str(project)


def _data_of(item: dict[str, t.Any]) -> dict[str, t.Any]:
    value = item.get("data")
    return value if isinstance(value, dict) else {}


def _status_of(item: dict[str, t.Any]) -> str:
    disposition = item.get("disposition")
    if isinstance(disposition, dict) and disposition.get("status"):
        return str(disposition["status"])
    status = item.get("effective_status")
    return str(status) if status else "none"


async def _scan_wiki_pages(
    api: t.Any,
    org: str,
    workspace: str,
    project: str,
    wiki_id: str,
) -> tuple[list[dict[str, t.Any]], int, int, bool]:
    """Page through wiki_page records via the platform list surface for aggregates."""
    records: list[dict[str, t.Any]] = []
    scanned_candidates = 0
    page = 1
    candidate_total = 0
    while scanned_candidates < _MAX_SCAN:
        payload = await asyncio.to_thread(
            api.list_items,
            org,
            workspace,
            project,
            item_type=_ITEM_TYPE,
            q=wiki_id,
            page=page,
            limit=_PAGE_SIZE,
        )
        raw_items = (
            payload.get("items") if isinstance(payload.get("items"), list) else []
        )
        page_items = [item for item in raw_items if isinstance(item, dict)]
        candidates = page_items[: _MAX_SCAN - scanned_candidates]
        scanned_candidates += len(candidates)
        records.extend(
            item for item in candidates if _data_of(item).get("wiki_id") == wiki_id
        )
        raw_total = payload.get("total")
        candidate_total = (
            raw_total if isinstance(raw_total, int) else scanned_candidates
        )
        has_next = payload.get("has_next")
        if (
            not page_items
            or len(page_items) < _PAGE_SIZE
            or (isinstance(has_next, bool) and not has_next)
            or page * _PAGE_SIZE >= candidate_total
        ):
            break
        page += 1
    return (
        records,
        scanned_candidates,
        candidate_total,
        candidate_total > scanned_candidates,
    )


@tool(name="wiki_progress", truncate=8000)
async def wiki_progress(
    wiki_id: t.Annotated[
        str,
        "Stable lowercase kebab-case namespace of the wiki to summarize.",
    ],
) -> dict[str, t.Any]:
    """Summarize one wiki's bounded coverage so a maintenance loop knows when to stop.

    Browsing, reading, and search are handled by the built-in `list_items`,
    `read_item`, and `search_items` tools; this reports the wiki-specific signal
    those do not: page kinds, disposition mix, and outstanding open questions.
    """
    if len(wiki_id) > 64 or not _WIKI_ID_PATTERN.fullmatch(wiki_id):
        raise ValueError("wiki_id must be 1-64 lowercase kebab-case characters")

    api, org, workspace, project = _platform_context()
    (
        records,
        scanned_candidates,
        candidate_total,
        scan_truncated,
    ) = await _scan_wiki_pages(api, org, workspace, project, wiki_id)
    by_kind = collections.Counter(
        str(_data_of(item).get("kind", "unknown")) for item in records
    )
    by_status = collections.Counter(str(_status_of(item)) for item in records)
    open_questions = 0
    pages_with_open_questions = 0
    for item in records:
        questions = _data_of(item).get("open_questions")
        count = len(questions) if isinstance(questions, list) else 0
        open_questions += count
        if count:
            pages_with_open_questions += 1
    initialized = bool(records)
    return {
        "wiki_id": wiki_id,
        "initialized": initialized,
        "pages_in_scan": len(records),
        "candidates_scanned": scanned_candidates,
        "candidate_platform_total": candidate_total,
        "by_kind": dict(sorted(by_kind.items())),
        "by_status": dict(sorted(by_status.items())),
        "open_questions": open_questions,
        "pages_with_open_questions": pages_with_open_questions,
        # A partial scan must never produce a positive loop stop signal.
        "open_questions_cleared": (
            initialized and not scan_truncated and open_questions == 0
        ),
        "complete_scan": not scan_truncated,
        "scan_truncated": scan_truncated,
    }
