"""Frontier-control reads over the built-in Agent Output read surface.

Generic browsing, reading, and full-text search are provided by the platform's
built-in `list_items`, `read_item`, and `search_items` tools. This module adds
only the two frontier-control views those cannot express: best-first target
selection (ordered by the run's custom `priority`/`depth` fields) and a run
progress roll-up over target states and claim dispositions.
"""

import asyncio
import collections
import typing as t

from dreadnode import get_default_instance
from dreadnode.agents.tools import tool

_PAGE_SIZE = 100
_MAX_SCAN = 1_000


def _platform_context() -> tuple[t.Any, str, str, str]:
    instance = get_default_instance()
    if not instance.can_sync:
        raise RuntimeError(
            "Analysis Ledger reads require a platform-connected runtime with an active project"
        )

    profile = instance.profile
    project = profile.project_key or profile.project_id
    if project is None:
        raise RuntimeError("Analysis Ledger reads require an active project")
    return instance.api, profile.org_key, profile.workspace_key, str(project)


def _has_value(value: t.Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _clean(values: dict[str, t.Any]) -> dict[str, t.Any]:
    return {key: value for key, value in values.items() if _has_value(value)}


def _data(item: dict[str, t.Any]) -> dict[str, t.Any]:
    value = item.get("data")
    return value if isinstance(value, dict) else {}


def _clip(value: t.Any, limit: int) -> t.Any:
    if not isinstance(value, str) or len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _target_summary(item: dict[str, t.Any]) -> dict[str, t.Any]:
    data = _data(item)
    return _clean(
        {
            "id": item.get("id"),
            "ref": _clip(item.get("ref"), 128),
            "item_type": item.get("item_type") or "analysis_target",
            "title": _clip(item.get("title") or data.get("title"), 512),
            "run_ref": _clip(data.get("run_ref"), 128),
            "target_key": _clip(data.get("target_key"), 512),
            "kind": data.get("kind"),
            "location": _clip(data.get("location"), 512),
            "priority": data.get("priority"),
            "target_state": data.get("target_state"),
            "depth": data.get("depth"),
            "parent_ref": _clip(data.get("parent_ref"), 128),
            "summary": _clip(data.get("summary"), 1_000),
            "updated_at": item.get("updated_at"),
        }
    )


async def _scan_items(
    api: t.Any,
    org: str,
    workspace: str,
    project: str,
    item_type: str,
    *,
    query: str,
) -> tuple[list[dict[str, t.Any]], int, int, bool]:
    """Page one analysis item type through the built-in list surface.

    Server-side filtering covers `item_type`; the run/state selectors live in the
    item ``data`` (not indexed columns). Full-text query narrows candidates by
    run ref; callers still apply an exact in-memory check.
    """
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
            item_type=item_type,
            q=query,
            page=page,
            limit=_PAGE_SIZE,
        )
        raw_items = (
            payload.get("items") if isinstance(payload.get("items"), list) else []
        )
        page_items = [item for item in raw_items if isinstance(item, dict)]
        candidates = page_items[: _MAX_SCAN - scanned_candidates]
        scanned_candidates += len(candidates)
        records.extend(candidates)
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


async def _require_run(
    api: t.Any,
    org: str,
    workspace: str,
    project: str,
    run_ref: str,
) -> dict[str, t.Any]:
    payload = await asyncio.to_thread(
        api.list_items,
        org,
        workspace,
        project,
        item_type="analysis_run",
        ref=run_ref,
        page=1,
        limit=2,
    )
    raw_items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(raw_items, list):
        raw_items = []
    items = [item for item in raw_items if isinstance(item, dict)]
    exact = [item for item in items if item.get("ref") == run_ref]
    if not exact:
        raise ValueError(
            f"analysis_run ref '{run_ref}' was not found or is not readable"
        )
    if len(exact) > 1:
        raise RuntimeError(f"analysis_run ref '{run_ref}' is not unique")
    return exact[0]


def _target_sort_key(item: dict[str, t.Any]) -> tuple[int, int, int, str]:
    data = _data(item)
    state_rank = 0 if data.get("target_state") == "in-progress" else 1
    raw_priority = data.get("priority", 0)
    raw_depth = data.get("depth", 0)
    priority = raw_priority if isinstance(raw_priority, int) else 0
    depth = raw_depth if isinstance(raw_depth, int) else 0
    stable_ref = str(item.get("ref") or data.get("target_key") or item.get("id") or "")
    return state_rank, -priority, depth, stable_ref


@tool(name="analysis_next_targets", truncate=12000)
async def analysis_next_targets(
    run_ref: t.Annotated[str, "Owning analysis_run ref."],
    limit: t.Annotated[
        int,
        "In-progress recovery target or highest-priority queued targets to return (1-5).",
    ] = 1,
    min_priority: t.Annotated[int, "Minimum target priority (0-100)."] = 0,
) -> dict[str, t.Any]:
    """Resume in-progress work, otherwise select queued targets deterministically.

    `list_items` sorts only by created_at/severity/status, so best-first ordering
    over the run's custom priority/depth fields is computed here. In-progress
    targets sort first so a fresh single-agent session can recover after a crash.
    """
    if limit < 1 or limit > 5:
        raise ValueError("limit must be between 1 and 5")
    if min_priority < 0 or min_priority > 100:
        raise ValueError("min_priority must be between 0 and 100")

    api, org, workspace, project = _platform_context()
    await _require_run(api, org, workspace, project, run_ref)
    records, scanned_candidates, candidate_total, scan_truncated = await _scan_items(
        api,
        org,
        workspace,
        project,
        "analysis_target",
        query=run_ref,
    )
    eligible = []
    for item in records:
        data = _data(item)
        priority = data.get("priority", 0)
        if (
            data.get("run_ref") == run_ref
            and data.get("target_state") in {"in-progress", "queued"}
            and isinstance(priority, int)
            and priority >= min_priority
        ):
            eligible.append(item)
    eligible.sort(key=_target_sort_key)
    selected = [] if scan_truncated else eligible[:limit]
    return {
        "run_ref": run_ref,
        "targets": [_target_summary(item) for item in selected],
        "resuming_in_progress": sum(
            1 for item in selected if _data(item).get("target_state") == "in-progress"
        ),
        "eligible_in_scan": len(eligible),
        "candidates_scanned": scanned_candidates,
        "candidate_platform_total": candidate_total,
        "selection_complete": not scan_truncated,
        "scan_truncated": scan_truncated,
    }


@tool(name="analysis_progress", truncate=12000)
async def analysis_progress(
    run_ref: t.Annotated[str, "Owning analysis_run ref."],
) -> dict[str, t.Any]:
    """Summarize target and claim state for one analysis run.

    Aggregates by the custom `data.target_state` and claim `disposition` fields, which
    the built-in facets (severity/status/category/capability/source) do not
    expose.
    """
    api, org, workspace, project = _platform_context()
    run = await _require_run(api, org, workspace, project, run_ref)
    run_data = _data(run)
    (
        targets,
        target_candidates_scanned,
        target_candidate_total,
        target_truncated,
    ) = await _scan_items(
        api,
        org,
        workspace,
        project,
        "analysis_target",
        query=run_ref,
    )
    (
        claims,
        claim_candidates_scanned,
        claim_candidate_total,
        claim_truncated,
    ) = await _scan_items(
        api,
        org,
        workspace,
        project,
        "analysis_claim",
        query=run_ref,
    )
    run_targets = [item for item in targets if _data(item).get("run_ref") == run_ref]
    run_claims = [item for item in claims if _data(item).get("run_ref") == run_ref]
    target_states = collections.Counter(
        str(_data(item).get("target_state", "unknown")) for item in run_targets
    )
    claim_states = collections.Counter(
        str(_data(item).get("disposition", "unknown")) for item in run_claims
    )
    queued_priorities = [
        priority
        for item in run_targets
        if _data(item).get("target_state") == "queued"
        for priority in [_data(item).get("priority")]
        if isinstance(priority, int)
    ]
    observed_depths = [
        depth
        for item in run_targets
        for depth in [_data(item).get("depth")]
        if isinstance(depth, int)
    ]
    progress_complete = not target_truncated and not claim_truncated
    recorded_targets_discovered = run_data.get("targets_discovered", 0)
    initialized = bool(run_targets) or (
        isinstance(recorded_targets_discovered, int) and recorded_targets_discovered > 0
    )
    frontier_exhausted = (
        initialized
        and progress_complete
        and not target_states.get("queued")
        and not target_states.get("in-progress")
    )
    max_targets = run_data.get("max_targets", 50)
    target_budget_reached = (
        progress_complete
        and isinstance(max_targets, int)
        and len(run_targets) >= max_targets
    )
    non_expanding_iterations = run_data.get("non_expanding_iterations", 0)
    non_expanding_stop = (
        initialized
        and isinstance(non_expanding_iterations, int)
        and non_expanding_iterations >= 3
    )
    stop_reasons = []
    if frontier_exhausted:
        stop_reasons.append("frontier_exhausted")
    if target_budget_reached:
        stop_reasons.append("target_budget_reached")
    if non_expanding_stop:
        stop_reasons.append("non_expanding_limit_reached")
    return {
        "run_ref": run_ref,
        "initialized": initialized,
        "run": _clean(
            {
                "run_key": run_data.get("run_key"),
                "run_state": run_data.get("run_state"),
                "max_targets": max_targets,
                "max_depth": run_data.get("max_depth"),
                "iterations_completed": run_data.get("iterations_completed"),
                "non_expanding_iterations": non_expanding_iterations,
                "targets_discovered": recorded_targets_discovered,
                "stop_reason": run_data.get("stop_reason"),
            }
        ),
        "targets": {
            "total_in_scan": len(run_targets),
            "by_state": dict(sorted(target_states.items())),
            **_clean(
                {
                    "highest_queued_priority": max(
                        queued_priorities,
                        default=None,
                    ),
                    "max_observed_depth": max(observed_depths, default=None),
                }
            ),
        },
        "claims": {
            "total_in_scan": len(run_claims),
            "by_disposition": dict(sorted(claim_states.items())),
        },
        "frontier_exhausted": frontier_exhausted,
        "target_budget_reached": target_budget_reached,
        "stop_ready": initialized and progress_complete and bool(stop_reasons),
        "stop_reasons": stop_reasons,
        "scan": {
            "target_candidates_scanned": target_candidates_scanned,
            "target_candidate_platform_total": target_candidate_total,
            "claim_candidates_scanned": claim_candidates_scanned,
            "claim_candidate_platform_total": claim_candidate_total,
            "complete": progress_complete,
            "truncated": target_truncated or claim_truncated,
        },
    }
