import json
import sys
import typing as t
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method

_CAPABILITY_ROOT = Path(__file__).resolve().parents[1]
if str(_CAPABILITY_ROOT) not in sys.path:
    sys.path.insert(0, str(_CAPABILITY_ROOT))

from web_pd_lib.constants import (  # noqa: E402
    EVENT_JOB_COMPLETED,
    EVENT_JOB_REQUESTED,
    EVENT_JOB_STARTED,
    EVENT_OPPORTUNITY_CLAIMED,
    EVENT_OPPORTUNITY_COMPLETED,
    EVENT_SCAN_STARTED,
    EVENT_SCAN_SUMMARY,
)
from web_pd_lib.journal import PdJournal  # noqa: E402
from web_pd_lib.models import PdEvent  # noqa: E402
from web_pd_lib.pd import PD_TOOL_SPECS, compute_dedupe_key, parse_tool_output, run_pd_binary  # noqa: E402
from web_pd_lib.runtime import emit_pd_event, get_current_actor, new_scan_id, resolve_runtime_paths  # noqa: E402


class ProjectDiscovery(Toolset):
    """ProjectDiscovery-only orchestration over a span journal and SQLite projection."""

    timeout: int = Config(default=300)
    max_results: int = Config(default=50)

    def _journal(self, scan_id: str) -> tuple[PdJournal, t.Any]:
        paths = resolve_runtime_paths(working_dir=Path.cwd(), fallback_key=scan_id)
        return PdJournal(paths.spans_path, paths.journal_path), paths

    @tool_method(name="pd_start_scan", catch=True)
    async def start_scan(
        self,
        target: t.Annotated[str, "Primary domain, host, URL, or scope label for the scan."],
        profile: t.Annotated[str, "Execution profile label recorded in the journal."] = "safe-local",
        notes: t.Annotated[str | None, "Optional operator note stored on the scan start event."] = None,
    ) -> dict[str, t.Any]:
        """Start a ProjectDiscovery scan session and emit the initial scan event."""
        scan_id = new_scan_id()
        paths = resolve_runtime_paths(working_dir=Path.cwd(), fallback_key=scan_id)
        journal = PdJournal(paths.spans_path, paths.journal_path)
        emit_pd_event(
            PdEvent(
                name=EVENT_SCAN_STARTED,
                scan_id=scan_id,
                event_kind="scan.started",
                target=target,
                source="controller",
                status="started",
                summary=notes,
                search_text=" ".join(bit for bit in [target, profile, notes] if bit),
                payload={"profile": profile, "notes": notes or "", "target": target},
            ),
            paths=paths,
        )
        journal.refresh()
        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "run_id": paths.run_id,
            "spans_path": str(paths.spans_path),
            "database": str(paths.journal_path),
        }

    @tool_method(name="pd_refresh_scan_index", catch=True)
    async def refresh_scan_index(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
    ) -> dict[str, t.Any]:
        """Refresh the SQLite projection from spans.jsonl."""
        journal, _paths = self._journal(scan_id)
        refresh_result = journal.refresh()
        summary = journal.get_scan_summary(scan_id)
        return {"refresh": refresh_result, "summary": summary}

    @tool_method(name="pd_get_scan_summary", catch=True)
    async def get_scan_summary(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
    ) -> dict[str, t.Any]:
        """Return event and opportunity counts for the current scan."""
        journal, _paths = self._journal(scan_id)
        journal.refresh()
        summary = journal.get_scan_summary(scan_id)
        return summary

    @tool_method(name="pd_get_facts", catch=True)
    async def get_facts(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        kinds: t.Annotated[
            list[str] | None,
            "Optional fact kinds such as fact.subdomain, fact.service, or fact.finding.",
        ] = None,
        limit: t.Annotated[int, "Maximum number of facts to return."] = 50,
    ) -> list[dict[str, t.Any]]:
        """Return fact events materialized from the span journal."""
        journal, _paths = self._journal(scan_id)
        journal.refresh()
        return journal.list_facts(scan_id=scan_id, kinds=kinds, limit=min(limit, self.max_results))

    @tool_method(name="pd_search_events", catch=True)
    async def search_events(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        query: t.Annotated[str, "FTS query string used against the local event index."],
        limit: t.Annotated[int, "Maximum number of search hits to return."] = 20,
    ) -> list[dict[str, t.Any]]:
        """Search the projected event journal with SQLite FTS5."""
        journal, _paths = self._journal(scan_id)
        journal.refresh()
        return [asdict(result) for result in journal.search(scan_id=scan_id, query=query, limit=limit)]

    @tool_method(name="pd_get_opportunities", catch=True)
    async def get_opportunities(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        status: t.Annotated[str | None, "Optional status filter such as open, claimed, or completed."] = "open",
        limit: t.Annotated[int, "Maximum number of opportunities to return."] = 10,
    ) -> list[dict[str, t.Any]]:
        """Return ranked derived opportunities for the scan."""
        journal, _paths = self._journal(scan_id)
        journal.refresh()
        return [asdict(item) for item in journal.list_opportunities(scan_id=scan_id, status=status, limit=limit)]

    @tool_method(name="pd_claim_opportunity", catch=True)
    async def claim_opportunity(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        opportunity_key: t.Annotated[str, "Opportunity key returned by pd_get_opportunities."],
        owner: t.Annotated[str | None, "Optional owner label; defaults to the current actor."] = None,
        summary: t.Annotated[str | None, "Optional short note describing the claim."] = None,
    ) -> dict[str, t.Any]:
        """Claim an opportunity by appending a claim event to the journal."""
        actor = owner or get_current_actor()
        journal, paths = self._journal(scan_id)
        journal.refresh()
        current = journal.list_opportunities(scan_id=scan_id, status=None, limit=self.max_results)
        match = next((item for item in current if item.opportunity_key == opportunity_key), None)
        if match is None:
            raise ValueError(f"Unknown opportunity key: {opportunity_key}")

        emit_pd_event(
            PdEvent(
                name=EVENT_OPPORTUNITY_CLAIMED,
                scan_id=scan_id,
                event_kind="opportunity.claimed",
                target=match.target,
                opportunity_key=match.opportunity_key,
                opportunity_kind=match.kind,
                priority=match.priority,
                status="claimed",
                owner=actor,
                summary=summary or match.summary,
                search_text=" ".join(bit for bit in [match.target, actor, summary or ""] if bit),
                payload={"score": match.score},
            ),
            paths=paths,
        )
        journal.refresh()
        updated = journal.list_opportunities(scan_id=scan_id, status=None, limit=self.max_results)
        claimed = next((item for item in updated if item.opportunity_key == opportunity_key), None)
        return asdict(claimed) if claimed is not None else {"opportunity_key": opportunity_key}

    @tool_method(name="pd_complete_opportunity", catch=True)
    async def complete_opportunity(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        opportunity_key: t.Annotated[str, "Opportunity key returned by pd_get_opportunities."],
        summary: t.Annotated[str, "Short completion note for the finished opportunity."],
        owner: t.Annotated[str | None, "Optional owner label; defaults to the current actor."] = None,
    ) -> dict[str, t.Any]:
        """Complete an opportunity by appending a completion event to the journal."""
        actor = owner or get_current_actor()
        journal, paths = self._journal(scan_id)
        journal.refresh()
        current = journal.list_opportunities(scan_id=scan_id, status=None, limit=self.max_results)
        match = next((item for item in current if item.opportunity_key == opportunity_key), None)
        if match is None:
            raise ValueError(f"Unknown opportunity key: {opportunity_key}")

        emit_pd_event(
            PdEvent(
                name=EVENT_OPPORTUNITY_COMPLETED,
                scan_id=scan_id,
                event_kind="opportunity.completed",
                target=match.target,
                opportunity_key=match.opportunity_key,
                opportunity_kind=match.kind,
                priority=match.priority,
                status="completed",
                owner=actor,
                summary=summary,
                search_text=" ".join(bit for bit in [match.target, summary] if bit),
                payload={"score": match.score},
            ),
            paths=paths,
        )
        journal.refresh()
        updated = journal.list_opportunities(scan_id=scan_id, status=None, limit=self.max_results)
        completed = next((item for item in updated if item.opportunity_key == opportunity_key), None)
        return asdict(completed) if completed is not None else {"opportunity_key": opportunity_key}

    @tool_method(name="pd_run_subfinder", catch=True)
    async def run_subfinder(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        domains: t.Annotated[list[str], "Root domains to enumerate with subfinder."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to subfinder."] = None,
    ) -> dict[str, t.Any]:
        """Run subfinder and emit structured subdomain facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="subfinder", targets=domains, extra_args=extra_args)

    @tool_method(name="pd_run_httpx", catch=True)
    async def run_httpx(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts or URLs to probe with httpx."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to httpx."] = None,
    ) -> dict[str, t.Any]:
        """Run httpx and emit structured service and URL facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="httpx", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_katana", catch=True)
    async def run_katana(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "URLs or hosts to crawl with katana."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to katana."] = None,
    ) -> dict[str, t.Any]:
        """Run katana and emit discovered URL facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="katana", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_dnsx", catch=True)
    async def run_dnsx(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts to resolve with dnsx."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to dnsx."] = None,
    ) -> dict[str, t.Any]:
        """Run dnsx and emit DNS fact events."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="dnsx", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_naabu", catch=True)
    async def run_naabu(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts to scan with naabu."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to naabu."] = None,
    ) -> dict[str, t.Any]:
        """Run naabu and emit open-port facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="naabu", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_tlsx", catch=True)
    async def run_tlsx(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts to fingerprint with tlsx."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to tlsx."] = None,
    ) -> dict[str, t.Any]:
        """Run tlsx and emit certificate facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="tlsx", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_alterx", catch=True)
    async def run_alterx(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts or domains to expand with alterx."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to alterx."] = None,
    ) -> dict[str, t.Any]:
        """Run alterx and emit generated subdomain facts."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="alterx", targets=targets, extra_args=extra_args)

    @tool_method(name="pd_run_nuclei", catch=True)
    async def run_nuclei(
        self,
        scan_id: t.Annotated[str, "Scan identifier returned by pd_start_scan."],
        targets: t.Annotated[list[str], "Hosts or URLs to validate with nuclei."],
        extra_args: t.Annotated[list[str] | None, "Optional extra CLI arguments appended to nuclei."] = None,
    ) -> dict[str, t.Any]:
        """Run nuclei and emit structured finding facts plus validation candidates."""
        return await self._run_pd_tool(scan_id=scan_id, tool_name="nuclei", targets=targets, extra_args=extra_args)

    async def _run_pd_tool(
        self,
        *,
        scan_id: str,
        tool_name: str,
        targets: list[str],
        extra_args: list[str] | None,
    ) -> dict[str, t.Any]:
        spec = PD_TOOL_SPECS[tool_name]
        journal, paths = self._journal(scan_id)
        journal.refresh()

        normalized_targets = [target.strip() for target in targets if target and target.strip()]
        if not normalized_targets:
            raise ValueError(f"{tool_name} requires at least one target")

        resolved_args = extra_args or []
        dedupe_key = compute_dedupe_key(
            scan_id=scan_id,
            tool_name=tool_name,
            targets=normalized_targets,
            extra_args=resolved_args,
        )
        existing_job = journal.get_job_by_dedupe(scan_id, dedupe_key)
        if existing_job is not None and existing_job.get("status") == "completed":
            return {
                "deduped": True,
                "job": existing_job,
                "summary": journal.get_scan_summary(scan_id),
            }

        job_id = uuid4().hex
        target_label = ", ".join(normalized_targets[:3])
        emit_pd_event(
            PdEvent(
                name=EVENT_JOB_REQUESTED,
                scan_id=scan_id,
                event_kind="job.requested",
                target=target_label,
                tool=tool_name,
                job_id=job_id,
                dedupe_key=dedupe_key,
                status="requested",
                search_text=" ".join([tool_name, target_label, *resolved_args]).strip(),
                payload={"targets": normalized_targets, "extra_args": resolved_args},
            ),
            paths=paths,
        )
        emit_pd_event(
            PdEvent(
                name=EVENT_JOB_STARTED,
                scan_id=scan_id,
                event_kind="job.started",
                target=target_label,
                tool=tool_name,
                job_id=job_id,
                dedupe_key=dedupe_key,
                status="running",
                search_text=" ".join([tool_name, target_label]).strip(),
                payload={"targets": normalized_targets, "extra_args": resolved_args},
            ),
            paths=paths,
        )

        result = await run_pd_binary(spec=spec, targets=normalized_targets, extra_args=resolved_args, timeout=self.timeout)
        artifact_path = self._write_artifact(paths=paths, scan_id=scan_id, job_id=job_id, tool_name=tool_name, result=result)
        facts, opportunities = parse_tool_output(
            tool_name=tool_name,
            scan_id=scan_id,
            job_id=job_id,
            source=tool_name,
            items=result.items,
            raw_output=result.raw_output,
        )

        for fact in facts:
            fact.artifact_path = str(artifact_path)
            emit_pd_event(fact, paths=paths)
        for opportunity in opportunities:
            opportunity.artifact_path = str(artifact_path)
            emit_pd_event(opportunity, paths=paths)

        emit_pd_event(
            PdEvent(
                name=EVENT_JOB_COMPLETED,
                scan_id=scan_id,
                event_kind="job.completed",
                target=target_label,
                tool=tool_name,
                job_id=job_id,
                dedupe_key=dedupe_key,
                status="completed" if result.success else "failed",
                artifact_path=str(artifact_path),
                summary=result.error or f"{len(facts)} facts, {len(opportunities)} opportunities",
                search_text=" ".join(
                    bit
                    for bit in [
                        tool_name,
                        target_label,
                        result.error or "",
                    ]
                    if bit
                ),
                payload={
                    "command": result.command,
                    "return_code": result.return_code,
                    "elapsed_seconds": result.elapsed_seconds,
                    "fact_count": len(facts),
                    "opportunity_count": len(opportunities),
                },
            ),
            paths=paths,
        )
        journal.refresh()
        summary = journal.get_scan_summary(scan_id)
        emit_pd_event(
            PdEvent(
                name=EVENT_SCAN_SUMMARY,
                scan_id=scan_id,
                event_kind="scan.summary",
                target=target_label,
                tool=tool_name,
                job_id=job_id,
                status="ok",
                summary=json.dumps(summary, sort_keys=True),
                search_text=f"{scan_id} {tool_name}",
                payload=summary,
            ),
            paths=paths,
        )
        journal.refresh()

        return {
            "scan_id": scan_id,
            "job_id": job_id,
            "tool": tool_name,
            "dedupe_key": dedupe_key,
            "command": result.command,
            "success": result.success,
            "return_code": result.return_code,
            "elapsed_seconds": result.elapsed_seconds,
            "artifact_path": str(artifact_path),
            "fact_count": len(facts),
            "opportunity_count": len(opportunities),
            "stderr": result.error,
            "facts": [asdict(item) for item in facts[:10]],
            "opportunities": [asdict(item) for item in opportunities[:10]],
            "summary": journal.get_scan_summary(scan_id),
        }

    def _write_artifact(
        self,
        *,
        paths: t.Any,
        scan_id: str,
        job_id: str,
        tool_name: str,
        result: t.Any,
    ) -> Path:
        scan_dir = paths.artifact_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = scan_dir / f"{job_id}-{tool_name}.jsonl"
        lines = result.raw_output or []
        artifact_path.write_text("\n".join(lines), encoding="utf-8")
        return artifact_path
