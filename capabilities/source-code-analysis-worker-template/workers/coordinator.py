"""Multi-agent source analysis coordinator — example capability worker.

This worker subscribes to ``source-analysis.requested`` on the runtime
event bus and runs a multi-stage agent pipeline against the GitHub repo
in the request payload:

    clone repo
        │
        ▼
    attack-surface mapper        (1 agent)
        │
        ▼
    5 specialists in parallel    (asyncio.gather + semaphore)
        │
        ▼
    final reviewer               (reconciles + investigates + records
                                  high/critical findings via tool)
        │
        ▼
    0..N validators              (1 per recorded finding, parallel)
        │
        ▼
    final markdown report

The file is intended to be readable top-to-bottom as a tutorial example
of a worker-coordinated capability. The patterns it shows up:

- ``@worker.on_event(...)`` to subscribe an event handler to the bus.
- ``client.create_session(...)`` + ``client.run_turn(...)`` to run an
  agent headlessly with a policy + labels.
- Reading both ``response_text`` and ``tool_calls`` off the
  ``turn.completed`` result — markdown for humans, structured signals
  for downstream stages.
- ``asyncio.gather`` + ``Semaphore`` for bounded-parallel agent fan-out.
- Extracting structured findings from a capability tool's ``tool_calls``
  while accounting for wire-name namespacing.
- ``client.publish(...)`` to stream progress and per-agent reports back
  onto the runtime event bus, so launchers can render in real time.

Production orchestrators typically layer on recovery turns,
``TurnFailedError`` salvage, cancellation, run-state persistence, and
graceful degradation. Those are intentionally omitted here so the
control flow stays readable. See README ➜ "What's Not In Here".
"""

import asyncio
import json
import re
import tempfile
import typing as t
from pathlib import Path
from uuid import uuid4

from dreadnode.capabilities.worker import EventEnvelope, RuntimeClient, Worker
from loguru import logger

# ── Configuration ────────────────────────────────────────────────────────

CAPABILITY_NAME = "source-code-analysis-worker-template"

# Event kinds on the runtime bus.
REQUEST_EVENT = "source-analysis.requested"
PROGRESS_EVENT = "source-analysis.progress"
REPORT_READY_EVENT = "source-analysis.report.ready"
COMPLETED_EVENT = "source-analysis.completed"
FAILED_EVENT = "source-analysis.failed"

# Agent names — must match the ``name:`` frontmatter in agents/*.md.
MAPPER = "attack-surface-mapper"
SPECIALISTS: tuple[str, ...] = (
    "cve-history-researcher",
    "recent-commit-test-reviewer",
    "common-vulnerability-hunter",
    "supply-chain-config-reviewer",
    "adversarial-pathfinder",
)
FINAL_REVIEWER = "final-reviewer"
VALIDATOR = "finding-validator"

DEFAULT_MAX_STEPS = 200
DEFAULT_SPECIALIST_CONCURRENCY = 3
DEFAULT_VALIDATOR_CONCURRENCY = 3
CLONE_DEPTH = 200
FINAL_REPORT_TRUNCATE_CHARS = 24_000

# Capability tools are exposed to the model under a wire name of the shape
# ``<sanitized-capability>__<bare-name>``; built-in tools use the bare name.
# Both forms appear in ``tool_calls`` depending on which side registered the
# tool — accept either when extracting findings.
RECORD_FINDING_TOOL = "record_finding"

worker = Worker(name="coordinator")


# ── Event handler ────────────────────────────────────────────────────────


@worker.on_event(REQUEST_EVENT)
async def analyze_repository(event: EventEnvelope, client: RuntimeClient) -> None:
    """Run one analysis end-to-end. Publishes COMPLETED or FAILED at exit."""
    payload = event.payload or {}
    run_id = str(payload.get("run_id") or uuid4())
    github_url = str(payload.get("github_url") or "").strip()
    model = payload.get("model") or None
    max_steps = int(payload.get("max_steps") or DEFAULT_MAX_STEPS)

    if not _is_github_url(github_url):
        await client.publish(
            FAILED_EVENT,
            {
                "run_id": run_id,
                "error": "missing or invalid github_url (expected https://github.com/owner/repo)",
            },
        )
        return

    try:
        final_report = await _run_pipeline(
            client,
            run_id=run_id,
            github_url=github_url,
            model=model,
            max_steps=max_steps,
        )
    except Exception as exc:
        logger.exception("source-analysis run failed | run_id={}", run_id)
        await client.publish(
            FAILED_EVENT,
            {
                "run_id": run_id,
                "github_url": github_url,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return

    await client.publish(
        COMPLETED_EVENT,
        {"run_id": run_id, "github_url": github_url, "final_report": final_report},
    )


# ── Pipeline ─────────────────────────────────────────────────────────────


async def _run_pipeline(
    client: RuntimeClient,
    *,
    run_id: str,
    github_url: str,
    model: str | None,
    max_steps: int,
) -> str:
    """Five stages: clone → mapper → specialists → final reviewer → validators."""
    with tempfile.TemporaryDirectory(prefix="source-analysis-") as tmp:
        repo_dir = Path(tmp) / "repo"

        # Stage 1: clone the repo into a temp dir the agents can inspect.
        await _publish_progress(client, run_id, "clone_started", f"Cloning {github_url}")
        await _git_clone(github_url, repo_dir)

        # Stage 2: attack surface mapper. One agent. Output is the lead list
        # every later stage uses to orient its review.
        await _publish_progress(client, run_id, "mapper_started")
        attack_surface, _ = await _run_agent_turn(
            client,
            run_id=run_id,
            github_url=github_url,
            agent=MAPPER,
            model=model,
            max_steps=max_steps,
            prompt=_mapper_prompt(github_url, repo_dir, max_steps),
        )
        await _publish_report(client, run_id, github_url, MAPPER, attack_surface)

        # Stage 3: 5 specialists in parallel, each examining a different
        # threat surface (CVE history, recent commits, common vulns, supply
        # chain, novel paths). Bounded concurrency so we don't fan out
        # arbitrarily wide.
        await _publish_progress(
            client,
            run_id,
            "specialists_started",
            f"Running {len(SPECIALISTS)} specialists",
        )
        specialist_reports = await _run_specialists(
            client,
            run_id=run_id,
            github_url=github_url,
            repo_dir=repo_dir,
            model=model,
            max_steps=max_steps,
            attack_surface=attack_surface,
        )

        # Stage 4: final reviewer. Reconciles specialist evidence into a
        # single review AND performs an independent adversarial pass over the
        # codebase, recording each high/critical finding via the
        # ``record_finding`` capability tool. The worker reads those tool
        # calls below to spawn validators.
        await _publish_progress(client, run_id, "final_review_started")
        final_report, final_tool_calls = await _run_agent_turn(
            client,
            run_id=run_id,
            github_url=github_url,
            agent=FINAL_REVIEWER,
            model=model,
            max_steps=max_steps,
            prompt=_final_review_prompt(github_url, repo_dir, max_steps, specialist_reports, attack_surface),
        )
        await _publish_report(client, run_id, github_url, FINAL_REVIEWER, final_report)

        # Stage 5: validators. One per recorded finding, in parallel.
        findings = _extract_findings(final_tool_calls)
        await _publish_progress(
            client,
            run_id,
            "validation_started",
            f"Validating {len(findings)} high/critical findings",
        )
        validation_reports = await _run_validators(
            client,
            run_id=run_id,
            github_url=github_url,
            repo_dir=repo_dir,
            model=model,
            max_steps=max_steps,
            final_report=final_report,
            findings=findings,
        )

        return _build_final_markdown(final_report, findings, validation_reports)


# ── Stage runners ────────────────────────────────────────────────────────


async def _run_specialists(
    client: RuntimeClient,
    *,
    run_id: str,
    github_url: str,
    repo_dir: Path,
    model: str | None,
    max_steps: int,
    attack_surface: str,
) -> dict[str, str]:
    """Run all specialists in parallel, bounded by a semaphore."""
    sem = asyncio.Semaphore(DEFAULT_SPECIALIST_CONCURRENCY)

    async def run_one(agent: str) -> tuple[str, str]:
        async with sem:
            report, _ = await _run_agent_turn(
                client,
                run_id=run_id,
                github_url=github_url,
                agent=agent,
                model=model,
                max_steps=max_steps,
                prompt=_specialist_prompt(agent, github_url, repo_dir, max_steps, attack_surface),
            )
        # Stream the report as soon as this specialist finishes — consumers
        # see progress without waiting for the slowest one.
        await _publish_report(client, run_id, github_url, agent, report)
        return agent, report

    results = await asyncio.gather(*(run_one(a) for a in SPECIALISTS))
    return dict(results)


async def _run_validators(
    client: RuntimeClient,
    *,
    run_id: str,
    github_url: str,
    repo_dir: Path,
    model: str | None,
    max_steps: int,
    final_report: str,
    findings: list[dict[str, t.Any]],
) -> dict[str, str]:
    """Validate each finding in its own session, in parallel."""
    if not findings:
        return {}
    sem = asyncio.Semaphore(DEFAULT_VALIDATOR_CONCURRENCY)
    truncated = _truncate(final_report, FINAL_REPORT_TRUNCATE_CHARS)

    async def validate_one(finding: dict[str, t.Any]) -> tuple[str, str]:
        finding_id = str(finding.get("id") or "unknown-finding")
        async with sem:
            report, _ = await _run_agent_turn(
                client,
                run_id=run_id,
                github_url=github_url,
                agent=VALIDATOR,
                model=model,
                max_steps=max_steps,
                prompt=_validator_prompt(github_url, repo_dir, max_steps, finding, truncated),
                # Tag the validator's session with its finding id so it's
                # easy to find in the trace UI.
                extra_labels={"finding_id": finding_id},
            )
        return finding_id, report

    results = await asyncio.gather(*(validate_one(f) for f in findings))
    return dict(results)


# ── Single agent turn ────────────────────────────────────────────────────


async def _run_agent_turn(
    client: RuntimeClient,
    *,
    run_id: str,
    github_url: str,
    agent: str,
    model: str | None,
    max_steps: int,
    prompt: str,
    extra_labels: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, t.Any]]]:
    """Create one session, run one headless turn, return (response_text, tool_calls)."""
    labels: dict[str, list[str]] = {
        "source_analysis_run": [run_id],
        "github_url": [github_url],
        "agent_role": [agent],
    }
    if extra_labels:
        for key, value in extra_labels.items():
            labels[key] = [value]

    session = await client.create_session(
        capability=CAPABILITY_NAME,
        agent=agent,
        model=model,
        policy={"name": "headless", "max_steps": max_steps},
        labels=labels,
    )
    await client.set_session_title(session.session_id, f"source-analysis {run_id[:8]} · {agent}")
    result = await client.run_turn(
        session_id=session.session_id,
        message=prompt,
        agent=agent,
        model=model,
        reset=True,
    )
    response_text = str(result.get("response_text") or "").strip()
    tool_calls = result.get("tool_calls") or []
    if not isinstance(tool_calls, list):
        tool_calls = []
    return response_text, tool_calls


# ── Prompt builders ──────────────────────────────────────────────────────
# Agents carry their full role, mission, and output schema in their .md
# system prompts. The user-message prompts below only carry per-call
# dynamic context (URL, paths, prior reports).


def _mapper_prompt(github_url: str, repo_dir: Path, max_steps: int) -> str:
    return (
        f"Map the attack surface for {github_url}.\n"
        f"Local checkout: {repo_dir}\n"
        f"Autonomous step budget: {max_steps}\n"
    )


def _specialist_prompt(agent: str, github_url: str, repo_dir: Path, max_steps: int, attack_surface: str) -> str:
    return (
        f"Analyze {github_url} as the {agent} specialist.\n"
        f"Local checkout: {repo_dir}\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Attack surface map (leads, not conclusions):\n{attack_surface}\n"
    )


def _final_review_prompt(
    github_url: str,
    repo_dir: Path,
    max_steps: int,
    specialist_reports: dict[str, str],
    attack_surface: str,
) -> str:
    rendered = "\n\n".join(f"# {agent}\n{r}" for agent, r in specialist_reports.items())
    return (
        f"Final review for {github_url}.\n"
        f"Local checkout: {repo_dir}\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Attack surface map:\n{attack_surface}\n\n"
        f"Specialist reports:\n{rendered}\n"
    )


def _validator_prompt(
    github_url: str,
    repo_dir: Path,
    max_steps: int,
    finding: dict[str, t.Any],
    final_report: str,
) -> str:
    finding_json = json.dumps(finding, indent=2, sort_keys=True)
    return (
        f"Validate one finding for {github_url}.\n"
        f"Local checkout: {repo_dir}\n"
        f"Autonomous step budget: {max_steps}\n\n"
        f"Finding to validate:\n```json\n{finding_json}\n```\n\n"
        f"Final review context:\n{final_report}\n"
    )


# ── Findings extraction ──────────────────────────────────────────────────


def _extract_findings(tool_calls: list[dict[str, t.Any]]) -> list[dict[str, t.Any]]:
    """Pull ``record_finding`` calls of high/critical severity, in call order.

    Capability tools appear in ``tool_calls`` under their wire name
    (``<sanitized_capability>__<bare>``). Built-in tools use the bare name.
    Match either form so this works regardless of which side registers the
    tool.
    """
    findings: list[dict[str, t.Any]] = []
    suffix = f"__{RECORD_FINDING_TOOL}"
    for index, call in enumerate(tool_calls, start=1):
        if not isinstance(call, dict):
            continue
        name = call.get("name") or ""
        if not isinstance(name, str):
            continue
        if name != RECORD_FINDING_TOOL and not name.endswith(suffix):
            continue
        args = call.get("arguments")
        if not isinstance(args, dict):
            continue
        severity = str(args.get("severity") or "").strip().lower()
        if severity not in {"high", "critical"}:
            continue
        finding = dict(args)
        finding["severity"] = severity
        finding.setdefault("id", f"FINDING-{index:03d}")
        findings.append(finding)
    return findings


# ── Helpers ──────────────────────────────────────────────────────────────


def _is_github_url(url: str) -> bool:
    return bool(re.match(r"^https://github\.com/[^/\s]+/[^/\s]+(?:\.git)?/?$", url))


async def _git_clone(url: str, dest: Path) -> None:
    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth",
        str(CLONE_DEPTH),
        url,
        str(dest),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode('utf-8', 'replace').strip()}")


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... truncated ..."


async def _publish_progress(client: RuntimeClient, run_id: str, stage: str, detail: str | None = None) -> None:
    payload: dict[str, t.Any] = {"run_id": run_id, "stage": stage}
    if detail:
        payload["detail"] = detail
    await client.publish(PROGRESS_EVENT, payload)


async def _publish_report(client: RuntimeClient, run_id: str, github_url: str, agent: str, report: str) -> None:
    await client.publish(
        REPORT_READY_EVENT,
        {"run_id": run_id, "github_url": github_url, "agent": agent, "report": report},
    )


def _build_final_markdown(
    final_report: str,
    findings: list[dict[str, t.Any]],
    validation_reports: dict[str, str],
) -> str:
    """Stitch validator reports onto the final review."""
    sections = [final_report.rstrip(), "", "## Validator Results"]
    if not findings:
        sections.append("No high or critical findings recorded; validators were not run.")
        return "\n".join(sections).rstrip() + "\n"
    sections.append(f"Reviewed {len(validation_reports)} of {len(findings)} high or critical findings.")
    for finding in findings:
        finding_id = str(finding.get("id") or "unknown-finding")
        title = str(finding.get("title") or "Untitled finding")
        sections.extend(["", f"### {finding_id}: {title}"])
        report = validation_reports.get(finding_id)
        sections.append(report or "Validator report was not produced for this finding.")
    return "\n".join(sections).rstrip() + "\n"


if __name__ == "__main__":
    worker.run()
