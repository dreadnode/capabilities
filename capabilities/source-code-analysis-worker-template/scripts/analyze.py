"""Submit a source-analysis run and stream progress to the terminal.

This is a thin example launcher for the source-code-analysis-worker-template
capability. It:

1. Connects to a runtime (remote sandbox by default, in-process with
   ``--local``).
2. Subscribes to the runtime event bus, filtering by run id.
3. Publishes a ``source-analysis.requested`` event.
4. Prints progress and per-agent ``report.ready`` events as they arrive.
5. Writes the final markdown to disk when ``source-analysis.completed``
   fires.

The capability itself lives in ``workers/coordinator.py``. Read that file
first to understand the analysis pipeline; this script is just glue.
"""

import argparse
import asyncio
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from dreadnode.app.client.runtime_client import RuntimeClient

REQUEST_EVENT = "source-analysis.requested"
PROGRESS_EVENT = "source-analysis.progress"
REPORT_READY_EVENT = "source-analysis.report.ready"
COMPLETED_EVENT = "source-analysis.completed"
FAILED_EVENT = "source-analysis.failed"

WATCH_KINDS: tuple[str, ...] = (
    PROGRESS_EVENT,
    REPORT_READY_EVENT,
    COMPLETED_EVENT,
    FAILED_EVENT,
)


async def amain(args: argparse.Namespace) -> None:
    client = await build_client(args)
    try:
        await client.start()
        if args.repo_file:
            await run_repo_file(client, args)
        else:
            run_id = args.run_id or str(uuid4())
            await run_one_repository(client, args, run_id, args.github_url, args.output)
    finally:
        await client.close()


async def build_client(args: argparse.Namespace) -> RuntimeClient:
    if args.local:
        from dreadnode.app.client.managed_client import ManagedRuntimeClient

        capability_dir = Path(__file__).resolve().parent.parent
        return ManagedRuntimeClient(capability_dirs=[str(capability_dir)])

    runtime_url = args.runtime_url or os.environ.get("DREADNODE_RUNTIME_URL")
    if not runtime_url:
        raise SystemExit(
            "Provide --runtime-url (or DREADNODE_RUNTIME_URL), or pass --local "
            "to boot an in-process runtime."
        )
    runtime_token = args.runtime_token or os.environ.get("DREADNODE_RUNTIME_TOKEN")
    return RuntimeClient(server_url=runtime_url.rstrip("/"), auth_token=runtime_token)


async def run_repo_file(client: RuntimeClient, args: argparse.Namespace) -> None:
    repos = read_repo_file(args.repo_file)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[tuple[str, str]] = []

    for index, repo_url in enumerate(repos, start=1):
        run_id = str(uuid4())
        output_path = str(output_dir / default_report_name(repo_url))
        print(f"\n[{index}/{len(repos)}] {repo_url}")
        try:
            await run_one_repository(client, args, run_id, repo_url, output_path)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            print(f"[{index}/{len(repos)}] FAILED: {message}")
            failures.append((repo_url, message))
            Path(output_path).write_text(
                f"# Analysis failed\n\nrepository: {repo_url}\nrun_id: {run_id}\nerror: {message}\n",
                encoding="utf-8",
            )

    if failures:
        print(f"\nCompleted with {len(failures)} failure(s):")
        for repo_url, message in failures:
            print(f"  - {repo_url}: {message}")


async def run_one_repository(
    client: RuntimeClient,
    args: argparse.Namespace,
    run_id: str,
    github_url: str,
    output_path: str,
) -> None:
    watcher = asyncio.create_task(watch_run(client, run_id, output_path))
    # Give the event subscription a beat to register before publishing.
    await asyncio.sleep(0.3)
    if not args.watch_only:
        payload: dict[str, Any] = {
            "run_id": run_id,
            "github_url": github_url,
            "max_steps": args.max_steps,
        }
        if args.model is not None:
            payload["model"] = args.model
        await client.publish(REQUEST_EVENT, payload)
        print(f"Requested analysis run {run_id}")
    else:
        print(f"Watching analysis run {run_id}")
    await watcher


async def watch_run(client: RuntimeClient, run_id: str, output_path: str) -> None:
    async for event in client.subscribe(*WATCH_KINDS):
        payload = event.payload if isinstance(event.payload, dict) else {}
        if payload.get("run_id") != run_id:
            continue
        kind = event.kind

        if kind == PROGRESS_EVENT:
            stage = payload.get("stage")
            detail = payload.get("detail")
            print(f"Progress: {stage}{f' — {detail}' if detail else ''}")
            continue
        if kind == REPORT_READY_EVENT:
            print(f"Report ready: {payload.get('agent')}")
            continue
        if kind == FAILED_EVENT:
            raise RuntimeError(str(payload.get("error") or "analysis failed"))
        if kind == COMPLETED_EVENT:
            final_report = str(payload.get("final_report") or "")
            Path(output_path).write_text(final_report, encoding="utf-8")
            print(f"Final report written to {output_path}")
            return


def read_repo_file(path: str) -> list[str]:
    repos: list[str] = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        repos.append(line)
    if not repos:
        raise SystemExit(f"No repositories found in {path}")
    return repos


def default_report_name(repo_url: str) -> str:
    repo = repo_url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    safe = "".join(
        char if char.isalnum() or char in "-_" else "-" for char in repo
    ).strip("-")
    return f"{safe or 'repo'}-final-report.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit a source-analysis run and watch progress.",
    )
    parser.add_argument(
        "github_url",
        nargs="?",
        help="Repository URL, e.g. https://github.com/owner/repo",
    )
    parser.add_argument(
        "--repo-file",
        default=None,
        help=(
            "File of GitHub URLs to analyze sequentially, one per line. "
            "Blank lines and # comments are ignored."
        ),
    )
    parser.add_argument(
        "--runtime-url",
        default=None,
        help="Sandbox/runtime URL. Falls back to $DREADNODE_RUNTIME_URL.",
    )
    parser.add_argument(
        "--runtime-token",
        default=None,
        help="Bearer token for the runtime URL. Falls back to $DREADNODE_RUNTIME_TOKEN.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Boot an in-process runtime that loads this capability instead of connecting remotely.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run id. Use with --watch-only to resume watching a run.",
    )
    parser.add_argument(
        "--watch-only",
        action="store_true",
        help="Watch an existing run without submitting a new request.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model id for agents that declare model: inherit (e.g. anthropic/claude-opus-4-5).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=200,
        help="Maximum autonomous steps per agent turn.",
    )
    parser.add_argument(
        "--output",
        default="final-report.md",
        help="Where to write the final report when running a single repo.",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for reports when using --repo-file. Each report is named <repo>-final-report.md.",
    )

    args = parser.parse_args()

    if args.watch_only:
        if args.run_id is None:
            parser.error("--watch-only requires --run-id")
        if args.repo_file is not None:
            parser.error("--watch-only cannot be used with --repo-file")
    elif args.repo_file is not None:
        if args.github_url is not None:
            parser.error("github_url positional cannot be used with --repo-file")
        if args.run_id is not None:
            parser.error("--run-id cannot be used with --repo-file")
    elif args.github_url is None:
        parser.error("github_url is required unless --repo-file is provided")
    return args


def main() -> None:
    asyncio.run(amain(parse_args()))


if __name__ == "__main__":
    main()
