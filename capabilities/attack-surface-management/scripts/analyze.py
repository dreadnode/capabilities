"""Submit an ASM worker-pipeline run and stream progress.

Launcher for the worker-coordinated ASM pipeline. It connects to a runtime,
publishes ``asm.analysis.requested``, watches progress/report events, and writes
the final report when ``asm.analysis.completed`` fires.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from dreadnode.app.client.runtime_client import RuntimeClient

WATCH_TIMEOUT_SECONDS = 14_400

REQUEST_EVENT = "asm.analysis.requested"
PROGRESS_EVENT = "asm.analysis.progress"
REPORT_READY_EVENT = "asm.analysis.report.ready"
COMPLETED_EVENT = "asm.analysis.completed"
FAILED_EVENT = "asm.analysis.failed"

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
        run_id = args.run_id or str(uuid4())
        await run_one(client, args, run_id)
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
            "Provide --runtime-url or DREADNODE_RUNTIME_URL, or pass --local "
            "to boot an in-process runtime."
        )
    runtime_token = args.runtime_token or os.environ.get("DREADNODE_RUNTIME_TOKEN")
    return RuntimeClient(server_url=runtime_url.rstrip("/"), auth_token=runtime_token)


async def run_one(client: RuntimeClient, args: argparse.Namespace, run_id: str) -> None:
    watcher = asyncio.create_task(watch_run(client, run_id, args.output))
    await asyncio.sleep(0.3)

    if not args.watch_only:
        payload: dict[str, Any] = {
            "run_id": run_id,
            "target": args.target,
            "wildcards": args.wildcard,
            "max_steps": args.max_steps,
        }
        if args.scope_json:
            payload["scope"] = json.loads(args.scope_json)
        if args.graph_api_url:
            payload["graph_api_url"] = args.graph_api_url
        if args.model:
            payload["model"] = args.model
        await client.publish(REQUEST_EVENT, payload)
        print(f"Requested ASM analysis run {run_id}")
    else:
        print(f"Watching ASM analysis run {run_id}")

    try:
        await asyncio.wait_for(watcher, timeout=args.timeout)
    except asyncio.TimeoutError as exc:
        raise RuntimeError(
            f"Run {run_id} did not complete within {args.timeout}s"
        ) from exc


async def watch_run(client: RuntimeClient, run_id: str, output_path: str) -> None:
    async for event in client.subscribe(*WATCH_KINDS):
        payload = event.payload if isinstance(event.payload, dict) else {}
        if payload.get("run_id") != run_id:
            continue

        if event.kind == PROGRESS_EVENT:
            stage = payload.get("stage")
            detail = payload.get("detail")
            print(f"Progress: {stage}{f' - {detail}' if detail else ''}")
            continue
        if event.kind == REPORT_READY_EVENT:
            print(f"Report ready: {payload.get('agent')}")
            continue
        if event.kind == FAILED_EVENT:
            raise RuntimeError(str(payload.get("error") or "ASM analysis failed"))
        if event.kind == COMPLETED_EVENT:
            final_report = str(payload.get("final_report") or "")
            Path(output_path).write_text(final_report, encoding="utf-8")
            print(f"Final report written to {output_path}")
            return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit an ASM worker-pipeline run and watch progress.",
    )
    parser.add_argument("target", nargs="?", help="Target name or domain label.")
    parser.add_argument(
        "--wildcard",
        action="append",
        default=[],
        help="Allowed wildcard scope expression. Repeat for multiple wildcards.",
    )
    parser.add_argument(
        "--scope-json",
        default=None,
        help="Optional JSON object with additional scope metadata.",
    )
    parser.add_argument("--graph-api-url", default=None, help="Task graph API URL.")
    parser.add_argument("--runtime-url", default=None, help="Runtime URL.")
    parser.add_argument("--runtime-token", default=None, help="Runtime bearer token.")
    parser.add_argument(
        "--local",
        action="store_true",
        help="Boot an in-process runtime that loads this capability.",
    )
    parser.add_argument("--run-id", default=None, help="Optional run id.")
    parser.add_argument(
        "--watch-only",
        action="store_true",
        help="Watch an existing run without publishing a request.",
    )
    parser.add_argument("--model", default=None, help="Model id for worker agents.")
    parser.add_argument(
        "--max-steps",
        type=int,
        default=240,
        help="Maximum autonomous steps per worker agent turn.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=WATCH_TIMEOUT_SECONDS,
        help="Wall-clock seconds to wait for completion.",
    )
    parser.add_argument(
        "--output",
        default="asm-report.md",
        help="Where to write the final report.",
    )

    args = parser.parse_args()
    if args.watch_only:
        if args.run_id is None:
            parser.error("--watch-only requires --run-id")
    elif not args.target:
        parser.error("target is required unless --watch-only is set")
    return args


def main() -> None:
    asyncio.run(amain(parse_args()))


if __name__ == "__main__":
    main()
