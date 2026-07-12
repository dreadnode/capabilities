"""Agent-facing launcher for the worker-coordinated network operations pipeline."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import typing as t
from uuid import uuid4

from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.app.client.runtime_client import RuntimeClient

REQUEST_EVENT = "netops.engagement.requested"
PROGRESS_EVENT = "netops.engagement.progress"
REPORT_READY_EVENT = "netops.engagement.report.ready"
COMPLETED_EVENT = "netops.engagement.completed"
FAILED_EVENT = "netops.engagement.failed"

WATCH_KINDS: tuple[str, ...] = (
    PROGRESS_EVENT,
    REPORT_READY_EVENT,
    COMPLETED_EVENT,
    FAILED_EVENT,
)

LOCAL_RUNTIME_CANDIDATES: tuple[str, ...] = (
    "http://127.0.0.1:8787",
    "http://localhost:8787",
)


def _truncate(text: str, limit: int) -> str:
    return (
        text
        if len(text) <= limit
        else text[:limit] + f"\n... truncated ({len(text)} chars total) ..."
    )


class NetopsPipelineTools(Toolset):
    """Launch and monitor the multi-agent network operations worker pipeline."""

    default_timeout: int = 600
    """Maximum wall-clock seconds to wait for the worker pipeline."""

    max_output_chars: int = 12_000
    """Maximum characters returned to the calling agent."""

    @tool_method(name="run_netops_pipeline", catch=True)
    async def run_pipeline(
        self,
        target: t.Annotated[
            str,
            "Primary target — network range (e.g. '10.10.10.0/24') or domain name.",
        ],
        domain: t.Annotated[
            str | None,
            "AD domain name (e.g. 'corp.local').",
        ] = None,
        credentials: t.Annotated[
            dict[str, str] | str | None,
            "Initial credentials as {username, password} or {username, hash}, or a descriptive string.",
        ] = None,
        network_ranges: t.Annotated[
            list[str] | str | None,
            "Additional network ranges to scan beyond the primary target.",
        ] = None,
        dc_ips: t.Annotated[
            list[str] | str | None,
            "Known domain controller IP addresses.",
        ] = None,
        exclusions: t.Annotated[
            list[str] | str | None,
            "Out-of-scope accounts, hosts, or networks.",
        ] = None,
        rules_of_engagement: t.Annotated[
            str | None,
            "Additional rules of engagement or constraints.",
        ] = None,
        model: t.Annotated[
            str | None,
            "Optional model id for worker agents.",
        ] = None,
        max_steps: t.Annotated[
            int, "Maximum autonomous steps per pipeline stage (each stage is capped independently)."
        ] = 240,
        timeout: t.Annotated[
            int | None,
            "Maximum wall-clock seconds to wait for the full pipeline.",
        ] = None,
    ) -> str:
        """Run the worker-coordinated network operations pipeline and return its final report.

        This publishes a `netops.engagement.requested` runtime event and waits
        for the coordinator worker to complete the staged pipeline: scope
        normalization, network discovery, AD enumeration, exploitation,
        credential harvesting, and report synthesis.
        """
        runtime_token = os.environ.get("DREADNODE_RUNTIME_TOKEN")
        run_id = str(uuid4())
        requested_timeout = int(timeout or self.default_timeout)
        timeout_seconds = max(60, min(requested_timeout, self.default_timeout))
        progress: list[str] = []

        payload: dict[str, t.Any] = {
            "run_id": run_id,
            "target": target,
            "max_steps": int(max_steps),
        }
        if domain:
            payload["domain"] = domain
        if credentials:
            if isinstance(credentials, str):
                payload["notes"] = credentials
            else:
                payload["credentials"] = credentials
        if network_ranges:
            payload["network_ranges"] = _coerce_string_list(network_ranges)
        if dc_ips:
            payload["dc_ips"] = _coerce_string_list(dc_ips)
        if exclusions:
            payload["exclusions"] = _coerce_string_list(exclusions)
        if rules_of_engagement:
            payload["rules_of_engagement"] = rules_of_engagement
        if model:
            payload["model"] = model

        final_report = await self._run_with_runtime_candidates(
            payload=payload,
            run_id=run_id,
            progress=progress,
            runtime_token=runtime_token,
            timeout_seconds=timeout_seconds,
        )

        result = {
            "run_id": run_id,
            "mode": "worker_coordinated_netops_pipeline",
            "progress": progress,
            "final_report": final_report,
        }
        return _truncate(
            json.dumps(result, indent=2, default=str), self.max_output_chars
        )

    async def _run_with_runtime_candidates(
        self,
        *,
        payload: dict[str, t.Any],
        run_id: str,
        progress: list[str],
        runtime_token: str | None,
        timeout_seconds: int,
    ) -> str:
        """Try runtime candidates in order: direct in-process first, then event-based."""
        explicit_url = os.environ.get("DREADNODE_RUNTIME_URL")
        candidates = (
            [explicit_url] if explicit_url else list(LOCAL_RUNTIME_CANDIDATES)
        )
        errors: list[str] = []

        for runtime_url in candidates:
            if not runtime_url:
                continue
            client = RuntimeClient(
                server_url=runtime_url.rstrip("/"),
                auth_token=runtime_token,
            )
            try:
                _patch_websockets_proxy_compat()
                await asyncio.wait_for(client.start(), timeout=15)
                if not explicit_url:
                    return await asyncio.wait_for(
                        self._run_direct_coordinator_pipeline(
                            client=client,
                            payload=payload,
                            run_id=run_id,
                        ),
                        timeout=timeout_seconds,
                    )
                await asyncio.wait_for(
                    client.publish(REQUEST_EVENT, payload), timeout=15
                )
                try:
                    return await asyncio.wait_for(
                        self._watch_run(client, run_id, progress),
                        timeout=timeout_seconds,
                    )
                except RuntimeError as exc:
                    message = str(exc)
                    if "event stream is unavailable" in message.lower():
                        progress.append(
                            "worker_request_published: runtime transport does "
                            "not expose event streaming to tools"
                        )
                        return (
                            "Network ops pipeline request was published, but "
                            "this tool transport cannot stream worker events. "
                            "Continue with direct tools while pipeline sessions "
                            f"run under run_id {run_id}."
                        )
                    raise
            except Exception as exc:
                errors.append(f"{runtime_url}: {type(exc).__name__}: {exc}")
            finally:
                try:
                    await client.close()
                except Exception:
                    pass

        detail = (
            "; ".join(errors) if errors else "no runtime candidates available"
        )
        raise RuntimeError(
            "Network ops pipeline could not connect to the runtime event bus. "
            f"Tried {candidates}. Errors: {detail}"
        )

    async def _run_direct_coordinator_pipeline(
        self,
        *,
        client: RuntimeClient,
        payload: dict[str, t.Any],
        run_id: str,
    ) -> str:
        coordinator = _load_coordinator_module()
        scope = coordinator._normalize_scope_payload(payload)
        return await coordinator._run_pipeline(
            client,
            run_id=run_id,
            scope=scope,
            model=payload.get("model"),
            max_steps=int(payload.get("max_steps") or 240),
        )

    async def _watch_run(
        self,
        client: RuntimeClient,
        run_id: str,
        progress: list[str],
    ) -> str:
        async for event in client.subscribe(*WATCH_KINDS):
            payload = (
                event.payload if isinstance(event.payload, dict) else {}
            )
            if payload.get("run_id") != run_id:
                continue

            if event.kind == PROGRESS_EVENT:
                stage = str(payload.get("stage") or "unknown")
                detail = str(payload.get("detail") or "")
                progress.append(f"{stage}: {detail}".rstrip(": "))
                continue
            if event.kind == REPORT_READY_EVENT:
                progress.append(f"report_ready: {payload.get('agent')}")
                continue
            if event.kind == FAILED_EVENT:
                raise RuntimeError(
                    str(
                        payload.get("error")
                        or "Network ops pipeline failed"
                    )
                )
            if event.kind == COMPLETED_EVENT:
                return str(payload.get("final_report") or "")
        raise RuntimeError(
            "Runtime event stream ended before pipeline completed"
        )


def _coerce_string_list(value: t.Any) -> list[str]:
    """Normalize *value* to a flat list of non-empty strings.

    Accepts ``None``, a plain list, a JSON-encoded list string, or a
    comma-separated string.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except Exception:
            parsed = None
        if isinstance(parsed, list):
            return [
                str(item).strip() for item in parsed if str(item).strip()
            ]
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return [str(value).strip()]


def _load_coordinator_module() -> t.Any:
    """Import the coordinator worker module with stubbed runtime dependencies.

    The coordinator imports ``dreadnode.capabilities.worker`` and ``loguru``
    which may not be installed in the tool process.  This loader injects
    lightweight stubs so the module can be imported and its pure-Python
    pipeline functions called directly.
    """
    _patch_websockets_proxy_compat()
    path = Path(__file__).resolve().parents[1] / "workers" / "coordinator.py"
    spec = importlib.util.spec_from_file_location(
        "netops_worker_coordinator_direct", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load network-ops coordinator from {path}"
        )

    worker_module = types.ModuleType("dreadnode.capabilities.worker")

    class Worker:
        def __init__(self, name: str):
            self.name = name

        def on_event(self, _event: str):
            def decorator(func: t.Any) -> t.Any:
                return func

            return decorator

        def run(self) -> None:
            return None

    worker_module.EventEnvelope = object  # type: ignore[attr-defined]
    worker_module.RuntimeClient = object  # type: ignore[attr-defined]
    worker_module.Worker = Worker  # type: ignore[attr-defined]
    previous_worker_module = sys.modules.get("dreadnode.capabilities.worker")
    sys.modules["dreadnode.capabilities.worker"] = worker_module

    # Stub loguru so the coordinator can be imported without the package.
    previous_loguru = sys.modules.get("loguru")
    if previous_loguru is None:
        loguru_module = types.ModuleType("loguru")

        class _StubLogger:
            def __getattr__(self, _name: str) -> t.Any:
                return lambda *_a, **_kw: None

        loguru_module.logger = _StubLogger()  # type: ignore[attr-defined]
        sys.modules["loguru"] = loguru_module

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        if previous_worker_module is None:
            sys.modules.pop("dreadnode.capabilities.worker", None)
        else:
            sys.modules["dreadnode.capabilities.worker"] = (
                previous_worker_module
            )
        if previous_loguru is None:
            sys.modules.pop("loguru", None)
        else:
            sys.modules["loguru"] = previous_loguru


def _patch_websockets_proxy_compat() -> None:
    try:
        import websockets.uri as websockets_uri
    except Exception:
        return
    if not hasattr(websockets_uri, "Proxy"):

        class Proxy:
            pass

        websockets_uri.Proxy = Proxy  # type: ignore[attr-defined]
    if not hasattr(websockets_uri, "get_proxy"):

        def get_proxy(_uri: t.Any) -> None:
            return None

        websockets_uri.get_proxy = get_proxy  # type: ignore[attr-defined]
    if not hasattr(websockets_uri, "parse_proxy"):

        def parse_proxy(_proxy: t.Any) -> None:
            return None

        websockets_uri.parse_proxy = parse_proxy  # type: ignore[attr-defined]
