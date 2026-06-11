"""Agent-facing launcher for the worker-coordinated ASM pipeline."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import types
import typing as t
import urllib.error
import urllib.request
from uuid import uuid4

from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.app.client.runtime_client import RuntimeClient

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

LOCAL_RUNTIME_CANDIDATES: tuple[str, ...] = (
    "http://127.0.0.1:8787",
    "http://localhost:8787",
)
DEFAULT_WORKER_MODEL = "openrouter/moonshotai/kimi-k2.6"


def _coerce_string_list(value: t.Any) -> list[str]:
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
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return [str(value).strip()]


def _truncate(text: str, limit: int) -> str:
    return (
        text
        if len(text) <= limit
        else text[:limit] + f"\n... truncated ({len(text)} chars total) ..."
    )


def _resolve_host(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []

    ips: list[str] = []
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        ip = str(sockaddr[0])
        if ip not in ips:
            ips.append(ip)
    return ips


def _probe_http(host: str) -> dict[str, t.Any] | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={"User-Agent": "dreadnode-asm-eval/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "final_url": response.geturl(),
                    "server": response.headers.get("server"),
                    "content_type": response.headers.get("content-type"),
                    "location": response.headers.get("location"),
                }
        except urllib.error.HTTPError as exc:
            return {
                "url": url,
                "status": exc.code,
                "final_url": exc.url,
                "server": exc.headers.get("server") if exc.headers else None,
                "content_type": exc.headers.get("content-type")
                if exc.headers
                else None,
                "location": exc.headers.get("location") if exc.headers else None,
            }
        except Exception:
            continue
    return None


def _lightweight_surface_probe(target: str, wildcards: list[str]) -> str:
    prefixes = (
        "www",
        "api",
        "auth",
        "login",
        "sso",
        "signon",
        "my",
        "portal",
        "app",
        "mobile",
        "ir",
        "careers",
    )
    bases: list[str] = []
    for wildcard in wildcards:
        base = wildcard.strip().lstrip("*.").strip(".")
        if base and base not in bases:
            bases.append(base)

    candidates: list[str] = []
    for base in bases:
        for prefix in prefixes:
            host = f"{prefix}.{base}"
            if host not in candidates:
                candidates.append(host)
            if len(candidates) >= 48:
                break
        if len(candidates) >= 48:
            break

    leads: list[dict[str, t.Any]] = []
    for host in candidates:
        ips = _resolve_host(host)
        if not ips:
            continue
        http = _probe_http(host)
        lead = {
            "host": host,
            "resolved_ips": ips[:4],
        }
        if http:
            lead["http"] = {
                key: value for key, value in http.items() if value is not None
            }
        leads.append(lead)
        if len(leads) >= 12:
            break

    if not leads:
        return ""

    clusters: dict[str, list[str]] = {
        "identity_or_access": [],
        "api_surface": [],
        "public_web": [],
    }
    for lead in leads:
        host = str(lead["host"])
        label = host.split(".", 1)[0]
        if label in {"auth", "login", "sso", "signon", "my", "portal"}:
            clusters["identity_or_access"].append(host)
        if label == "api" or "api" in host:
            clusters["api_surface"].append(host)
        if label in {"www", "app", "mobile", "ir", "careers"}:
            clusters["public_web"].append(host)

    clusters = {key: value for key, value in clusters.items() if value}
    triage = [
        "resolved hosts are concrete leads for follow-up enrichment and graph insertion",
        "HTTP metadata can identify externally reachable services, redirects, and hosting fingerprints",
        "identity, API, and public web clusters are priority candidates for bounded validation",
    ]
    return "\n".join(
        [
            "## Bounded Fallback Probe",
            "",
            (
                "The worker pipeline performed a bounded passive probe because the "
                "graph-backed discovery path returned sparse data."
            ),
            "",
            f"Target: {target}",
            "",
            "Observed leads:",
            "```json",
            json.dumps(leads, indent=2, sort_keys=True),
            "```",
            "",
            "Lead clusters:",
            "```json",
            json.dumps(clusters, indent=2, sort_keys=True),
            "```",
            "",
            "Triage notes:",
            *[f"- {item}" for item in triage],
        ]
    )


class AsmPipelineTools(Toolset):
    """Launch and monitor the multi-agent ASM worker pipeline."""

    default_timeout: int = 480
    """Maximum wall-clock seconds to wait for the worker pipeline."""

    max_output_chars: int = 12_000
    """Maximum characters returned to the calling agent."""

    @tool_method(name="run_asm_worker_pipeline", catch=True)
    async def run_pipeline(
        self,
        target: t.Annotated[str, "Target name or primary domain label."],
        wildcards: t.Annotated[
            list[str] | str,
            "Allowed wildcard scope expressions, e.g. ['*.example.com'].",
        ],
        graph_api_url: t.Annotated[
            str | None,
            "Task Graph API URL to pass to worker agents for graph-capable tools.",
        ] = None,
        scope: t.Annotated[
            dict[str, t.Any] | str | None,
            "Optional additional scope metadata as a JSON object.",
        ] = None,
        model: t.Annotated[
            str | None,
            "Optional direct model id for worker agents, e.g. openrouter/qwen/qwen3.7-max.",
        ] = None,
        max_steps: t.Annotated[
            int, "Maximum autonomous steps per worker agent turn."
        ] = 30,
        timeout: t.Annotated[
            int | None,
            "Maximum wall-clock seconds to wait for the full pipeline.",
        ] = None,
    ) -> str:
        """Run the worker-coordinated ASM pipeline and return its final report.

        This publishes an `asm.analysis.requested` runtime event and waits for the
        coordinator worker to complete the staged pipeline: scope normalization,
        discovery, enrichment, gadget clustering, review, validation fan-out, and
        final synthesis.
        """

        runtime_token = os.environ.get("DREADNODE_RUNTIME_TOKEN")
        run_id = str(uuid4())
        requested_timeout = int(timeout or self.default_timeout)
        timeout_seconds = max(60, min(requested_timeout, self.default_timeout))
        progress: list[str] = []

        payload: dict[str, t.Any] = {
            "run_id": run_id,
            "target": target,
            "wildcards": _coerce_string_list(wildcards),
            "max_steps": int(max_steps),
        }
        if graph_api_url:
            payload["graph_api_url"] = graph_api_url
        payload["model"] = (
            model or os.environ.get("ASM_WORKER_MODEL") or DEFAULT_WORKER_MODEL
        )
        if scope:
            if isinstance(scope, str):
                try:
                    payload["scope"] = json.loads(scope)
                except Exception:
                    payload["notes"] = scope
            else:
                payload["scope"] = scope

        final_report = await self._run_with_runtime_candidates(
            payload=payload,
            run_id=run_id,
            progress=progress,
            runtime_token=runtime_token,
            timeout_seconds=timeout_seconds,
        )
        fallback_report = await asyncio.to_thread(
            _lightweight_surface_probe,
            target,
            payload["wildcards"],
        )

        result = {
            "run_id": run_id,
            "mode": "worker_coordinated_asm_pipeline",
            "progress": progress,
            "fallback_probe": fallback_report,
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
        explicit_url = os.environ.get("DREADNODE_RUNTIME_URL")
        candidates = [explicit_url] if explicit_url else list(LOCAL_RUNTIME_CANDIDATES)
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
                            "worker_request_published: runtime transport does not expose event streaming to tools"
                        )
                        return (
                            "ASM worker pipeline request was published, but this tool "
                            "transport cannot stream worker events. Continue the ASM "
                            "assessment with direct tools while worker-coordinated "
                            f"sessions run under run_id {run_id}."
                        )
                    raise
            except Exception as exc:
                errors.append(f"{runtime_url}: {type(exc).__name__}: {exc}")
            finally:
                try:
                    await client.close()
                except Exception:
                    pass

        detail = "; ".join(errors) if errors else "no runtime candidates available"
        raise RuntimeError(
            "ASM worker pipeline could not connect to the runtime event bus. "
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
            payload = event.payload if isinstance(event.payload, dict) else {}
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
                    str(payload.get("error") or "ASM worker pipeline failed")
                )
            if event.kind == COMPLETED_EVENT:
                return str(payload.get("final_report") or "")
        raise RuntimeError(
            "Runtime event stream ended before ASM worker pipeline completed"
        )


def _load_coordinator_module() -> t.Any:
    _patch_websockets_proxy_compat()
    path = Path(__file__).resolve().parents[1] / "workers" / "coordinator.py"
    spec = importlib.util.spec_from_file_location("asm_worker_coordinator_direct", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load ASM coordinator from {path}")

    worker_module = types.ModuleType("dreadnode.capabilities.worker")

    class Worker:
        def __init__(self, name: str):
            self.name = name

        def on_event(self, _event: str):
            def decorator(func):
                return func

            return decorator

        def run(self):
            return None

    worker_module.EventEnvelope = object
    worker_module.RuntimeClient = object
    worker_module.Worker = Worker
    previous_worker_module = sys.modules.get("dreadnode.capabilities.worker")
    sys.modules["dreadnode.capabilities.worker"] = worker_module

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        if previous_worker_module is None:
            sys.modules.pop("dreadnode.capabilities.worker", None)
        else:
            sys.modules["dreadnode.capabilities.worker"] = previous_worker_module


def _patch_websockets_proxy_compat() -> None:
    try:
        import websockets.uri as websockets_uri
    except Exception:
        return
    if hasattr(websockets_uri, "Proxy"):
        proxy_present = True
    else:
        proxy_present = False

    if not proxy_present:

        class Proxy:  # pragma: no cover - runtime dependency compatibility shim
            pass

        websockets_uri.Proxy = Proxy
    if not hasattr(websockets_uri, "get_proxy"):

        def get_proxy(_uri):  # pragma: no cover - runtime dependency compatibility shim
            return None

        websockets_uri.get_proxy = get_proxy
    if not hasattr(websockets_uri, "parse_proxy"):

        def parse_proxy(
            _proxy,
        ):  # pragma: no cover - runtime dependency compatibility shim
            return None

        websockets_uri.parse_proxy = parse_proxy
