import asyncio
import hashlib
import json
import os
import shutil
import typing as t
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .constants import (
    EVENT_FACT_CERTIFICATE,
    EVENT_FACT_DNS,
    EVENT_FACT_FINDING,
    EVENT_FACT_PORT,
    EVENT_FACT_SERVICE,
    EVENT_FACT_SUBDOMAIN,
    EVENT_FACT_URL,
    EVENT_OPPORTUNITY_INTERESTING_SERVICE,
    EVENT_OPPORTUNITY_INTERESTING_URL,
    EVENT_OPPORTUNITY_VALIDATION_CANDIDATE,
)
from .models import PdEvent, ToolResult

_PDTM_BIN_DIR = Path.home() / ".pdtm" / "go" / "bin"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    binary: str
    default_args: tuple[str, ...]
    target_mode: t.Literal["stdin", "flag", "argv"]
    target_flag: str | None = None


PD_TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        default_args=("-json", "-silent"),
        target_mode="flag",
        target_flag="-d",
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        default_args=("-json", "-silent"),
        target_mode="stdin",
    ),
    "katana": ToolSpec(
        name="katana",
        binary="katana",
        default_args=("-jsonl", "-silent"),
        target_mode="stdin",
    ),
    "dnsx": ToolSpec(
        name="dnsx",
        binary="dnsx",
        default_args=("-json", "-silent"),
        target_mode="stdin",
    ),
    "naabu": ToolSpec(
        name="naabu",
        binary="naabu",
        default_args=("-json", "-silent"),
        target_mode="stdin",
    ),
    "tlsx": ToolSpec(
        name="tlsx",
        binary="tlsx",
        default_args=("-json", "-silent"),
        target_mode="stdin",
    ),
    "alterx": ToolSpec(
        name="alterx",
        binary="alterx",
        default_args=("-silent",),
        target_mode="stdin",
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        binary="nuclei",
        default_args=("-jsonl", "-silent"),
        target_mode="stdin",
    ),
}


def resolve_binary(name: str) -> str:
    """Resolve a ProjectDiscovery binary, preferring the PDTM install path."""
    direct_path = _PDTM_BIN_DIR / name
    if direct_path.is_file() and os.access(direct_path, os.X_OK):
        return str(direct_path)

    which_path = shutil.which(name)
    if which_path:
        return which_path

    return name


def compute_dedupe_key(*, scan_id: str, tool_name: str, targets: list[str], extra_args: list[str]) -> str:
    """Compute a stable dedupe key for a PD execution request."""
    fingerprint = {
        "scan_id": scan_id,
        "tool": tool_name,
        "targets": sorted(targets),
        "extra_args": extra_args,
    }
    digest = hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:24]


async def run_pd_binary(
    *,
    spec: ToolSpec,
    targets: list[str],
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> ToolResult:
    """Execute a ProjectDiscovery binary and capture JSON and raw output."""
    extra_args = extra_args or []
    base_args = list(spec.default_args)
    stdin_data: bytes | None = None

    if spec.target_mode == "stdin":
        stdin_data = ("\n".join(targets) + "\n").encode("utf-8")
    elif spec.target_mode == "flag" and spec.target_flag is not None:
        for target in targets:
            base_args.extend([spec.target_flag, target])
    else:
        base_args.extend(targets)

    command = [resolve_binary(spec.binary), *base_args, *extra_args]

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ToolResult(
            tool=spec.name,
            command=command,
            success=False,
            error=f"Binary not found: {command[0]}",
        )

    if stdin_data and proc.stdin:
        proc.stdin.write(stdin_data)
        await proc.stdin.drain()
        proc.stdin.close()

    raw_output: list[str] = []
    items: list[dict[str, t.Any]] = []
    assert proc.stdout is not None

    start = asyncio.get_running_loop().time()
    async for line in proc.stdout:
        decoded = line.decode("utf-8", errors="replace").strip()
        if not decoded:
            continue
        raw_output.append(decoded)
        try:
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            items.append(parsed)

    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        return ToolResult(
            tool=spec.name,
            command=command,
            success=False,
            raw_output=raw_output,
            error=f"Timeout after {timeout}s",
            elapsed_seconds=round(asyncio.get_running_loop().time() - start, 3),
        )

    stderr = ""
    if proc.stderr is not None:
        stderr = (await proc.stderr.read()).decode("utf-8", errors="replace").strip()

    return ToolResult(
        tool=spec.name,
        command=command,
        success=proc.returncode == 0,
        items=items,
        raw_output=raw_output,
        error=stderr or None,
        return_code=proc.returncode or 0,
        elapsed_seconds=round(asyncio.get_running_loop().time() - start, 3),
    )


def parse_tool_output(
    *,
    tool_name: str,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
    raw_output: list[str],
) -> tuple[list[PdEvent], list[PdEvent]]:
    """Normalize tool output into fact events plus derived opportunities."""
    if tool_name == "subfinder":
        facts = _parse_subfinder(scan_id=scan_id, job_id=job_id, source=source, items=items, raw_output=raw_output)
    elif tool_name == "httpx":
        facts = _parse_httpx(scan_id=scan_id, job_id=job_id, source=source, items=items)
    elif tool_name == "katana":
        facts = _parse_katana(scan_id=scan_id, job_id=job_id, source=source, items=items)
    elif tool_name == "dnsx":
        facts = _parse_dnsx(scan_id=scan_id, job_id=job_id, source=source, items=items)
    elif tool_name == "naabu":
        facts = _parse_naabu(scan_id=scan_id, job_id=job_id, source=source, items=items)
    elif tool_name == "tlsx":
        facts = _parse_tlsx(scan_id=scan_id, job_id=job_id, source=source, items=items)
    elif tool_name == "alterx":
        facts = _parse_alterx(scan_id=scan_id, job_id=job_id, source=source, raw_output=raw_output)
    elif tool_name == "nuclei":
        facts = _parse_nuclei(scan_id=scan_id, job_id=job_id, source=source, items=items)
    else:
        facts = []
    return facts, _derive_opportunities(facts)


def _parse_subfinder(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
    raw_output: list[str],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    seen: set[str] = set()
    for item in items:
        host = str(item.get("host") or item.get("input") or "").strip()
        if host and host not in seen:
            seen.add(host)
            events.append(
                PdEvent(
                    name=EVENT_FACT_SUBDOMAIN,
                    scan_id=scan_id,
                    event_kind="fact.subdomain",
                    target=host,
                    tool="subfinder",
                    job_id=job_id,
                    source=source,
                    search_text=host,
                    payload=item,
                )
            )
    for line in raw_output:
        line = line.strip()
        if not line or line.startswith("{") or line in seen:
            continue
        seen.add(line)
        events.append(
            PdEvent(
                name=EVENT_FACT_SUBDOMAIN,
                scan_id=scan_id,
                event_kind="fact.subdomain",
                target=line,
                tool="subfinder",
                job_id=job_id,
                source=source,
                search_text=line,
                payload={"host": line},
            )
        )
    return events


def _parse_httpx(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        url = str(item.get("url") or item.get("input") or "").strip()
        host = str(item.get("host") or urlparse(url).hostname or item.get("input") or "").strip()
        title = str(item.get("title") or "").strip()
        tech = item.get("tech") or []
        status_code = item.get("status_code")
        port = item.get("port")
        search_bits = [url, host, title]
        if isinstance(tech, list):
            search_bits.extend(str(entry) for entry in tech)
        if host:
            events.append(
                PdEvent(
                    name=EVENT_FACT_SERVICE,
                    scan_id=scan_id,
                    event_kind="fact.service",
                    target=host,
                    tool="httpx",
                    job_id=job_id,
                    source=source,
                    summary=title or None,
                    search_text=" ".join(bit for bit in search_bits if bit),
                    payload=item,
                )
            )
        if url:
            events.append(
                PdEvent(
                    name=EVENT_FACT_URL,
                    scan_id=scan_id,
                    event_kind="fact.url",
                    target=url,
                    tool="httpx",
                    job_id=job_id,
                    source=source,
                    summary=f"status={status_code} port={port}",
                    search_text=" ".join(bit for bit in search_bits if bit),
                    payload=item,
                )
            )
    return events


def _parse_katana(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        request = item.get("request")
        endpoint = ""
        if isinstance(request, dict):
            endpoint = str(request.get("endpoint") or request.get("url") or "").strip()
        if not endpoint:
            endpoint = str(item.get("url") or item.get("endpoint") or "").strip()
        if not endpoint:
            continue
        events.append(
            PdEvent(
                name=EVENT_FACT_URL,
                scan_id=scan_id,
                event_kind="fact.url",
                target=endpoint,
                tool="katana",
                job_id=job_id,
                source=source,
                search_text=f"{endpoint} {item.get('response', '')}",
                payload=item,
            )
        )
    return events


def _parse_dnsx(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        host = str(item.get("host") or item.get("input") or "").strip()
        if not host:
            continue
        events.append(
            PdEvent(
                name=EVENT_FACT_DNS,
                scan_id=scan_id,
                event_kind="fact.dns",
                target=host,
                tool="dnsx",
                job_id=job_id,
                source=source,
                search_text=_search_text(host, item.get("a"), item.get("aaaa"), item.get("cname")),
                payload=item,
            )
        )
    return events


def _parse_naabu(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        host = str(item.get("host") or item.get("ip") or "").strip()
        port = item.get("port")
        if not host or port is None:
            continue
        events.append(
            PdEvent(
                name=EVENT_FACT_PORT,
                scan_id=scan_id,
                event_kind="fact.port",
                target=f"{host}:{port}",
                tool="naabu",
                job_id=job_id,
                source=source,
                search_text=f"{host}:{port}",
                payload=item,
            )
        )
    return events


def _parse_tlsx(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        host = str(item.get("host") or item.get("ip") or item.get("input") or "").strip()
        if not host:
            continue
        common_name = ""
        subject_an = item.get("subject_an")
        if isinstance(subject_an, list) and subject_an:
            common_name = str(subject_an[0])
        search_text = _search_text(host, common_name, item.get("tls_version"), item.get("cipher"))
        events.append(
            PdEvent(
                name=EVENT_FACT_CERTIFICATE,
                scan_id=scan_id,
                event_kind="fact.certificate",
                target=host,
                tool="tlsx",
                job_id=job_id,
                source=source,
                search_text=search_text,
                payload=item,
            )
        )
    return events


def _parse_alterx(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    raw_output: list[str],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    seen: set[str] = set()
    for line in raw_output:
        candidate = line.strip()
        if not candidate or candidate.startswith("{") or candidate in seen:
            continue
        seen.add(candidate)
        events.append(
            PdEvent(
                name=EVENT_FACT_SUBDOMAIN,
                scan_id=scan_id,
                event_kind="fact.subdomain",
                target=candidate,
                tool="alterx",
                job_id=job_id,
                source=source,
                search_text=candidate,
                payload={"host": candidate},
            )
        )
    return events


def _parse_nuclei(
    *,
    scan_id: str,
    job_id: str,
    source: str,
    items: list[dict[str, t.Any]],
) -> list[PdEvent]:
    events: list[PdEvent] = []
    for item in items:
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        matched = str(item.get("matched-at") or item.get("matched") or item.get("host") or "").strip()
        target = matched or str(item.get("template-id") or "").strip()
        if not target:
            continue
        search_text = _search_text(
            target,
            item.get("template-id"),
            info.get("name") if isinstance(info, dict) else None,
            info.get("severity") if isinstance(info, dict) else None,
        )
        events.append(
            PdEvent(
                name=EVENT_FACT_FINDING,
                scan_id=scan_id,
                event_kind="fact.finding",
                target=target,
                tool="nuclei",
                job_id=job_id,
                source=source,
                summary=str(info.get("name") or item.get("template-id") or ""),
                search_text=search_text,
                payload=item,
            )
        )
    return events


def _derive_opportunities(facts: list[PdEvent]) -> list[PdEvent]:
    seen: set[str] = set()
    opportunities: list[PdEvent] = []
    for fact in facts:
        candidate = _fact_to_opportunity(fact)
        if candidate is None:
            continue
        if candidate.opportunity_key in seen:
            continue
        seen.add(str(candidate.opportunity_key))
        opportunities.append(candidate)
    return opportunities


def _fact_to_opportunity(fact: PdEvent) -> PdEvent | None:
    payload = fact.payload
    if fact.name == EVENT_FACT_SERVICE:
        port = int(payload.get("port") or 0)
        tech = payload.get("tech") or []
        title = str(payload.get("title") or "").strip()
        url = str(payload.get("url") or "").strip()
        non_standard_port = port not in {0, 80, 443}
        if not (non_standard_port or tech or title):
            return None
        score = 1.0
        if non_standard_port:
            score += 1.0
        if tech:
            score += 0.5
        if title:
            score += 0.5
        target = url or fact.target or ""
        return _opportunity_event(
            name=EVENT_OPPORTUNITY_INTERESTING_SERVICE,
            kind="interesting_service",
            fact=fact,
            target=target,
            priority="high" if score >= 2.0 else "medium",
            score=score,
            summary=title or f"Interesting service on {fact.target}",
        )

    if fact.name == EVENT_FACT_URL:
        target = fact.target or ""
        parsed = urlparse(target)
        path = parsed.path or "/"
        lowered = target.lower()
        keywords = ("admin", "login", "signin", "graphql", "swagger", "api", "dashboard")
        if path == "/" and not any(keyword in lowered for keyword in keywords):
            return None
        score = 1.0
        if path != "/":
            score += 0.5
        if any(keyword in lowered for keyword in keywords):
            score += 1.0
        return _opportunity_event(
            name=EVENT_OPPORTUNITY_INTERESTING_URL,
            kind="interesting_url",
            fact=fact,
            target=target,
            priority="high" if score >= 2.0 else "medium",
            score=score,
            summary=f"Interesting URL: {target}",
        )

    if fact.name == EVENT_FACT_FINDING:
        severity = _extract_severity(fact.payload)
        if severity == "info":
            return None
        score_map = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
        score = score_map.get(severity, 1.5)
        return _opportunity_event(
            name=EVENT_OPPORTUNITY_VALIDATION_CANDIDATE,
            kind="validation_candidate",
            fact=fact,
            target=fact.target or "",
            priority="high" if score >= 3.0 else "medium",
            score=score,
            summary=f"Nuclei finding requires validation: {fact.summary or fact.target}",
        )

    return None


def _opportunity_event(
    *,
    name: str,
    kind: str,
    fact: PdEvent,
    target: str,
    priority: str,
    score: float,
    summary: str,
) -> PdEvent:
    opportunity_key = hashlib.sha256(
        json.dumps(
            {
                "scan_id": fact.scan_id,
                "kind": kind,
                "target": target,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()[:20]
    return PdEvent(
        name=name,
        scan_id=fact.scan_id,
        event_kind=f"opportunity.{kind}",
        target=target,
        tool=fact.tool,
        job_id=fact.job_id,
        opportunity_key=opportunity_key,
        opportunity_kind=kind,
        priority=priority,
        status="open",
        source=fact.source,
        summary=summary,
        search_text=_search_text(target, summary),
        payload={"score": score, "source_event": fact.name, "source_target": fact.target},
    )


def _extract_severity(payload: dict[str, t.Any]) -> str:
    info = payload.get("info")
    if isinstance(info, dict):
        severity = info.get("severity")
        if isinstance(severity, str) and severity:
            return severity.lower()
    severity = payload.get("severity")
    if isinstance(severity, str) and severity:
        return severity.lower()
    return "info"


def _search_text(*parts: t.Any) -> str:
    flattened: list[str] = []
    for part in parts:
        if isinstance(part, list):
            flattened.extend(str(entry) for entry in part if entry)
        elif part:
            flattened.append(str(part))
    return " ".join(flattened)
