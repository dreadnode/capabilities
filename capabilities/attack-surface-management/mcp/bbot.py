#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "badsecrets~=0.13.47",
#   "baddns~=1.12.294",
#   "fastmcp>=2.0",
#   "neo4j>=5.28.1",
#   "bbot",
#   "aiosqlite>=0.21.0",
#   "extractous~=0.3.0",
#   "pyOpenSSL~=25.3.0",
# ]
# ///
"""BBOT reconnaissance and Neo4j graph query tools exposed as an MCP server.

Provides BBOT scan execution and Neo4j Cypher query tools for attack
surface management. Connects to a running Neo4j instance where BBOT
stores its scan results.

Environment variables:
    NEO4J_URI: Neo4j bolt URI (default: bolt://localhost:7687)
    NEO4J_USER: Neo4j username (default: neo4j)
    NEO4J_PASSWORD: Neo4j password (default: bbotislife)
    BBOT_DATA_DIR: BBOT data directory (default: .bbot)
"""

from __future__ import annotations

import asyncio
import ast
import contextlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
from typing import Annotated
import urllib.error
import urllib.request

from fastmcp import FastMCP
from neo4j import AsyncGraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "bbotislife")
BBOT_DATA_DIR = os.environ.get("BBOT_DATA_DIR", ".bbot")
SCAN_TIMEOUT = 3600
MAX_OUTPUT = 50_000
_CYPHER_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _safe_json(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


def _validate_cypher_identifier(value: str, kind: str) -> str:
    """Validate identifiers interpolated into Cypher label/type/property slots."""
    if not _CYPHER_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"Invalid {kind}: {value!r}")
    return value


def _parse_mapping(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    with contextlib.suppress(Exception):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    with contextlib.suppress(Exception):
        parsed = ast.literal_eval(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _query_graph_api(
    graph_api_url: str, cypher: str, params: dict | None = None
) -> list[dict]:
    """Execute Cypher through a task-local HTTP graph proxy."""
    url = graph_api_url.rstrip("/") + "/query"
    body = json.dumps({"cypher": cypher, "params": params or {}}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Graph API query failed ({exc.code}): {detail}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise RuntimeError(f"Graph API returned unexpected payload: {payload!r}")
    return payload["rows"]


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _summarize_bbot_stdout(output: str, max_chars: int) -> str:
    """Condense BBOT JSON/stdout output into agent-friendly telemetry."""
    type_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    examples: list[dict] = []
    scans: list[dict] = []
    diagnostic_tail: list[str] = []
    event_count = 0

    for raw_line in output.splitlines():
        line = _strip_ansi(raw_line).strip()
        if not line:
            continue

        parsed = None
        if line.startswith("{"):
            with contextlib.suppress(Exception):
                value = json.loads(line)
                if isinstance(value, dict):
                    parsed = value

        if parsed:
            event_count += 1
            event_type = str(parsed.get("type") or "UNKNOWN")
            scope = str(parsed.get("scope_description") or "unknown")
            module = str(parsed.get("module") or parsed.get("source") or "")
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            scope_counts[scope] = scope_counts.get(scope, 0) + 1
            if module:
                module_counts[module] = module_counts.get(module, 0) + 1

            compact = {
                "type": event_type,
                "scope_description": scope,
                "data": parsed.get("data"),
            }
            if module:
                compact["module"] = module
            if event_type == "SCAN":
                scans.append(compact)
            elif len(examples) < 120 and event_type in {
                "DNS_NAME",
                "URL",
                "OPEN_TCP_PORT",
                "TECHNOLOGY",
                "FINDING",
                "IP_ADDRESS",
                "WEBSCREENSHOT",
                "STORAGE_BUCKET",
                "SOCIAL",
                "MOBILE_APP",
            }:
                examples.append(compact)
            continue

        diagnostic_tail.append(line[:300])
        diagnostic_tail = diagnostic_tail[-40:]

    summary = {
        "mode": "bbot_stdout_json_summary",
        "raw_output_chars": len(output),
        "event_count": event_count,
        "type_counts": dict(
            sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "scope_counts": dict(
            sorted(scope_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "module_counts": dict(
            sorted(module_counts.items(), key=lambda item: (-item[1], item[0]))[:40]
        ),
        "representative_events": examples,
        "scan_records": scans[-5:],
        "diagnostic_tail": diagnostic_tail,
    }
    text = (
        "BBOT completed with JSON/stdout evidence. The raw event stream was "
        "summarized to keep the agent context small; use the counts and "
        "representative_events below for ASM statistics and leads.\n\n"
        + json.dumps(summary, indent=2, default=str)
    )
    if len(text) > max_chars:
        text = (
            text[:max_chars] + f"\n\n... [SUMMARY TRUNCATED: {len(text)} chars total]"
        )
    return text


def _count_bbot_json_events(output: str) -> int:
    """Count JSON event lines in BBOT stdout."""
    event_count = 0
    for raw_line in output.splitlines():
        line = _strip_ansi(raw_line).strip()
        if not line.startswith("{"):
            continue
        with contextlib.suppress(Exception):
            value = json.loads(line)
            if isinstance(value, dict):
                event_count += 1
    return event_count


def _bbot_output_has_blocking_diagnostic(output: str) -> bool:
    """Detect BBOT diagnostics that mean no useful scan ran."""
    blocking_markers = (
        "Setup hard-failed",
        "[ERRR]",
        "[ERROR]",
        "Please specify --allow-deadly to continue",
        "No modules to scan",
    )
    return any(marker in output for marker in blocking_markers)


def _has_dependency_control_arg(args: list[str]) -> bool:
    dependency_args = {
        "--no-deps",
        "--force-deps",
        "--retry-deps",
        "--ignore-failed-deps",
        "--install-all-deps",
    }
    return any(arg in dependency_args for arg in args)


def _has_module_exclusion_arg(args: list[str]) -> bool:
    return any(arg in {"--exclude-modules", "-em"} for arg in args)


def _requests_baddns(modules: list[str] | None) -> bool:
    return bool(modules) and any(module.startswith("baddns") for module in modules)


def _allows_deadly(args: list[str]) -> bool:
    return "--allow-deadly" in args


def _normalize_modules(modules: list[str] | None, extra_args: list[str]) -> list[str]:
    """Drop common non-BBOT/deadly module guesses that would abort a scan."""
    if not modules:
        return []
    replacements = {
        "aws_s3_scan": "bucket_amazon",
        "azure_blob_scan": "bucket_microsoft",
        "azure_blobs": "bucket_microsoft",
        "gcp_storage": "bucket_google",
        "gcp_storage_buckets": "bucket_google",
        "gcp_storage_scan": "bucket_google",
        "s3_buckets": "bucket_amazon",
        "s3_scan": "bucket_amazon",
        "subenum": "subdomaincenter",
        "subdomain_enum": "subdomaincenter",
        "subdomain-enum": "subdomaincenter",
        "subdomainenum": "subdomaincenter",
        "technologies": "httpx",
    }
    unsupported = {
        "amass",
        "assetfinder",
        "crtsh",
        "dns_zone_transfer",
        "fastdial",
        "find_subdomains",
        "findomain",
        "gau",
        "massdns",
        "naabu",
        "portscan",
        "screenshot",
        "shuffledns",
        "subdomain-finder",
        "subdomain_find",
        "subdomain_bruteforce",
        "subdomain-bruteforce",
        "subdomainfinder",
        "subfinder",
        "sublist3r",
        "web_enum",
        "web-enum",
        "web_screenshot",
        "web-screenshot",
        "web_screenshots",
        "web-screenshots",
        "webenum",
        "wappalyzer",
    }
    normalized: list[str] = []
    for module in modules:
        module = replacements.get(module, module)
        if module in unsupported:
            continue
        if module == "nuclei" and not _allows_deadly(extra_args):
            continue
        normalized.append(module)
    return normalized


def _normalize_presets(presets: list[str] | None, extra_args: list[str]) -> list[str]:
    """Avoid BBOT deadly preset aborts unless explicitly requested."""
    if not presets:
        return []
    replacements = {
        "asset-discovery-and-enrichment": "subdomain-enum",
        "asset-discovery": "subdomain-enum",
        "asset_discovery": "subdomain-enum",
        "asset-discovery-web-endpoints": "web-basic",
        "asset_discovery_web_endpoints": "web-basic",
        "asset_discovery_and_enrichment": "subdomain-enum",
        "discovery": "subdomain-enum",
        "subdomain_discovery": "subdomain-enum",
        "subdomain-discovery": "subdomain-enum",
        "subdomain_enumeration": "subdomain-enum",
        "subdomain-enumeration": "subdomain-enum",
        "web_breach": "web-basic",
        "web_basic": "web-basic",
        "web_discovery": "web-basic",
        "web_scan": "web-basic",
        "web-port-scan-and-tech-detect": "web-basic",
        "web_port_scan_and_tech_detect": "web-basic",
    }
    supported = {
        "subdomain-enum",
        "web-basic",
        "web-thorough",
        "cloud-enum",
        "code-enum",
        "email-enum",
        "spider",
        "nuclei",
        "nuclei-intense",
        "dirbust-light",
        "dirbust-heavy",
        "lightfuzz-light",
        "lightfuzz-medium",
        "tech-detect",
        "kitchen-sink",
    }
    presets = [replacements.get(preset, preset) for preset in presets]
    presets = [preset for preset in presets if preset in supported]
    if _allows_deadly(extra_args):
        return presets
    return [preset for preset in presets if not preset.startswith("nuclei")]


def _normalize_flags(flags: list[str] | None) -> list[str]:
    """Drop CLI switches and stale flag names emitted as BBOT flags."""
    if not flags:
        return []
    supported = {
        "active",
        "passive",
        "safe",
        "aggressive",
        "subdomain-enum",
        "web-basic",
        "web-thorough",
        "cloud-enum",
        "code-enum",
        "email-enum",
    }
    return [flag for flag in flags if flag in supported]


def _sandbox_suppression_note(
    requested_modules: list[str] | None, graph_api_url: str | None
) -> str:
    if not graph_api_url or not requested_modules:
        return ""
    suppressed = sorted(
        {module for module in requested_modules if module in {"gowitness", "portscan"}}
    )
    if not suppressed:
        return ""
    return (
        "Sandbox note: "
        + ", ".join(suppressed)
        + " requested but suppressed in Graph API mode for runtime reliability; "
        "use returned DNS/URL/FINDING evidence, `httpx`, and safe web presets for bounded validation.\n\n"
    )


def _bbot_subprocess_env(graph_api_url: str | None) -> dict[str, str]:
    env = os.environ.copy()
    if graph_api_url:
        bbot_home = Path(tempfile.mkdtemp(prefix="asm-bbot-home-"))
        env["HOME"] = str(bbot_home)
        env["BBOT_HOME"] = str(bbot_home / ".bbot")
    return env


def _normalize_config(config: list[str]) -> list[str]:
    """Accept common stale BBOT config names emitted by older prompts/skills."""
    replacements = {
        "modules.httpx.timeout": "modules.http.timeout",
        "scope.distance": "scope.search_distance",
    }
    dropped = {
        "scope.report_distance",
    }
    normalized: list[str] = []
    for item in config:
        key, sep, value = item.partition("=")
        if key in dropped:
            continue
        if (
            key.startswith("modules.")
            and key.endswith(".enabled")
            and value.lower() == "false"
        ):
            continue
        normalized.append(f"{replacements.get(key, key)}{sep}{value}")
    return normalized


def _normalize_extra_args(args: list[str]) -> list[str]:
    """Drop stale BBOT CLI flags emitted by models."""
    normalized: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--scope-distance":
            skip_next = True
            continue
        if arg.startswith("--scope-distance="):
            continue
        normalized.append(arg)
    return normalized


def _normalize_targets(targets: list[str]) -> list[str]:
    """Convert wildcard scope expressions into BBOT seed targets."""
    normalized: list[str] = []
    for target in targets:
        stripped = target.strip()
        if stripped.startswith("*.") and len(stripped) > 2:
            stripped = stripped[2:]
        if stripped:
            normalized.append(stripped)
    return normalized


def _coerce_int_limit(limit: int, *, maximum: int = 1000) -> int:
    if limit < 1 or limit > maximum:
        raise ValueError(f"Limit must be between 1 and {maximum}.")
    return limit


class _Neo4jClient:
    """Lazy async Neo4j driver wrapper."""

    def __init__(self) -> None:
        self._driver = None

    async def get(self):
        if self._driver is None:
            self._driver = AsyncGraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
            )
            await self._driver.verify_connectivity()
        return self._driver

    async def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        driver = await self.get()
        async with driver.session() as session:
            result = await session.run(cypher, params or {})
            return [record.data() async for record in result]


_neo4j = _Neo4jClient()

mcp = FastMCP("bbot")


@mcp.tool()
async def bbot_health() -> str:
    """Check BBOT and Neo4j connectivity."""
    errors = []

    # Check bbot
    try:
        proc = await asyncio.create_subprocess_exec(
            "bbot",
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        bbot_version = stdout.decode().strip() if proc.returncode == 0 else "not found"
    except FileNotFoundError:
        bbot_version = "not installed"
        errors.append("bbot CLI not found in PATH")

    # Check Neo4j
    try:
        await _neo4j.get()
        neo4j_status = f"connected ({NEO4J_URI})"
    except Exception as e:
        neo4j_status = f"error: {e}"
        errors.append(f"Neo4j connection failed: {e}")

    status = "healthy" if not errors else "degraded"
    return f"Status: {status}\n" f"  BBOT: {bbot_version}\n" f"  Neo4j: {neo4j_status}"


@mcp.tool()
async def run_bbot_scan(
    targets: Annotated[list[str], "Targets to scan (domains, IPs, CIDRs)"],
    modules: Annotated[list[str] | None, "Specific modules to run"] = None,
    presets: Annotated[
        list[str] | None, "Presets (subdomain-enum, web-basic, nuclei, etc.)"
    ] = None,
    flags: Annotated[
        list[str] | None, "Module group flags (passive, safe, active, etc.)"
    ] = None,
    config: Annotated[list[str] | None, "Config options in key=value format"] = None,
    extra_args: Annotated[list[str] | None, "Additional bbot CLI flags"] = None,
    graph_api_url: Annotated[
        str | None,
        "Task-local Graph API URL. When supplied, run BBOT in stdout JSON mode so sandboxed evaluations do not require raw Bolt access.",
    ] = None,
) -> str:
    """Execute a BBOT reconnaissance scan.

    When graph_api_url is provided, results are returned as summarized stdout
    JSON instead of forcing BBOT's Neo4j output module against localhost.
    """
    if not targets:
        return "Error: at least one target is required."

    targets = _normalize_targets(targets)
    extra = _normalize_extra_args(list(extra_args or []))
    requested_modules = list(modules or [])
    modules = _normalize_modules(modules, extra)
    presets = _normalize_presets(presets, extra)
    flags = _normalize_flags(flags)
    cfg = _normalize_config(list(config or []))
    if graph_api_url:
        parts = ["bbot", "--yes", "--json", "--brief", "--output-modules", "stdout"]
    else:
        cfg.extend(
            [
                f"modules.neo4j.uri={NEO4J_URI}",
                f"modules.neo4j.username={NEO4J_USER}",
                f"modules.neo4j.password={NEO4J_PASSWORD}",
            ]
        )
        parts = ["bbot", "--yes", "--output-modules", "neo4j", "--brief"]
    parts.extend(["--targets", *targets])
    if modules:
        parts.extend(["--modules", *modules])
    if flags:
        parts.extend(["--flags", *flags])
    if presets:
        parts.extend(["--preset", *presets])
    parts.extend(["--config", *cfg])
    if extra:
        parts.extend(extra)
    if graph_api_url and not _has_dependency_control_arg(extra):
        parts.append("--no-deps")
    if graph_api_url and not _has_module_exclusion_arg(extra):
        excluded = ["portscan", "gowitness"]
        if not _requests_baddns(modules):
            excluded.extend(["baddns", "baddns_direct", "baddns_zone"])
        parts.extend(["--exclude-modules", *excluded])

    cmd = " ".join(parts)

    try:
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(cmd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=_bbot_subprocess_env(graph_api_url),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
        output = stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        return f"Scan timed out after {SCAN_TIMEOUT}s"
    except FileNotFoundError:
        return "Error: bbot not found. Install with: pip install bbot"

    if graph_api_url:
        note = _sandbox_suppression_note(requested_modules, graph_api_url)
        event_count = _count_bbot_json_events(output)
        summarized = _summarize_bbot_stdout(output, MAX_OUTPUT)
        if (
            proc.returncode != 0
            or event_count == 0
            or _bbot_output_has_blocking_diagnostic(output)
        ):
            status = (
                f"exited with code {proc.returncode}"
                if proc.returncode
                else "produced no usable BBOT JSON events"
            )
            return f"Scan {status}.\n\n{note}{summarized}"
        output = note + summarized
    elif len(output) > MAX_OUTPUT:
        output = output[:MAX_OUTPUT] + "\n\n... [TRUNCATED]"

    status = (
        "completed" if proc.returncode == 0 else f"exited with code {proc.returncode}"
    )
    return f"Scan {status}.\n\n{output}"


@mcp.tool()
async def query_graph(
    cypher: Annotated[str, "Cypher query to execute"],
    params: Annotated[dict | None, "Query parameters (use $param in query)"] = None,
    graph_api_url: Annotated[
        str | None,
        "Task-local Graph API URL for querying Neo4j over HTTP when raw Bolt is unavailable.",
    ] = None,
) -> str:
    """Execute a Cypher query against the Neo4j graph database."""
    if graph_api_url:
        result = await asyncio.to_thread(
            _query_graph_api, graph_api_url, cypher, params
        )
    else:
        result = await _neo4j.query(cypher, params)
    return _safe_json(result)


@mcp.tool()
async def get_findings(
    severity: Annotated[
        str | None, "Filter by severity (critical, high, medium, low)"
    ] = None,
) -> str:
    """Retrieve security findings from BBOT scans."""
    if severity:
        result = await _neo4j.query(
            "MATCH (f:FINDING) WHERE f.severity = $sev RETURN f", {"sev": severity}
        )
    else:
        result = await _neo4j.query("MATCH (f:FINDING) RETURN f")
    return _safe_json(result)


@mcp.tool()
async def get_db_schema() -> str:
    """Retrieve Neo4j labels, relationship types, and property metadata."""
    queries = {
        "node_labels": "CALL db.labels() YIELD label RETURN label",
        "relationship_types": "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType",
        "node_properties": "CALL db.schema.nodeTypeProperties()",
        "relationship_properties": "CALL db.schema.relTypeProperties()",
    }
    labels, rel_types, node_props, rel_props = await asyncio.gather(
        *(_neo4j.query(query) for query in queries.values())
    )

    schema: dict[str, object] = {
        "node_labels": sorted(
            record["label"] for record in labels if record.get("label")
        ),
        "relationship_types": sorted(
            record["relationshipType"]
            for record in rel_types
            if record.get("relationshipType")
        ),
        "node_properties": {},
        "relationship_properties": {},
    }

    node_properties: dict[str, list[dict[str, object]]] = {}
    for record in node_props:
        label = str(record.get("nodeType", "")).lstrip(":")
        if not label:
            continue
        node_properties.setdefault(label, []).append(
            {
                "property": record.get("propertyName"),
                "types": record.get("propertyTypes"),
                "mandatory": record.get("mandatory"),
            }
        )

    relationship_properties: dict[str, list[dict[str, object]]] = {}
    for record in rel_props:
        rel_type = str(record.get("relType", "")).lstrip(":")
        if not rel_type:
            continue
        relationship_properties.setdefault(rel_type, []).append(
            {
                "property": record.get("propertyName"),
                "types": record.get("propertyTypes"),
                "mandatory": record.get("mandatory"),
            }
        )

    schema["node_properties"] = node_properties
    schema["relationship_properties"] = relationship_properties
    return _safe_json(schema)


@mcp.tool()
async def get_asset_summary() -> str:
    """Get a summary count of all asset types in the database."""
    result = await _neo4j.query(
        "MATCH (n) RETURN labels(n)[0] as type, count(n) AS count ORDER BY count DESC"
    )
    return _safe_json(result)


@mcp.tool()
async def get_subdomains(
    domain: Annotated[str, "Parent domain to search for subdomains"],
    limit: Annotated[int, "Maximum results"] = 100,
) -> str:
    """List discovered subdomains for a domain."""
    result = await _neo4j.query(
        """
        MATCH (n:DNS_NAME)
        WITH coalesce(n.name, n.data, n.host) AS name
        WHERE name ENDS WITH $domain
        RETURN name
        ORDER BY name
        LIMIT $limit
        """,
        {"domain": domain, "limit": limit},
    )
    return _safe_json(result)


@mcp.tool()
async def get_technologies() -> str:
    """List all discovered technologies and their usage counts."""
    result = await _neo4j.query(
        """
        MATCH (t:TECHNOLOGY)
        RETURN DISTINCT coalesce(t.name, t.data) AS name, t.version AS version, count(*) AS usage
        ORDER BY usage DESC
        """
    )
    return _safe_json(result)


@mcp.tool()
async def explore_nodes(
    label: Annotated[
        str | None, "Node label to browse, for example DNS_NAME, URL, FINDING"
    ] = None,
    property_filter: Annotated[
        str | None,
        "Optional filter: 'property=value' for exact match or 'property CONTAINS value' for substring",
    ] = None,
    limit: Annotated[int, "Maximum nodes to return (1-1000)"] = 100,
) -> str:
    """Browse graph nodes by label and optional property filter."""
    limit = _coerce_int_limit(limit)
    query_parts = [
        f"MATCH (node:{_validate_cypher_identifier(label, 'label')})"
        if label
        else "MATCH (node)"
    ]
    params: dict[str, object] = {"limit": limit}

    if property_filter:
        if " CONTAINS " in property_filter:
            prop, value = property_filter.split(" CONTAINS ", 1)
            prop = _validate_cypher_identifier(prop.strip(), "property")
            query_parts.append(f"WHERE toString(node.`{prop}`) CONTAINS $value")
            params["value"] = value.strip()
        elif "=" in property_filter:
            prop, value = property_filter.split("=", 1)
            prop = _validate_cypher_identifier(prop.strip(), "property")
            query_parts.append(f"WHERE node.`{prop}` = $value")
            params["value"] = value.strip()
        else:
            raise ValueError("property_filter must use '=' or ' CONTAINS '.")

    query_parts.append("RETURN node LIMIT $limit")
    result = await _neo4j.query(" ".join(query_parts), params)
    return _safe_json(result)


@mcp.tool()
async def explore_relationships(
    source_label: Annotated[str | None, "Optional source node label"] = None,
    relationship_type: Annotated[str | None, "Optional relationship type"] = None,
    target_label: Annotated[str | None, "Optional target node label"] = None,
    limit: Annotated[int, "Maximum relationships to return (1-1000)"] = 100,
) -> str:
    """Browse graph relationships with optional source/type/target filters."""
    limit = _coerce_int_limit(limit)
    source = (
        f"(source:{_validate_cypher_identifier(source_label, 'source label')})"
        if source_label
        else "(source)"
    )
    target = (
        f"(target:{_validate_cypher_identifier(target_label, 'target label')})"
        if target_label
        else "(target)"
    )
    if relationship_type:
        rel = f"-[relationship:{_validate_cypher_identifier(relationship_type, 'relationship type')}]->"
    else:
        rel = "-[relationship]->"

    result = await _neo4j.query(
        f"MATCH {source}{rel}{target} RETURN source, relationship, target LIMIT $limit",
        {"limit": limit},
    )
    return _safe_json(result)


@mcp.tool()
async def get_screenshot(
    uuid: Annotated[str | None, "WEBSCREENSHOT uuid or id"] = None,
    url: Annotated[str | None, "Substring of the original screenshot URL"] = None,
) -> str:
    """Resolve a WEBSCREENSHOT node to a local screenshot file path."""
    if not uuid and not url:
        raise ValueError("Either uuid or url must be provided.")

    if uuid:
        result = await _neo4j.query(
            """
            MATCH (w:WEBSCREENSHOT)
            WHERE w.uuid = $uuid OR w.id = $uuid
            OPTIONAL MATCH (s:SCAN {id: w.scan})
            RETURN properties(w) AS web_props, properties(s) AS scan_props
            LIMIT 1
            """,
            {"uuid": uuid},
        )
    else:
        result = await _neo4j.query(
            """
            MATCH (w:WEBSCREENSHOT)
            WHERE toString(w.url) CONTAINS $url OR toString(w.data) CONTAINS $url
            OPTIONAL MATCH (s:SCAN {id: w.scan})
            RETURN properties(w) AS web_props, properties(s) AS scan_props
            LIMIT 1
            """,
            {"url": url},
        )

    if not result:
        needle = f"UUID {uuid!r}" if uuid else f"URL {url!r}"
        return f"No screenshot found for {needle}."

    web_props = result[0].get("web_props") or {}
    scan_props = result[0].get("scan_props") or {}
    web_data = _parse_mapping(web_props.get("data"))
    scan_data = _parse_mapping(scan_props.get("data"))

    screenshot_uuid = web_props.get("uuid") or web_props.get("id") or uuid
    original_url = (
        web_props.get("url") or web_data.get("url") or web_props.get("host") or url
    )
    relative_path = web_props.get("path") or web_data.get("path")
    scan_name = scan_props.get("name") or scan_data.get("name") or web_props.get("scan")

    if not relative_path:
        return _safe_json(
            {
                "error": "Screenshot data is missing a path.",
                "uuid": screenshot_uuid,
                "url": original_url,
            }
        )

    path = Path(str(relative_path)).expanduser()
    candidates = [path] if path.is_absolute() else []
    bbot_home = Path(BBOT_DATA_DIR).expanduser().resolve()
    if not path.is_absolute() and scan_name:
        candidates.append(bbot_home / "scans" / str(scan_name) / path)
    if not path.is_absolute():
        candidates.append(bbot_home / path)

    for candidate in candidates:
        if candidate.exists():
            return _safe_json(
                {
                    "path": str(candidate),
                    "url": original_url,
                    "uuid": screenshot_uuid,
                }
            )

    return _safe_json(
        {
            "error": "Screenshot file not found.",
            "checked_paths": [str(candidate) for candidate in candidates],
            "url": original_url,
            "uuid": screenshot_uuid,
        }
    )
