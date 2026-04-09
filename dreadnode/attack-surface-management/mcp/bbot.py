#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "neo4j>=5.28.1",
#   "bbot",
# ]
# ///
"""BBOT reconnaissance and Neo4j graph query tools exposed as an MCP server.

Provides BBOT scan execution and Neo4j Cypher query tools for attack
surface management. Connects to a running Neo4j instance where BBOT
stores its scan results.

Environment variables:
    NEO4J_URI: Neo4j bolt URI (default: bolt://localhost:7687)
    NEO4J_USER: Neo4j username (default: neo4j)
    NEO4J_PASSWORD: Neo4j password (REQUIRED — no default, fails closed)
    NEO4J_QUERY_TIMEOUT: Per-query timeout in seconds (default: 60)
    BBOT_DATA_DIR: BBOT data directory (default: .bbot)
    BBOT_SCAN_TIMEOUT: Subprocess timeout in seconds (default: 3600)
"""

from __future__ import annotations

import ast
import asyncio
import atexit
import contextlib
import functools
import json
import os
import re
import signal
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from neo4j import AsyncGraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
# No default — refuses to bake BBOT's documented "bbotislife" default into
# source. Server fails closed at first connection if unset.
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD")
BBOT_DATA_DIR = os.environ.get("BBOT_DATA_DIR", ".bbot")
# `or N` handles both unset and empty-string (the harness passes empty when
# the deployer hasn't exported the var).
SCAN_TIMEOUT = int(os.environ.get("BBOT_SCAN_TIMEOUT") or 3600)
QUERY_TIMEOUT = int(os.environ.get("NEO4J_QUERY_TIMEOUT") or 60)
MAX_OUTPUT = 50_000

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _safe_ident(value: str, kind: str) -> str:
    """Validate that a string is a safe Cypher identifier (label, rel type, property name).

    Cypher does not support parameterized labels, relationship types, or property
    names, so any caller-supplied identifier must be allowlisted before being
    interpolated into a query.
    """
    if not isinstance(value, str) or not _IDENT_RE.fullmatch(value):
        raise ValueError(
            f"Invalid {kind}: {value!r}. Must match [A-Za-z_][A-Za-z0-9_]*."
        )
    return value


def _catch_errors(func):
    """Decorator: catch exceptions and return a friendly error string.

    MCP tools that propagate raw Neo4j exceptions surface as JSON-RPC errors
    with a stack trace, which is noisy and hard for the agent to act on. Wrap
    them so the agent gets a short, structured message it can reason about.
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except ValueError as e:
            return f"Error: invalid argument: {e}"
        except asyncio.TimeoutError:
            return (
                f"Error: query exceeded NEO4J_QUERY_TIMEOUT ({QUERY_TIMEOUT}s). "
                f"Narrow the query (add LIMIT, tighter WHERE) or raise the timeout."
            )
        except ServiceUnavailable as e:
            return f"Error: Neo4j unavailable at {NEO4J_URI}: {e}"
        except Neo4jError as e:
            # e.code is e.g. 'Neo.ClientError.Statement.SyntaxError'
            return (
                f"Error: Neo4j {getattr(e, 'code', 'error')}: "
                f"{getattr(e, 'message', str(e))}"
            )
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"

    return wrapper


def _parse_serialized_dict(data: Any) -> Any:
    """Parse string representations of JSON or Python literals into dicts."""
    if not isinstance(data, str):
        return data
    with contextlib.suppress(Exception):
        result = json.loads(data)
        return result if isinstance(result, dict) else {}
    with contextlib.suppress(Exception):
        result = ast.literal_eval(data)
        return result if isinstance(result, dict) else {}
    return data


def _summarize(data: dict[str, Any]) -> dict[str, Any]:
    """Condense a node record to essential fields, truncating long values."""
    summary: dict[str, Any] = {}
    essential = [
        "id", "type", "data", "host", "netloc", "port",
        "tags", "scope_description", "scope_distance",
    ]
    for field in essential:
        if field in data and data[field] is not None:
            value = data[field]
            if isinstance(value, list) and len(value) > 5:
                summary[field] = value[:5]
                summary[f"{field}_truncated"] = True
            elif isinstance(value, str) and len(value) > 200:
                summary[field] = value[:200] + "..."
            else:
                summary[field] = value
    if "id" in summary and isinstance(summary["id"], str) and len(summary["id"]) > 40:
        summary["id"] = summary["id"][:40] + "..."
    return summary


class _Neo4jClient:
    """Lazy async Neo4j driver wrapper."""

    def __init__(self) -> None:
        self._driver = None

    async def get(self):
        if self._driver is None:
            if not NEO4J_PASSWORD:
                raise RuntimeError(
                    "NEO4J_PASSWORD is not set. Configure it via the env block in "
                    "capability.yaml or export it before launching the server."
                )
            self._driver = AsyncGraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
            )
            await self._driver.verify_connectivity()
        return self._driver

    async def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        driver = await self.get()

        async def _run() -> list[dict]:
            async with driver.session() as session:
                # Cypher is dynamic by design here: `query_graph` exposes an
                # arbitrary-Cypher tool, and the helper methods build queries
                # via validated identifiers (`_safe_ident`) and `$param` value
                # binding. The neo4j-python `LiteralString` requirement is a
                # heuristic against unparameterized injection that we have
                # already mitigated; the runtime accepts plain `str` fine.
                result = await session.run(cypher, params or {})  # pyright: ignore[reportArgumentType]
                return [record.data() async for record in result]

        # asyncio.wait_for cancels the inner coroutine on timeout, which
        # closes the session and lets the driver release the connection.
        return await asyncio.wait_for(_run(), timeout=QUERY_TIMEOUT)

    async def get_nodes(
        self,
        label: str,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch nodes by label with optional property filtering.

        List-valued filters use containment semantics (all of $value must be in
        n.<key>) rather than list equality, since Neo4j list `=` requires exact
        ordered match — a footgun for tag-style fields.
        """
        where_clauses = ["$label IN labels(n)"]
        params: dict[str, Any] = {"label": label}

        if filters:
            for key, value in filters.items():
                # key comes from internal callers only, but validate anyway
                # so a future caller can't smuggle Cypher through it.
                _safe_ident(key, "filter key")
                if isinstance(value, list):
                    where_clauses.append(
                        f"all(_v IN ${key} WHERE _v IN n.`{key}`)"
                    )
                else:
                    where_clauses.append(f"n.`{key}` = ${key}")
                params[key] = value

        cypher = (
            "MATCH (n) "
            f"WHERE {' AND '.join(where_clauses)} "
            "RETURN n "
            f"LIMIT {int(limit)}"
        )
        result = await self.query(cypher, params)
        return [record["n"] for record in result]


_neo4j = _Neo4jClient()


def _shutdown_neo4j() -> None:
    """Best-effort close of the Neo4j driver on interpreter shutdown."""
    driver = _neo4j._driver
    if driver is None:
        return
    with contextlib.suppress(Exception):
        asyncio.run(driver.close())


atexit.register(_shutdown_neo4j)

mcp = FastMCP("bbot")


@mcp.tool()
async def bbot_health() -> str:
    """Check BBOT and Neo4j connectivity."""
    errors = []

    # Check bbot
    try:
        proc = await asyncio.create_subprocess_exec(
            "bbot", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        bbot_version = stdout.decode().strip() if proc.returncode == 0 else "not found"
    except FileNotFoundError:
        bbot_version = "not installed"
        errors.append("bbot CLI not found in PATH")

    # Check Neo4j
    if not NEO4J_PASSWORD:
        neo4j_status = "NEO4J_PASSWORD not set"
        errors.append("NEO4J_PASSWORD environment variable is required")
    else:
        try:
            await _neo4j.get()
            neo4j_status = f"connected ({NEO4J_URI})"
        except Exception as e:
            neo4j_status = f"error: {e}"
            errors.append(f"Neo4j connection failed: {e}")

    status = "healthy" if not errors else "degraded"
    return (
        f"Status: {status}\n"
        f"  BBOT: {bbot_version}\n"
        f"  Neo4j: {neo4j_status}"
    )


@mcp.tool()
@_catch_errors
async def run_bbot_scan(
    targets: Annotated[list[str], "Targets to scan (domains, IPs, CIDRs)"],
    modules: Annotated[list[str] | None, "Specific modules to run"] = None,
    presets: Annotated[list[str] | None, "Presets (subdomain-enum, web-basic, nuclei, etc.)"] = None,
    flags: Annotated[list[str] | None, "Module group flags (passive, safe, active, etc.)"] = None,
    config: Annotated[list[str] | None, "Config options in key=value format"] = None,
    extra_args: Annotated[list[str] | None, "Additional bbot CLI flags"] = None,
) -> str:
    """Execute a BBOT reconnaissance scan with results stored in Neo4j."""
    if not targets:
        return "Error: at least one target is required."
    if not NEO4J_PASSWORD:
        raise RuntimeError(
            "NEO4J_PASSWORD is not set. Configure it via the env block in "
            "capability.yaml or export it before launching the server."
        )

    cfg = list(config or [])
    cfg.extend([
        f"modules.neo4j.uri={NEO4J_URI}",
        f"modules.neo4j.username={NEO4J_USER}",
        f"modules.neo4j.password={NEO4J_PASSWORD}",
    ])

    # `--brief` keeps stdout to summary lines so a long scan does not saturate
    # MAX_OUTPUT. Full event data still lands in Neo4j via the neo4j output
    # module, where the agent should query it via query_graph / explore_nodes.
    parts: list[str] = ["bbot", "--yes", "--output-modules", "neo4j", "--brief"]
    parts.extend(["--targets", *targets])
    if modules:
        parts.extend(["--modules", *modules])
    if flags:
        parts.extend(["--flags", *flags])
    if presets:
        parts.extend(["--preset", *presets])
    parts.extend(["--config", *cfg])
    if extra_args:
        parts.extend(extra_args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # New session/process group so we can signal the entire bbot
            # process tree on timeout. BBOT spawns children (nuclei, dnsbrute,
            # httpx, ...) and a bare proc.terminate() would not reach them.
            start_new_session=True,
        )
    except FileNotFoundError:
        return "Error: bbot not found. Install with: pip install bbot"

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
        output = stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        # wait_for only cancels the await; the bbot process tree is still
        # running. On POSIX, signal the whole group created by
        # start_new_session=True. On platforms without os.killpg (for example
        # Windows), fall back to terminating the direct child process so
        # timeouts still fail closed instead of raising in cleanup.
        if hasattr(os, "killpg"):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
        else:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            if hasattr(os, "killpg"):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            else:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            await proc.wait()
        return f"Scan timed out after {SCAN_TIMEOUT}s (process tree terminated)"

    if len(output) > MAX_OUTPUT:
        output = output[:MAX_OUTPUT] + f"\n\n... [TRUNCATED: {len(output)} chars total]"

    status = "completed" if proc.returncode == 0 else f"exited with code {proc.returncode}"
    return f"Scan {status}.\n\n{output}"


@mcp.tool()
@_catch_errors
async def query_graph(
    cypher: Annotated[str, "Cypher query to execute"],
    params: Annotated[dict | None, "Query parameters (use $param in query)"] = None,
) -> str:
    """Execute a Cypher query against the Neo4j graph database."""
    result = await _neo4j.query(cypher, params)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_db_schema() -> str:
    """Retrieve the Neo4j database schema.

    Returns node labels, relationship types, and their properties.
    Essential for understanding the data model and constructing queries.
    """
    queries = {
        "node_labels": "CALL db.labels() YIELD label",
        "relationship_types": "CALL db.relationshipTypes() YIELD relationshipType",
        "node_properties": "CALL db.schema.nodeTypeProperties()",
        "relationship_properties": "CALL db.schema.relTypeProperties()",
    }

    results = await asyncio.gather(*(_neo4j.query(q) for q in queries.values()))
    node_labels_res, rel_types_res, node_props_res, rel_props_res = results

    schema: dict[str, Any] = {
        "node_labels": sorted([r["label"] for r in node_labels_res]),
        "relationship_types": sorted([r["relationshipType"] for r in rel_types_res]),
        "node_properties": {},
        "relationship_properties": {},
    }

    for record in node_props_res:
        label = record.get("nodeType", "").lstrip(":")
        if not label:
            continue
        schema["node_properties"].setdefault(label, []).append({
            "property": record.get("propertyName"),
            "types": record.get("propertyTypes"),
            "mandatory": record.get("mandatory"),
        })

    for record in rel_props_res:
        rel_type = record.get("relType", "").lstrip(":")
        if not rel_type:
            continue
        schema["relationship_properties"].setdefault(rel_type, []).append({
            "property": record.get("propertyName"),
            "types": record.get("propertyTypes"),
            "mandatory": record.get("mandatory"),
        })

    return json.dumps(schema, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_scan_metadata(
    scope_distance: Annotated[int, "Filter by scope distance (0 = direct targets)"] = 0,
    tags: Annotated[list[str] | None, "Filter by scan tags (node must contain all)"] = None,
) -> str:
    """Retrieve metadata about completed BBOT scans.

    Returns scan IDs, targets, modules used, and timing information.
    """
    filters: dict[str, Any] = {"scope_distance": scope_distance}
    if tags:
        filters["tags"] = tags
    scans = await _neo4j.get_nodes(label="SCAN", filters=filters)
    return json.dumps([_summarize(s) for s in scans], indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_findings(
    scope_distance: Annotated[int, "Filter by scope distance (0 = direct targets)"] = 0,
    tags: Annotated[list[str] | None, "Filter by tags (node must contain all)"] = None,
) -> str:
    """Retrieve security findings and vulnerabilities from scans.

    Returns finding type, severity, description, affected resource, and
    evidence. Use query_graph with `f.severity IN [...]` for severity filtering.
    """
    filters: dict[str, Any] = {"scope_distance": scope_distance}
    if tags:
        filters["tags"] = tags
    findings = await _neo4j.get_nodes(label="FINDING", filters=filters)
    return json.dumps([_summarize(f) for f in findings], indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_asset_summary() -> str:
    """Get a summary count of all asset types in the database."""
    result = await _neo4j.query(
        "MATCH (n) RETURN labels(n)[0] as type, count(n) AS count ORDER BY count DESC"
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_subdomains(
    domain: Annotated[str, "Parent domain to search for subdomains"],
    limit: Annotated[int, "Maximum results"] = 100,
) -> str:
    """List discovered subdomains for a domain."""
    # BBOT's neo4j output module stores the hostname in `data`, not `name` —
    # DNS_NAME nodes have no `name` property at all. Same applies to URL,
    # TECHNOLOGY, IP_ADDRESS, etc: `data` is the canonical primary value.
    result = await _neo4j.query(
        "MATCH (n:DNS_NAME) WHERE n.data ENDS WITH $domain "
        "RETURN n.data AS name ORDER BY n.data LIMIT $limit",
        {"domain": domain, "limit": limit},
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_technologies() -> str:
    """List all discovered technologies and their usage counts."""
    # TECHNOLOGY events are serialized to graph mode with `data` set to the
    # technology name string (via `_pretty_string`), not separate name/version
    # properties. Group by data + host to dedupe per-host fingerprints.
    result = await _neo4j.query(
        "MATCH (t:TECHNOLOGY) "
        "RETURN t.data AS technology, count(*) AS usage "
        "ORDER BY usage DESC"
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def explore_nodes(
    label: Annotated[str | None, "Node type (e.g., 'DNS_NAME', 'URL', 'FINDING')"] = None,
    property_filter: Annotated[
        str | None,
        "Filter: 'property=value' for exact match, 'property CONTAINS value' for substring",
    ] = None,
    limit: Annotated[int, "Maximum nodes to return (1-1000)"] = 100,
) -> str:
    """Explore nodes in the graph database interactively.

    Use get_db_schema() first to see available node labels.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("Limit must be between 1 and 1000.")

    if label is not None:
        _safe_ident(label, "label")
        match_clause = f"MATCH (node:`{label}`)"
    else:
        match_clause = "MATCH (node)"

    query_parts = [match_clause]
    params: dict[str, Any] = {"limit": limit}

    if property_filter:
        # Split on the operator first so we can validate the property name.
        if "CONTAINS" in property_filter:
            prop, _, value = property_filter.partition("CONTAINS")
            op = "CONTAINS"
        elif "=" in property_filter:
            prop, _, value = property_filter.partition("=")
            op = "="
        else:
            raise ValueError(
                "property_filter must use 'property=value' or 'property CONTAINS value'."
            )
        prop = prop.strip()
        value = value.strip()
        _safe_ident(prop, "property name")
        query_parts.append(f"WHERE node.`{prop}` {op} $value")
        params["value"] = value

    query_parts.append("RETURN node LIMIT $limit")
    result = await _neo4j.query(" ".join(query_parts), params)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def explore_relationships(
    source_label: Annotated[str | None, "Source node type (e.g., 'DNS_NAME')"] = None,
    relationship_type: Annotated[str | None, "Relationship type — BBOT names these after the emitting module/record (e.g. 'A', 'CNAME', 'httpx', 'dnsresolve'); call get_db_schema first"] = None,
    target_label: Annotated[str | None, "Target node type (e.g., 'IP_ADDRESS')"] = None,
    limit: Annotated[int, "Maximum relationships to return (1-1000)"] = 100,
) -> str:
    """Discover how nodes are connected in the graph database.

    Use get_db_schema() to see available relationship types.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("Limit must be between 1 and 1000.")

    if source_label is not None:
        _safe_ident(source_label, "source_label")
        source = f"(source:`{source_label}`)"
    else:
        source = "(source)"

    if relationship_type is not None:
        _safe_ident(relationship_type, "relationship_type")
        rel = f"-[relationship:`{relationship_type}`]->"
    else:
        rel = "-[relationship]->"

    if target_label is not None:
        _safe_ident(target_label, "target_label")
        target = f"(target:`{target_label}`)"
    else:
        target = "(target)"

    query = f"MATCH {source}{rel}{target} RETURN source, relationship, target LIMIT $limit"
    result = await _neo4j.query(query, {"limit": limit})
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
@_catch_errors
async def get_screenshot(
    uuid: Annotated[str | None, "The UUID of the WEBSCREENSHOT node"] = None,
    url: Annotated[str | None, "The URL to find a screenshot of"] = None,
) -> str:
    """Retrieve a screenshot from the database.

    Identify a screenshot by its UUID (from explore_nodes) or by the
    original URL that was screenshotted. Returns the file path for viewing.
    """
    if not uuid and not url:
        raise ValueError("Either 'uuid' or 'url' must be provided.")

    if url and not uuid:
        # WEBSCREENSHOT has no top-level `url` property — the URL lives inside
        # the JSON-encoded `.data` dict (alongside `path`). The URL string
        # appears verbatim in that serialization regardless of whether BBOT
        # used json.dumps (double quotes) or Python repr (single quotes), so
        # a plain CONTAINS match is reliable.
        nodes = await _neo4j.query(
            "MATCH (node:WEBSCREENSHOT) WHERE node.data CONTAINS $url RETURN node LIMIT 1",
            {"url": url},
        )
        if not nodes:
            return f"No screenshot found for URL '{url}'."
        uuid = nodes[0].get("node", {}).get("uuid")
        if not uuid:
            return f"No screenshot found for URL '{url}'."

    cypher = """
    MATCH (w:WEBSCREENSHOT {uuid: $uuid})
    MATCH (s:SCAN {id: w.scan})
    RETURN w.data AS web_data, s.data AS scan_data
    """
    result = await _neo4j.query(cypher, {"uuid": uuid})
    if not result:
        return f"No screenshot data found for UUID '{uuid}'."

    scan_data = _parse_serialized_dict(result[0].get("scan_data", ""))
    web_data = _parse_serialized_dict(result[0].get("web_data", ""))

    scan_name = str(scan_data.get("name", "")) if isinstance(scan_data, dict) else ""
    relative_path = str(web_data.get("path", "")) if isinstance(web_data, dict) else ""
    original_url = str(web_data.get("url", "")) if isinstance(web_data, dict) else ""

    if not scan_name or not relative_path:
        return "Screenshot data is missing required fields."

    bbot_home = Path(BBOT_DATA_DIR).expanduser().resolve()
    full_path = (bbot_home / "scans" / scan_name / relative_path).resolve()

    # Containment check: a malicious or corrupted `path` field in the
    # WEBSCREENSHOT node (e.g. containing `..` segments) must not be able
    # to escape the bbot data directory and read arbitrary files.
    if not full_path.is_relative_to(bbot_home):
        return f"Screenshot path escapes bbot data directory: {full_path}"

    if not full_path.exists():
        return f"Screenshot file not found at: {full_path}"

    return json.dumps(
        {"path": str(full_path), "url": original_url, "uuid": uuid},
        indent=2,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
