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
from typing import Annotated

from fastmcp import FastMCP
from neo4j import AsyncGraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "bbotislife")
BBOT_DATA_DIR = os.environ.get("BBOT_DATA_DIR", ".bbot")
SCAN_TIMEOUT = 3600
MAX_OUTPUT = 50_000
_CYPHER_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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

    cfg = list(config or [])
    cfg.extend([
        f"modules.neo4j.uri={NEO4J_URI}",
        f"modules.neo4j.username={NEO4J_USER}",
        f"modules.neo4j.password={NEO4J_PASSWORD}",
    ])

    parts = ["bbot", "--yes", "--output-modules", "neo4j", "--brief"]
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

    cmd = " ".join(parts)

    try:
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(cmd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
        output = stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        return f"Scan timed out after {SCAN_TIMEOUT}s"
    except FileNotFoundError:
        return "Error: bbot not found. Install with: pip install bbot"

    if len(output) > MAX_OUTPUT:
        output = output[:MAX_OUTPUT] + "\n\n... [TRUNCATED]"

    status = "completed" if proc.returncode == 0 else f"exited with code {proc.returncode}"
    return f"Scan {status}.\n\n{output}"


@mcp.tool()
async def query_graph(
    cypher: Annotated[str, "Cypher query to execute"],
    params: Annotated[dict | None, "Query parameters (use $param in query)"] = None,
) -> str:
    """Execute a Cypher query against the Neo4j graph database."""
    result = await _neo4j.query(cypher, params)
    return _safe_json(result)


@mcp.tool()
async def get_findings(
    severity: Annotated[str | None, "Filter by severity (critical, high, medium, low)"] = None,
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
        "node_labels": sorted(record["label"] for record in labels if record.get("label")),
        "relationship_types": sorted(
            record["relationshipType"] for record in rel_types if record.get("relationshipType")
        ),
        "node_properties": {},
        "relationship_properties": {},
    }

    node_properties: dict[str, list[dict[str, object]]] = {}
    for record in node_props:
        label = str(record.get("nodeType", "")).lstrip(":")
        if not label:
            continue
        node_properties.setdefault(label, []).append({
            "property": record.get("propertyName"),
            "types": record.get("propertyTypes"),
            "mandatory": record.get("mandatory"),
        })

    relationship_properties: dict[str, list[dict[str, object]]] = {}
    for record in rel_props:
        rel_type = str(record.get("relType", "")).lstrip(":")
        if not rel_type:
            continue
        relationship_properties.setdefault(rel_type, []).append({
            "property": record.get("propertyName"),
            "types": record.get("propertyTypes"),
            "mandatory": record.get("mandatory"),
        })

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
    label: Annotated[str | None, "Node label to browse, for example DNS_NAME, URL, FINDING"] = None,
    property_filter: Annotated[
        str | None,
        "Optional filter: 'property=value' for exact match or 'property CONTAINS value' for substring",
    ] = None,
    limit: Annotated[int, "Maximum nodes to return (1-1000)"] = 100,
) -> str:
    """Browse graph nodes by label and optional property filter."""
    limit = _coerce_int_limit(limit)
    query_parts = [f"MATCH (node:{_validate_cypher_identifier(label, 'label')})" if label else "MATCH (node)"]
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
    source = f"(source:{_validate_cypher_identifier(source_label, 'source label')})" if source_label else "(source)"
    target = f"(target:{_validate_cypher_identifier(target_label, 'target label')})" if target_label else "(target)"
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
    original_url = web_props.get("url") or web_data.get("url") or web_props.get("host") or url
    relative_path = web_props.get("path") or web_data.get("path")
    scan_name = scan_props.get("name") or scan_data.get("name") or web_props.get("scan")

    if not relative_path:
        return _safe_json({
            "error": "Screenshot data is missing a path.",
            "uuid": screenshot_uuid,
            "url": original_url,
        })

    path = Path(str(relative_path)).expanduser()
    candidates = [path] if path.is_absolute() else []
    bbot_home = Path(BBOT_DATA_DIR).expanduser().resolve()
    if not path.is_absolute() and scan_name:
        candidates.append(bbot_home / "scans" / str(scan_name) / path)
    if not path.is_absolute():
        candidates.append(bbot_home / path)

    for candidate in candidates:
        if candidate.exists():
            return _safe_json({
                "path": str(candidate),
                "url": original_url,
                "uuid": screenshot_uuid,
            })

    return _safe_json({
        "error": "Screenshot file not found.",
        "checked_paths": [str(candidate) for candidate in candidates],
        "url": original_url,
        "uuid": screenshot_uuid,
    })
