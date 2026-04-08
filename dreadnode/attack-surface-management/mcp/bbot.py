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
import json
import os
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
        output = output[:MAX_OUTPUT] + f"\n\n... [TRUNCATED]"

    status = "completed" if proc.returncode == 0 else f"exited with code {proc.returncode}"
    return f"Scan {status}.\n\n{output}"


@mcp.tool()
async def query_graph(
    cypher: Annotated[str, "Cypher query to execute"],
    params: Annotated[dict | None, "Query parameters (use $param in query)"] = None,
) -> str:
    """Execute a Cypher query against the Neo4j graph database."""
    result = await _neo4j.query(cypher, params)
    return json.dumps(result, indent=2, default=str)


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
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_asset_summary() -> str:
    """Get a summary count of all asset types in the database."""
    result = await _neo4j.query(
        "MATCH (n) RETURN labels(n)[0] as type, count(n) AS count ORDER BY count DESC"
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_subdomains(
    domain: Annotated[str, "Parent domain to search for subdomains"],
    limit: Annotated[int, "Maximum results"] = 100,
) -> str:
    """List discovered subdomains for a domain."""
    result = await _neo4j.query(
        "MATCH (n:DNS_NAME) WHERE n.name ENDS WITH $domain RETURN n.name ORDER BY n.name LIMIT $limit",
        {"domain": domain, "limit": limit},
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_technologies() -> str:
    """List all discovered technologies and their usage counts."""
    result = await _neo4j.query(
        "MATCH (t:TECHNOLOGY) RETURN DISTINCT t.name, t.version, count(*) as usage ORDER BY usage DESC"
    )
    return json.dumps(result, indent=2, default=str)
