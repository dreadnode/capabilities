"""BBOT reconnaissance scanning and Neo4j graph database query tools.

Provides run_bbot_scan for executing BBOT CLI scans and a suite of Neo4j
Cypher query tools for analyzing reconnaissance results stored in a
property graph. The Neo4j connection is lazily initialized on first query.

Prerequisites:
    - bbot CLI installed and in PATH
    - Neo4j database running (container or external)
    - Neo4j output module configured in BBOT
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import json
import logging
import os
import shlex
import typing as t
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

try:
    from neo4j import AsyncDriver, AsyncGraphDatabase
except ImportError:
    AsyncDriver = None  # type: ignore[assignment, misc]
    AsyncGraphDatabase = None  # type: ignore[assignment, misc]

# Reduce Neo4j driver logging noise
logging.getLogger("neo4j").setLevel(logging.ERROR)


def _parse_serialized_dict(data: str) -> t.Any:
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


def _summarize(data: dict[str, t.Any]) -> dict[str, t.Any]:
    """Condense a node record to essential fields, truncating long values."""
    summary: dict[str, t.Any] = {}
    essential = ["id", "type", "data", "host", "netloc", "port", "tags", "scope_description", "scope_distance"]
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


class BbotTools(Toolset):
    """Execute BBOT reconnaissance scans and query results from the Neo4j graph database."""

    neo4j_uri: str = "bolt://localhost:7687"
    """Neo4j bolt URI. Override with NEO4J_URI env var or set directly."""

    neo4j_user: str = "neo4j"
    """Neo4j username."""

    neo4j_password: str = "bbotislife"
    """Neo4j password."""

    bbot_data_dir: str = ".bbot"
    """Directory where BBOT stores scan data."""

    scan_timeout: int = 3600
    """Maximum time in seconds for a BBOT scan to run."""

    max_output_chars: int = 50_000
    """Maximum characters returned from scan output."""

    _driver: t.Any = PrivateAttr(default=None)

    def model_post_init(self, __context: t.Any) -> None:
        """Apply environment variable overrides after initialization."""
        if uri := os.environ.get("NEO4J_URI"):
            self.neo4j_uri = uri
        if user := os.environ.get("NEO4J_USER"):
            self.neo4j_user = user
        if password := os.environ.get("NEO4J_PASSWORD"):
            self.neo4j_password = password

    async def _ensure_driver(self) -> "AsyncDriver":
        """Lazily initialize and return the Neo4j async driver."""
        if self._driver is None:
            if AsyncGraphDatabase is None:
                raise RuntimeError(
                    "neo4j package is not installed. Install with: pip install neo4j>=5.28.1"
                )
            self._driver = AsyncGraphDatabase.driver(
                self.neo4j_uri, auth=(self.neo4j_user, self.neo4j_password)
            )
            await self._driver.verify_connectivity()
        return self._driver

    async def _query(
        self, cypher: str, params: dict[str, t.Any] | None = None
    ) -> list[dict[str, t.Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        driver = await self._ensure_driver()
        async with driver.session() as session:
            result = await session.run(cypher, params or {})
            return [record.data() async for record in result]

    async def _get_nodes(
        self, label: str, filters: dict[str, t.Any] | None = None, limit: int = 100
    ) -> list[dict[str, t.Any]]:
        """Fetch nodes by label with optional property filtering."""
        where_clauses = ["$label IN labels(n)"]
        if filters:
            where_clauses.extend(f"n.`{key}` = ${key}" for key in filters)

        cypher = f"""
            MATCH (n)
            WHERE {" AND ".join(where_clauses)}
            RETURN n
            {"LIMIT " + str(limit) if limit else ""}
        """
        params: dict[str, t.Any] = {"label": label}
        if filters:
            params.update(filters)
        result = await self._query(cypher, params)
        return [record["n"] for record in result]

    # ── Scanning ──────────────────────────────────────────────────────────

    @tool_method(name="run_bbot_scan", catch=True)
    async def run_scan(
        self,
        targets: t.Annotated[list[str], "Targets to scan (e.g., ['example.com', '10.0.0.0/24'])"],
        modules: t.Annotated[list[str] | None, "Modules to run (e.g., ['httpx', 'nuclei'])"] = None,
        presets: t.Annotated[
            list[str] | None,
            "Presets to use (e.g., ['subdomain-enum', 'web-basic']). "
            "Available: subdomain-enum, web-basic, web-thorough, cloud-enum, code-enum, "
            "email-enum, spider, nuclei, nuclei-intense, dirbust-light, dirbust-heavy, "
            "lightfuzz-light, lightfuzz-medium, tech-detect, kitchen-sink",
        ] = None,
        flags: t.Annotated[
            list[str] | None,
            "Flags to enable module groups (e.g., ['passive', 'safe']). "
            "Available: active, passive, safe, aggressive, subdomain-enum, web-basic, "
            "web-thorough, cloud-enum, code-enum, portscan, web-screenshots",
        ] = None,
        config: t.Annotated[
            list[str] | None,
            "Custom config in key=value format (e.g., ['modules.httpx.timeout=5'])",
        ] = None,
        extra_args: t.Annotated[
            list[str] | None,
            "Additional bbot CLI flags (e.g., ['--strict-scope', '--proxy http://127.0.0.1:8080'])",
        ] = None,
    ) -> str:
        """Execute a BBOT reconnaissance scan against targets.

        Assembles and runs a `bbot` command, automatically configuring it to
        report findings to the Neo4j database. Results are stored in the graph
        and can be queried with the other tools.

        The scan runs locally via the bbot CLI which must be installed and in PATH.
        """
        if not targets:
            raise ValueError("At least one target is required to run a scan.")

        # Configure Neo4j output
        config = config or []
        config.extend([
            f"modules.neo4j.uri={self.neo4j_uri}",
            f"modules.neo4j.username={self.neo4j_user}",
            f"modules.neo4j.password={self.neo4j_password}",
        ])

        # Assemble the BBOT command
        parts = ["bbot", "--yes", "--output-modules", "neo4j", "--brief"]

        parts.extend(["--targets", *targets])

        if modules:
            parts.extend(["--modules", *modules])
        if flags:
            parts.extend(["--flags", *flags])
        if presets:
            parts.extend(["--preset", *presets])
        if config:
            parts.extend(["--config", *config])
        if extra_args:
            parts.extend(extra_args)

        command_str = " ".join(parts)

        # Execute the scan
        try:
            process = await asyncio.create_subprocess_exec(
                *shlex.split(command_str),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            output_chunks: list[str] = []

            async def stream() -> None:
                if not process or not process.stdout:
                    return
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    output_chunks.append(line.decode(errors="replace").strip())

            await asyncio.wait_for(stream(), timeout=self.scan_timeout)
            await process.wait()

            exit_code = process.returncode or 0

        except asyncio.TimeoutError:
            if process:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            output = "\n".join(output_chunks)
            return f"Scan timed out after {self.scan_timeout}s. Partial output:\n{output}"

        except FileNotFoundError:
            return (
                "Error: bbot command not found. "
                "Install BBOT: pip install bbot (https://github.com/blacklanternsecurity/bbot)"
            )

        output = "\n".join(output_chunks)

        if exit_code != 0:
            return f"BBOT scan exited with code {exit_code}:\n{output}"

        if len(output) > self.max_output_chars:
            output = output[: self.max_output_chars] + f"\n\n... [TRUNCATED: {len(output)} chars total]"

        return f"Scan completed successfully.\n\n{output}"

    # ── Graph Queries ─────────────────────────────────────────────────────

    @tool_method(name="query_graph", catch=True)
    async def query_graph(
        self,
        cypher: t.Annotated[str, "The Cypher query to execute"],
        params: t.Annotated[
            dict[str, t.Any] | None,
            "Optional parameters to safely inject values (prevents injection). "
            "Use $param syntax in the query.",
        ] = None,
    ) -> str:
        """Execute a Cypher query against the Neo4j graph database.

        This is the primary analysis tool for exploring reconnaissance data.
        Use parameterized queries ($param) for user input to prevent injection.

        Common patterns:
            Count by type: MATCH (n) RETURN labels(n)[0] as type, count(n) as count ORDER BY count DESC
            Find domains: MATCH (n:DNS_NAME) WHERE n.name CONTAINS 'api' RETURN n.name LIMIT 20
            DNS to IP: MATCH (d:DNS_NAME)-[:RESOLVES_TO]->(ip:IP_ADDRESS) RETURN d.name, ip.address
            Critical findings: MATCH (f:FINDING) WHERE f.severity IN ['critical', 'high'] RETURN f
            Tech stack: MATCH (n:TECHNOLOGY) RETURN DISTINCT n.name, n.version
            Shared hosting: MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d) WITH ip, count(d) as cnt WHERE cnt > 1 RETURN ip.address, cnt
        """
        result = await self._query(cypher, params)
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="get_scan_metadata", catch=True)
    async def get_scans(
        self,
        scope_distance: t.Annotated[int, "Filter by scope distance (0 = direct targets)"] = 0,
        tags: t.Annotated[list[str] | None, "Filter by scan tags"] = None,
    ) -> str:
        """Retrieve metadata about completed BBOT scans.

        Returns scan IDs, targets, modules used, and timing information.
        """
        scans = await self._get_nodes(
            label="SCAN",
            filters={"scope_distance": scope_distance, **({"tags": tags} if tags else {})},
        )
        summarized = [_summarize(scan) for scan in scans]
        return json.dumps(summarized, indent=2, default=str)

    @tool_method(name="get_findings", catch=True)
    async def get_findings(
        self,
        scope_distance: t.Annotated[int, "Filter by scope distance (0 = direct targets)"] = 0,
        tags: t.Annotated[list[str] | None, "Filter by tags (e.g., ['critical', 'authentication'])"] = None,
    ) -> str:
        """Retrieve security findings and vulnerabilities from scans.

        Returns finding type, severity, description, affected resource,
        and evidence. Use this to quickly identify confirmed issues.
        """
        findings = await self._get_nodes(
            label="FINDING",
            filters={"scope_distance": scope_distance, **({"tags": tags} if tags else {})},
        )
        summarized = [_summarize(finding) for finding in findings]
        return json.dumps(summarized, indent=2, default=str)

    @tool_method(name="get_db_schema", catch=True)
    async def get_schema(self) -> str:
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

        results = await asyncio.gather(*(self._query(q) for q in queries.values()))
        node_labels_res, rel_types_res, node_props_res, rel_props_res = results

        schema: dict[str, t.Any] = {
            "node_labels": sorted([r["label"] for r in node_labels_res]),
            "relationship_types": sorted([r["relationshipType"] for r in rel_types_res]),
            "node_properties": {},
            "relationship_properties": {},
        }

        for record in node_props_res:
            label = record.get("nodeType", "").lstrip(":")
            if not label:
                continue
            if label not in schema["node_properties"]:
                schema["node_properties"][label] = []
            schema["node_properties"][label].append({
                "property": record.get("propertyName"),
                "types": record.get("propertyTypes"),
                "mandatory": record.get("mandatory"),
            })

        for record in rel_props_res:
            rel_type = record.get("relType", "").lstrip(":")
            if not rel_type:
                continue
            if rel_type not in schema["relationship_properties"]:
                schema["relationship_properties"][rel_type] = []
            schema["relationship_properties"][rel_type].append({
                "property": record.get("propertyName"),
                "types": record.get("propertyTypes"),
                "mandatory": record.get("mandatory"),
            })

        return json.dumps(schema, indent=2, default=str)

    @tool_method(name="explore_nodes", catch=True)
    async def explore_nodes(
        self,
        label: t.Annotated[str | None, "Node type (e.g., 'DNS_NAME', 'URL', 'FINDING')"] = None,
        property_filter: t.Annotated[
            str | None,
            "Filter: 'property=value' for exact match, 'property CONTAINS value' for substring",
        ] = None,
        limit: t.Annotated[int, "Maximum nodes to return (1-1000)"] = 100,
    ) -> str:
        """Explore nodes in the graph database interactively.

        Flexible tool for discovering and examining nodes when you're not sure
        exactly what you're looking for. Use get_db_schema() first to see
        available node labels.
        """
        if limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        query_parts = [f"MATCH (node:{label})" if label else "MATCH (node)"]
        params: dict[str, t.Any] = {}

        if property_filter:
            if "CONTAINS" in property_filter:
                parts = property_filter.split("CONTAINS", 1)
                if len(parts) == 2:
                    prop, value = parts
                    query_parts.append(f"WHERE node.{prop.strip()} CONTAINS $value")
                    params["value"] = value.strip()
            elif "=" in property_filter:
                prop, value = property_filter.split("=", 1)
                query_parts.append(f"WHERE node.{prop.strip()} = $value")
                params["value"] = value.strip()

        query_parts.append("RETURN node LIMIT $limit")

        result = await self._query(" ".join(query_parts), {"limit": limit, **params})
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="explore_relationships", catch=True)
    async def explore_relationships(
        self,
        source_label: t.Annotated[str | None, "Source node type (e.g., 'DNS_NAME')"] = None,
        relationship_type: t.Annotated[str | None, "Relationship type (e.g., 'RESOLVES_TO')"] = None,
        target_label: t.Annotated[str | None, "Target node type (e.g., 'IP_ADDRESS')"] = None,
        limit: t.Annotated[int, "Maximum relationships to return (1-1000)"] = 100,
    ) -> str:
        """Discover how nodes are connected in the graph database.

        Use get_db_schema() to see available relationship types.
        """
        if limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        source = f"(source:{source_label})" if source_label else "(source)"
        rel = f"-[relationship:{relationship_type}]->" if relationship_type else "-[relationship]->"
        target = f"(target:{target_label})" if target_label else "(target)"

        query = f"MATCH {source}{rel}{target} RETURN source, relationship, target LIMIT $limit"
        result = await self._query(query, {"limit": limit})
        return json.dumps(result, indent=2, default=str)

    @tool_method(name="get_screenshot", catch=True)
    async def get_screenshot(
        self,
        uuid: t.Annotated[str | None, "The UUID of the WEBSCREENSHOT node"] = None,
        url: t.Annotated[str | None, "The URL to find a screenshot of"] = None,
    ) -> str:
        """Retrieve a screenshot from the database.

        Identify a screenshot by its UUID (from explore_nodes) or by the
        original URL that was screenshotted. Returns the file path for viewing.
        """
        if not uuid and not url:
            raise ValueError("Either 'uuid' or 'url' must be provided.")

        if url and not uuid:
            nodes = await self._query(
                "MATCH (node:WEBSCREENSHOT) WHERE node.url CONTAINS $url RETURN node LIMIT 1",
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
        result = await self._query(cypher, {"uuid": uuid})
        if not result:
            return f"No screenshot data found for UUID '{uuid}'."

        scan_data = _parse_serialized_dict(result[0].get("scan_data", ""))
        web_data = _parse_serialized_dict(result[0].get("web_data", ""))

        scan_name = str(scan_data.get("name", ""))
        relative_path = str(web_data.get("path", ""))
        original_url = str(web_data.get("url", ""))

        if not all([scan_name, relative_path]):
            return "Screenshot data is missing required fields."

        bbot_home = Path(self.bbot_data_dir).expanduser().resolve()
        full_path = bbot_home / "scans" / scan_name / relative_path

        if not full_path.exists():
            return f"Screenshot file not found at: {full_path}"

        return json.dumps({
            "path": str(full_path),
            "url": original_url,
            "uuid": uuid,
        }, indent=2)
