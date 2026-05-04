"""Toolset: graph queries via Cypher and saved-query management.

The most powerful BHE primitive is the raw Cypher endpoint
``/api/v2/graphs/cypher`` — it accepts an OpenCypher query and
returns a graph the agent can walk. Free-form Cypher is also
the easiest way to footgun a deployment, so this module wraps it
with three guardrails:

1. **Read-only enforcement** — queries containing write clauses
   (``CREATE``, ``MERGE``, ``DELETE``, ``SET``, ``REMOVE``,
   ``DETACH``) are rejected unless the agent passes
   ``allow_writes=True``. The default tightens the blast radius for
   exploratory work; the agent can opt in for tag-management or
   bulk-update workflows.
2. **Default ``LIMIT`` enforcement** — queries without a ``LIMIT``
   are wrapped to add one, so a stray ``MATCH (n) RETURN n`` doesn't
   stream a million nodes.
3. **Result truncation** — the ``Graph`` returned is summarised
   before round-tripping through the tool boundary so the model
   sees structure, not raw bytes.
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client
from runtime.cypher_helpers import ensure_limit, is_write_query, summarise_graph
from runtime.cypher_library import (
    CATEGORIES,
    all_patterns,
    category_counts,
    get_pattern,
    patterns_by_category,
    patterns_for_finding,
)


class CypherTools(Toolset):
    """Run Cypher queries and manage saved queries against BHE."""

    default_limit: int = 200
    """Default ``LIMIT`` injected when a query doesn't supply one."""

    max_nodes: int = 200
    """Max node rows returned through the tool boundary."""

    max_edges: int = 400
    """Max edge rows returned through the tool boundary."""

    @tool_method(name="run_cypher", catch=True)
    async def run_cypher(
        self,
        query: t.Annotated[
            str,
            "OpenCypher query string. The runtime injects a default LIMIT "
            "when one is missing; pass an explicit LIMIT to override.",
        ],
        allow_writes: t.Annotated[
            bool,
            "If false (default), queries containing CREATE/MERGE/DELETE/"
            "SET/REMOVE/DETACH/DROP are rejected before reaching the API.",
        ] = False,
        include_properties: t.Annotated[
            bool,
            "Pass include_properties=True on the BHE side. Use only when "
            "the agent needs more than label/kind/objectId on each node.",
        ] = False,
    ) -> str:
        """Execute a Cypher query against the BHE graph.

        Read-only by default. Returns a digest of the resulting
        graph: counts, the first N nodes, and the first N edges
        with their kind / direction. The full graph stays on the
        server — this tool is for exploration, not bulk export.
        """
        if not query.strip():
            return "error: query is empty"
        if not allow_writes and is_write_query(query):
            return (
                "error: query contains a write clause; pass allow_writes=True "
                "if you really intend to mutate the graph"
            )
        bounded_query = ensure_limit(query, self.default_limit)
        client = get_client()
        try:
            payload = await client.post_json(
                "/api/v2/graphs/cypher",
                json={
                    "query": bounded_query,
                    "include_properties": include_properties,
                },
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(
            summarise_graph(
                payload, max_nodes=self.max_nodes, max_edges=self.max_edges
            ),
            indent=2,
            default=str,
        )

    @tool_method(name="list_saved_queries", catch=True)
    async def list_saved_queries(
        self,
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 100,
    ) -> str:
        """List user-saved Cypher queries on the BHE deployment.

        Each entry carries a name, description, and the query
        body so an agent can pick a relevant one and either run it
        directly or adapt it for a one-off question.
        """
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/saved-queries", params={"skip": skip, "limit": limit}
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="run_saved_query", catch=True)
    async def run_saved_query(
        self,
        query_id: t.Annotated[int, "Id of the saved query to execute"],
        include_properties: t.Annotated[bool, "Forward to the cypher endpoint"] = False,
    ) -> str:
        """Look up a saved query by id and run it.

        Convenience wrapper: fetches the query body, then routes it
        through ``run_cypher`` so the same safety guards apply.
        Saved queries that contain write clauses still require
        ``allow_writes=True`` if you call ``run_cypher`` directly.
        """
        client = get_client()
        try:
            entry = await client.get_json(f"/api/v2/saved-queries/{query_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        body = (entry.get("data") or {}).get("query") or entry.get("query")
        if not body:
            return f"error: saved query {query_id} has no query body"
        return await self.run_cypher(body, include_properties=include_properties)

    @tool_method(name="create_saved_query", catch=True)
    async def create_saved_query(
        self,
        name: t.Annotated[str, "Display name for the saved query"],
        query: t.Annotated[str, "OpenCypher source"],
        description: t.Annotated[str, "Free-form description"] = "",
    ) -> str:
        """Persist a Cypher query so other tools/agents can run it."""
        if not query.strip():
            return "error: query is empty"
        client = get_client()
        try:
            data = await client.post_json(
                "/api/v2/saved-queries",
                json={"name": name, "query": query, "description": description},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="delete_saved_query", catch=True)
    async def delete_saved_query(
        self,
        query_id: t.Annotated[int, "Id of the saved query to remove"],
    ) -> str:
        """Delete a saved query."""
        client = get_client()
        try:
            await client.delete_json(f"/api/v2/saved-queries/{query_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return f"deleted {query_id}"

    # ------------------------------------------------------------------
    # Curated attack-pattern library (in-process, doesn't hit the API)
    # ------------------------------------------------------------------

    @tool_method(name="list_attack_patterns", catch=True)
    async def list_attack_patterns(
        self,
        category: t.Annotated[
            str,
            "Filter by category (domain-admins, tier-zero, kerberos, "
            "delegation, adcs, acl-abuse, sessions-lateral, gpo, "
            "credentials, azure, trust, owned). Empty for the full catalog.",
        ] = "",
        finding_type: t.Annotated[
            str,
            "Filter by BHE attack-path finding type (e.g. 'Kerberoastable', "
            "'ADCSESC1'). Useful for picking patterns that map to "
            "currently-active findings.",
        ] = "",
    ) -> str:
        """Browse the curated attack-pattern catalog.

        The catalog ships ~40 read-only Cypher queries covering AD,
        Azure, and PKI attack patterns. Each entry has an id you
        can pass to ``run_attack_pattern`` to execute without
        writing fresh Cypher. Filter by category or finding type
        to narrow the list before running.
        """
        if category:
            entries = patterns_by_category(category)
            if not entries:
                return (
                    f"error: unknown category {category!r}. "
                    f"Known: {', '.join(CATEGORIES)}"
                )
        elif finding_type:
            entries = patterns_for_finding(finding_type)
        else:
            entries = all_patterns()

        return json.dumps(
            {
                "catalog_size": len(all_patterns()),
                "category_counts": category_counts(),
                "matches": len(entries),
                "patterns": [
                    {
                        "id": p.id,
                        "category": p.category,
                        "name": p.name,
                        "description": p.description,
                        "attack_path_type": p.attack_path_type,
                    }
                    for p in entries
                ],
            },
            indent=2,
            default=str,
        )

    @tool_method(name="run_attack_pattern", catch=True)
    async def run_attack_pattern(
        self,
        pattern_id: t.Annotated[
            str,
            "Pattern id from list_attack_patterns (e.g. 'tier-zero-from-domain-users').",
        ],
        include_properties: t.Annotated[
            bool,
            "Forward to the cypher endpoint. Pull node/edge properties "
            "in the result; off by default for a smaller payload.",
        ] = False,
    ) -> str:
        """Execute a named attack-pattern query.

        Wraps ``run_cypher`` — same safety guards (read-only,
        LIMIT enforcement, result truncation). Returns the same
        digest. Saves the agent from re-deriving canonical AD
        attack queries on every session.
        """
        pattern = get_pattern(pattern_id)
        if pattern is None:
            return (
                f"error: no pattern with id {pattern_id!r}. "
                f"Use list_attack_patterns to browse the catalog."
            )
        return await self.run_cypher(
            pattern.cypher,
            include_properties=include_properties,
        )

    @tool_method(name="describe_attack_pattern", catch=True)
    async def describe_attack_pattern(
        self,
        pattern_id: t.Annotated[str, "Pattern id"],
    ) -> str:
        """Return the full pattern definition — name, category,
        description, attack-path-type, and the literal Cypher.

        Useful as a starting point when adapting a curated pattern
        for a one-off question — read the body, copy it into
        ``run_cypher``, tweak the WHERE clause.
        """
        pattern = get_pattern(pattern_id)
        if pattern is None:
            return f"error: no pattern with id {pattern_id!r}"
        return json.dumps(
            {
                "id": pattern.id,
                "category": pattern.category,
                "name": pattern.name,
                "description": pattern.description,
                "attack_path_type": pattern.attack_path_type,
                "cypher": pattern.cypher,
                "references": list(pattern.references),
            },
            indent=2,
            default=str,
        )
