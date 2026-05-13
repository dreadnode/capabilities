#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "neo4j>=5.0",
#   "aiohttp>=3.0",
# ]
# ///
"""BloodHound CE MCP server — graph queries and API interaction.

Env vars:
  BLOODHOUND_URL          (default: http://localhost:8080)
  BLOODHOUND_USERNAME     (default: admin)
  BLOODHOUND_PASSWORD     (required unless provided via connect tool)
  NEO4J_URL               (default: bolt://localhost:7687)
  NEO4J_USERNAME          (default: neo4j)
  NEO4J_PASSWORD          (default: bloodhoundcommunityedition)
"""

from __future__ import annotations

import os
from typing import Annotated, Any

import aiohttp
from fastmcp import FastMCP
from neo4j import AsyncGraphDatabase

mcp = FastMCP("bloodhound")

# ── Standard query catalog ───────────────────────────────────────────

STANDARD_QUERIES: dict[str, dict[str, str]] = {
    # Domain Admins & Trusts
    "find_all_domain_admins": {
        "description": "Find all users and computers that are members of the Domain Admins group",
        "category": "domain-admins",
        "cypher": "MATCH p = (t:Group)<-[:MemberOf*1..]-(a) WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512' RETURN p LIMIT 1000",
    },
    "map_domain_trusts": {
        "description": "Map all domain trust relationships",
        "category": "domain-admins",
        "cypher": "MATCH p = (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p",
    },
    # Tier Zero
    "find_tier_zero_locations": {
        "description": "Find where tier zero principals are logged in",
        "category": "tier-zero",
        "cypher": "MATCH p = (c:Computer)-[:HasSession]->(s) WHERE s.highvalue = true RETURN p",
    },
    "find_shortest_paths_to_tier_zero": {
        "description": "Find shortest attack paths from any principal to tier zero assets",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((s)-[r*1..]->(t)) WHERE t.highvalue = true AND s<>t RETURN p LIMIT 1000",
    },
    "find_paths_from_domain_users_to_tier_zero": {
        "description": "Find paths from Domain Users group to tier zero",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((g:Group)-[r*1..]->(t)) WHERE g.objectid ENDS WITH '-513' AND t.highvalue = true RETURN p LIMIT 1000",
    },
    "find_paths_from_owned_objects": {
        "description": "Find attack paths from owned principals",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((s)-[r*1..]->(t)) WHERE s.owned = true AND t.highvalue = true AND s<>t RETURN p LIMIT 1000",
    },
    # Kerberos
    "find_kerberoastable_tier_zero": {
        "description": "Find tier zero users vulnerable to Kerberoasting",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true AND NOT u.objectid ENDS WITH '-502' AND NOT u.gmsa=true AND NOT u.msa=true AND u.highvalue=true RETURN u LIMIT 100",
    },
    "find_all_kerberoastable_users": {
        "description": "Find all Kerberoastable users",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true AND NOT u.objectid ENDS WITH '-502' AND NOT u.gmsa=true AND NOT u.msa=true RETURN u LIMIT 500",
    },
    "find_asreproast_users": {
        "description": "Find users vulnerable to AS-REP roasting (no pre-auth required)",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true RETURN u LIMIT 500",
    },
    "find_paths_from_kerberoastable_to_da": {
        "description": "Find paths from Kerberoastable users to Domain Admins",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p=shortestPath((u)-[r*1..]->(g)) RETURN p LIMIT 1000",
    },
    # Delegation
    "find_shortest_paths_unconstrained_delegation": {
        "description": "Find paths to computers with unconstrained delegation",
        "category": "delegation",
        "cypher": "MATCH (c:Computer) WHERE c.unconstraineddelegation=true MATCH p=shortestPath((s)-[r*1..]->(c)) WHERE s<>c RETURN p LIMIT 1000",
    },
    # DCSync & Privileges
    "find_dcsync_privileges": {
        "description": "Find principals with DCSync privileges",
        "category": "privileges",
        "cypher": "MATCH p = (n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p",
    },
    "find_domain_users_local_admins": {
        "description": "Find domain users with local admin rights",
        "category": "privileges",
        "cypher": "MATCH p = (g:Group)-[:AdminTo]->(c:Computer) WHERE g.objectid ENDS WITH '-513' RETURN p",
    },
    # PKI / ADCS
    "find_pki_hierarchy": {
        "description": "Map the PKI certificate authority hierarchy",
        "category": "pki",
        "cypher": "MATCH p = ()-[:IssuedSignedBy|EnterpriseCAFor|RootCAFor|TrustedForNTAuth*1..]->(d:Domain) RETURN p",
    },
    "find_esc1_vulnerable_templates": {
        "description": "Find certificate templates vulnerable to ESC1",
        "category": "pki",
        "cypher": "MATCH (t:CertTemplate) WHERE t.enrolleesuppliessubject=true AND t.authenticationenabled=true AND t.requiresmanagerapproval=false AND t.enabled=true MATCH p = ()-[:Enroll|GenericAll|AllExtendedRights]->(t) RETURN p LIMIT 1000",
    },
    "find_esc8_vulnerable_cas": {
        "description": "Find CAs vulnerable to ESC8 (NTLM relay to HTTP enrollment)",
        "category": "pki",
        "cypher": "MATCH (ca:EnterpriseCA) WHERE ca.isuserspecifiessanenabled=true RETURN ca",
    },
    # NTLM & Network
    "find_ntlm_relay_edges": {
        "description": "Find NTLM relay attack opportunities",
        "category": "network",
        "cypher": "MATCH p = ()-[:CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToHTTP*1..]->(t) RETURN p LIMIT 1000",
    },
    "find_computers_no_smb_signing": {
        "description": "Find computers without SMB signing enabled",
        "category": "network",
        "cypher": "MATCH (c:Computer) WHERE c.signingrequired=false RETURN c LIMIT 500",
    },
    "find_computers_webclient_running": {
        "description": "Find computers running the WebClient service",
        "category": "network",
        "cypher": "MATCH (c:Computer) WHERE c.webclientrunning=true RETURN c LIMIT 500",
    },
    # Hygiene
    "find_unsupported_operating_systems": {
        "description": "Find computers running unsupported operating systems",
        "category": "hygiene",
        "cypher": "MATCH (c:Computer) WHERE c.operatingsystem =~ '.*(2000|2003|2008|XP|Vista|7 |ME|98).*' RETURN c LIMIT 500",
    },
    "find_users_password_not_rotated": {
        "description": "Find enabled users whose password hasn't been changed in over a year",
        "category": "hygiene",
        "cypher": "MATCH (u:User) WHERE u.enabled=true AND u.pwdlastset < (datetime().epochSeconds - 31536000) RETURN u LIMIT 500",
    },
    # Azure / Entra
    "find_global_administrators": {
        "description": "Find Azure/Entra Global Administrator role members",
        "category": "azure",
        "cypher": "MATCH p = (n)-[:AZHasRole|AZMemberOf*1..]->(r:AZRole) WHERE r.displayname = 'Global Administrator' RETURN p",
    },
    "find_paths_from_entra_to_tier_zero": {
        "description": "Find paths from Entra principals to on-prem tier zero",
        "category": "azure",
        "cypher": "MATCH p=shortestPath((s:AZUser)-[r*1..]->(t)) WHERE t.highvalue=true RETURN p LIMIT 1000",
    },
}

# ── Connection state ─────────────────────────────────────────────────

_graph_driver: Any | None = None
_api_token: dict | None = None
_config: dict[str, str] = {}


def _default_config() -> dict[str, str]:
    return {
        "bloodhound_url": os.environ.get("BLOODHOUND_URL", "http://localhost:8080"),
        "username": os.environ.get("BLOODHOUND_USERNAME", "admin"),
        "password": os.environ.get("BLOODHOUND_PASSWORD", ""),
        "neo4j_url": os.environ.get("NEO4J_URL", "bolt://localhost:7687"),
        "neo4j_username": os.environ.get("NEO4J_USERNAME", "neo4j"),
        "neo4j_password": os.environ.get("NEO4J_PASSWORD", "bloodhoundcommunityedition"),
        "neo4j_database": os.environ.get("NEO4J_DATABASE", "neo4j"),
    }


async def _ensure_connected() -> None:
    global _graph_driver, _api_token, _config
    if _graph_driver is not None:
        return
    if not _config:
        _config = _default_config()
    if not _config["password"]:
        raise RuntimeError("Not connected. Call connect(password=...) or set BLOODHOUND_PASSWORD env var.")
    _graph_driver = AsyncGraphDatabase.driver(
        _config["neo4j_url"],
        auth=(_config["neo4j_username"], _config["neo4j_password"]),
    )
    # Verify Neo4j
    async with _graph_driver.session(database=_config["neo4j_database"]) as session:
        await session.run("RETURN 1")
    # Authenticate to BloodHound API
    async with aiohttp.ClientSession() as http:
        async with http.post(
            f"{_config['bloodhound_url']}/api/v2/login",
            json={"login_method": "secret", "username": _config["username"], "secret": _config["password"]},
        ) as resp:
            result = await resp.json()
    if not result or not isinstance(result.get("data"), dict):
        raise RuntimeError(f"BloodHound API auth failed: {result}")
    _api_token = result["data"]


async def _run_cypher(cypher: str, params: dict | None = None) -> list[dict]:
    await _ensure_connected()
    assert _graph_driver is not None
    records = []
    async with _graph_driver.session(database=_config["neo4j_database"]) as session:
        result = await session.run(cypher, params or {})
        async for record in result:
            records.append(dict(record))
    return records


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool
async def connect(
    bloodhound_url: Annotated[str | None, "BloodHound CE URL (e.g. http://localhost:8080)"] = None,
    username: Annotated[str | None, "BloodHound username"] = None,
    password: Annotated[str | None, "BloodHound password"] = None,
    neo4j_url: Annotated[str | None, "Neo4j bolt URL"] = None,
    neo4j_username: Annotated[str | None, "Neo4j username"] = None,
    neo4j_password: Annotated[str | None, "Neo4j password"] = None,
) -> str:
    """Connect to BloodHound CE and Neo4j. Overrides env var defaults for this session."""
    global _graph_driver, _api_token, _config
    if _graph_driver is not None:
        await _graph_driver.close()
    _graph_driver = None
    _api_token = None
    _config = _default_config()
    if bloodhound_url:
        _config["bloodhound_url"] = bloodhound_url
    if username:
        _config["username"] = username
    if password:
        _config["password"] = password
    if neo4j_url:
        _config["neo4j_url"] = neo4j_url
    if neo4j_username:
        _config["neo4j_username"] = neo4j_username
    if neo4j_password:
        _config["neo4j_password"] = neo4j_password
    await _ensure_connected()
    return f"Connected to BloodHound at {_config['bloodhound_url']} + Neo4j at {_config['neo4j_url']}"


@mcp.tool
async def query(
    cypher: Annotated[str, "Cypher query to execute against the BloodHound graph"],
    params: Annotated[dict | None, "Query parameters"] = None,
) -> list[dict]:
    """Execute an arbitrary Cypher query against the BloodHound Neo4j database."""
    return await _run_cypher(cypher, params)


@mcp.tool
async def standard_query(
    name: Annotated[str, "Name of the standard query (e.g. find_all_domain_admins)"],
) -> list[dict]:
    """Run a named standard query from the built-in catalog."""
    entry = STANDARD_QUERIES.get(name)
    if entry is None:
        available = ", ".join(sorted(STANDARD_QUERIES.keys()))
        raise ValueError(f"Unknown query '{name}'. Available: {available}")
    return await _run_cypher(entry["cypher"])


@mcp.tool
async def list_queries(
    category: Annotated[str | None, "Filter by category (e.g. kerberos, pki, tier-zero, azure)"] = None,
) -> list[dict]:
    """List available standard queries with descriptions. Optionally filter by category."""
    results = []
    for name, entry in sorted(STANDARD_QUERIES.items()):
        if category and entry["category"] != category:
            continue
        results.append(
            {
                "name": name,
                "description": entry["description"],
                "category": entry["category"],
            }
        )
    if not results and category:
        categories = sorted({e["category"] for e in STANDARD_QUERIES.values()})
        return [{"error": f"No queries in category '{category}'", "available_categories": categories}]
    return results


if __name__ == "__main__":
    mcp.run(transport="stdio")
