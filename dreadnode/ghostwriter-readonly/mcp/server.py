#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "aiohttp>=3.9,<4.0",
# ]
# ///
"""Read-only GhostWriter MCP server — query engagement data without modifying state.

Credentials are read from the server's environment so they never appear in conversations.

Env vars:
    GHOSTWRITER_URL         (required, e.g. https://10.2.10.100)
    GHOSTWRITER_API_TOKEN   (preferred auth method)
    GHOSTWRITER_USERNAME    (for JWT login fallback)
    GHOSTWRITER_PASSWORD    (for JWT login fallback)
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import aiohttp
from fastmcp import FastMCP
from gql import Client, gql as gql_parse
from gql.client import AsyncClientSession
from gql.transport.aiohttp import AIOHTTPTransport


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Connect to GhostWriter at startup; fail fast if credentials are bad."""
    await _ensure_connected()
    yield


mcp = FastMCP("ghostwriter", lifespan=_lifespan)

GRAPHQL_PATH = "/v1/graphql"

# ── Connection state ────────────────────────────────────────────────

_gql_client: Client | None = None
_gql_session: AsyncClientSession | None = None
_config: dict[str, str] = {}

NOTE_TABLES: dict[str, tuple[str, str]] = {
    "client": ("clientNote", "clientId"),
    "project": ("projectNote", "projectId"),
    "domain": ("domainNote", "domainId"),
    "server": ("serverNote", "serverId"),
}


@functools.lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _default_config() -> dict[str, str]:
    return {
        "url": os.environ.get("GHOSTWRITER_URL", "").rstrip("/"),
        "api_token": os.environ.get("GHOSTWRITER_API_TOKEN", ""),
        "username": os.environ.get("GHOSTWRITER_USERNAME", ""),
        "password": os.environ.get("GHOSTWRITER_PASSWORD", ""),
    }


async def _login_jwt(base_url: str, username: str, password: str) -> str:
    """Authenticate via GhostWriter's GraphQL login mutation to get a JWT."""
    connector = aiohttp.TCPConnector(ssl=_ssl_context())
    async with aiohttp.ClientSession(connector=connector) as session:
        mutation = {
            "query": (
                "mutation Login($username: String!, $password: String!) {"
                " login(username: $username, password: $password)"
                " { token expires } }"
            ),
            "variables": {"username": username, "password": password},
        }
        async with session.post(f"{base_url}{GRAPHQL_PATH}", json=mutation) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"GhostWriter login failed ({resp.status}): {text}")
            data = await resp.json()
            if "errors" in data:
                raise RuntimeError(f"GhostWriter login error: {json.dumps(data['errors'])}")
            token: str | None = data.get("data", {}).get("login", {}).get("token")
            if not token:
                raise RuntimeError(f"GhostWriter login response missing token: {json.dumps(data)}")
            return token


async def _ensure_connected() -> None:
    global _gql_client, _gql_session, _config
    if _gql_session is not None:
        return
    if not _config:
        _config = _default_config()
    if not _config["url"]:
        raise RuntimeError(
            "GHOSTWRITER_URL env var is required."
        )
    if not _config["api_token"] and not (_config["username"] and _config["password"]):
        raise RuntimeError(
            "Set GHOSTWRITER_API_TOKEN or both "
            "GHOSTWRITER_USERNAME and GHOSTWRITER_PASSWORD env vars."
        )
    token = _config["api_token"] or await _login_jwt(
        _config["url"], _config["username"], _config["password"]
    )
    transport = AIOHTTPTransport(
        url=f"{_config['url']}{GRAPHQL_PATH}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        ssl=_ssl_context(),
    )
    _gql_client = Client(transport=transport, fetch_schema_from_transport=False)
    _gql_session = await _gql_client.connect_async(reconnecting=True)
    # Verify credentials actually work before declaring success
    try:
        await _gql_session.execute(
            gql_parse("{ client_aggregate { aggregate { count } } }")
        )
    except Exception as exc:
        await _gql_client.close_async()
        _gql_client = None
        _gql_session = None
        raise RuntimeError(f"GhostWriter authentication failed: {exc}") from exc


async def _run_query(
    query: str, variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    await _ensure_connected()
    assert _gql_session is not None
    result = await _gql_session.execute(gql_parse(query), variable_values=variables)
    return result  # type: ignore[return-value]


def _where(
    conditions: list[str], decls: list[str],
) -> tuple[str, str]:
    """Build Hasura where clause and variable declaration fragments."""
    where = f", where: {{{', '.join(conditions)}}}" if conditions else ""
    decl = "".join(f", {d}" for d in decls)
    return where, decl


# ── Tools ───────────────────────────────────────────────────────────


@mcp.tool
async def get_status() -> dict:
    """Check connection status and return aggregate counts of clients, projects, and findings."""
    result = await _run_query("""
        query StatusCheck {
            client_aggregate { aggregate { count } }
            project_aggregate { aggregate { count } }
            reportedFinding_aggregate { aggregate { count } }
        }
    """)
    return {
        "url": _config.get("url", ""),
        "auth_method": "API token" if _config.get("api_token") else "JWT login",
        "clients": result.get("client_aggregate", {}).get("aggregate", {}).get("count", 0),
        "projects": result.get("project_aggregate", {}).get("aggregate", {}).get("count", 0),
        "findings": result.get("reportedFinding_aggregate", {}).get("aggregate", {}).get("count", 0),
    }


# ── Clients ─────────────────────────────────────────────────────────


@mcp.tool
async def list_clients(
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List client organizations."""
    result = await _run_query(
        """
        query AllClients($limit: Int!) {
            client(order_by: {id: desc}, limit: $limit) {
                id, name, shortName, description,
                projects_aggregate { aggregate { count } }
            }
        }
        """,
        {"limit": limit},
    )
    return result.get("client", [])


@mcp.tool
async def get_client(
    id: Annotated[int, "Client ID"],
) -> dict:
    """Get full details for a single client including associated projects."""
    result = await _run_query(
        """
        query ClientDetail($id: bigint!) {
            client_by_pk(id: $id) {
                id, name, shortName, description, codename,
                address, timezone,
                projects(order_by: {id: desc}) {
                    id, codename, projectType { projectType },
                    startDate, endDate, complete
                }
            }
        }
        """,
        {"id": id},
    )
    return result.get("client_by_pk") or {"error": f"No client found with id={id}"}


# ── Projects ────────────────────────────────────────────────────────


@mcp.tool
async def list_projects(
    client_id: Annotated[int | None, "Filter by client ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List projects/engagements."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if client_id is not None:
        conditions.append("clientId: {_eq: $clientId}")
        decls.append("$clientId: bigint")
        variables["clientId"] = client_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllProjects($limit: Int!{decl}) {{
            project(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, codename, complete, description,
                startDate, endDate,
                projectType {{ projectType }},
                client {{ id, name }},
                reports_aggregate {{ aggregate {{ count }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("project", [])


@mcp.tool
async def get_project(
    id: Annotated[int, "Project ID"],
) -> dict:
    """Get full project details with associated findings, reports, and oplogs."""
    result = await _run_query(
        """
        query ProjectDetail($id: bigint!) {
            project_by_pk(id: $id) {
                id, codename, complete, description, slackChannel,
                startDate, endDate,
                projectType { projectType },
                client { id, name, shortName },
                reports {
                    id, title, complete, delivered, creation,
                    findings(order_by: {severityId: asc}) {
                        id, title, severity { severity }, affectedEntities
                    }
                },
                oplogs { id, name }
            }
        }
        """,
        {"id": id},
    )
    return result.get("project_by_pk") or {"error": f"No project found with id={id}"}


# ── Findings ────────────────────────────────────────────────────────


@mcp.tool
async def list_findings(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    severity: Annotated[str | None, "Filter by severity (e.g. Critical, High)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List reported findings across engagements."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit, "offset": offset}
    if project_id is not None:
        conditions.append("report: {projectId: {_eq: $projectId}}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    if severity is not None:
        conditions.append("severity: {severity: {_ilike: $severity}}")
        decls.append("$severity: String")
        variables["severity"] = severity
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllFindings($limit: Int!, $offset: Int!{decl}) {{
            reportedFinding(
                order_by: {{severityId: asc, id: desc}},
                limit: $limit, offset: $offset{where}
            ) {{
                id, title, affectedEntities, complete,
                severity {{ severity }},
                findingType {{ findingType }},
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("reportedFinding", [])


@mcp.tool
async def get_finding(
    id: Annotated[int, "Finding ID"],
) -> dict:
    """Get full finding details including CVSS, remediation, and evidence."""
    result = await _run_query(
        """
        query FindingDetail($id: bigint!) {
            reportedFinding_by_pk(id: $id) {
                id, title, position, complete,
                affectedEntities, description, impact, mitigation,
                replication_steps, hostDetectionTechniques,
                networkDetectionTechniques, references, findingGuidance,
                cvssScore, cvssVector,
                severity { severity },
                findingType { findingType },
                report { id, title, project { id, codename, client { name } } },
                evidences { id, document }
            }
        }
        """,
        {"id": id},
    )
    return result.get("reportedFinding_by_pk") or {"error": f"No finding found with id={id}"}


@mcp.tool
async def list_finding_templates(
    severity: Annotated[str | None, "Filter by severity (e.g. Critical, High)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List the finding template library."""
    variables: dict[str, Any] = {"limit": limit}
    decls: list[str] = []
    where = ""
    if severity is not None:
        where = ", where: {severity: {severity: {_ilike: $severity}}}"
        decls.append("$severity: String")
        variables["severity"] = severity
    decl = "".join(f", {d}" for d in decls)
    result = await _run_query(
        f"""
        query AllFindingTemplates($limit: Int!{decl}) {{
            finding(order_by: {{severityId: asc, id: desc}}, limit: $limit{where}) {{
                id, title, description,
                severity {{ severity }},
                type {{ findingType }}
            }}
        }}
        """,
        variables,
    )
    return result.get("finding", [])


# ── Objectives / Targets / Scope ────────────────────────────────────


@mcp.tool
async def list_objectives(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List project objectives and their sub-tasks."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllObjectives($limit: Int!{decl}) {{
            objective(order_by: {{position: asc, id: desc}}, limit: $limit{where}) {{
                id, objective, description, complete, deadline, position, result,
                objectivePriority {{ priority }},
                objectiveStatus {{ objectiveStatus }},
                project {{ id, codename }},
                objectiveSubTasks(order_by: {{id: asc}}) {{
                    id, task, complete, deadline,
                    objectiveStatus {{ objectiveStatus }}
                }}
            }}
        }}
        """,
        variables,
    )
    return result.get("objective", [])


@mcp.tool
async def list_targets(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List target hosts and systems."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllTargets($limit: Int!{decl}) {{
            target(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, hostname, ipAddress, description, compromised,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("target", [])


@mcp.tool
async def list_scope(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List scope definitions (IP ranges, domains, etc.)."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllScope($limit: Int!{decl}) {{
            scope(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, name, scope, description, disallowed, requiresCaution,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("scope", [])


# ── Deconflictions / Evidence / Whitecards ──────────────────────────


@mcp.tool
async def list_deconflictions(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List deconfliction entries."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllDeconflictions($limit: Int!{decl}) {{
            deconfliction(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, description, alertSource,
                alertTimestamp, reportTimestamp, responseTimestamp,
                deconflictionStatus {{ status }},
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("deconfliction", [])


@mcp.tool
async def list_evidence(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    finding_id: Annotated[int | None, "Filter by finding ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List evidence files."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("report: {projectId: {_eq: $projectId}}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    if finding_id is not None:
        conditions.append("findingId: {_eq: $findingId}")
        decls.append("$findingId: bigint")
        variables["findingId"] = finding_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllEvidence($limit: Int!{decl}) {{
            evidence(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, friendlyName, caption, description, document, uploadDate,
                finding {{ id, title, severity {{ severity }} }},
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("evidence", [])


@mcp.tool
async def list_whitecards(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List white cards / exceptions."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllWhitecards($limit: Int!{decl}) {{
            whitecard(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, description, issued,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("whitecard", [])


# ── Observations / Reports ──────────────────────────────────────────


@mcp.tool
async def list_observations(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List observations/notes from reports."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit, "offset": offset}
    if project_id is not None:
        conditions.append("report: {projectId: {_eq: $projectId}}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllObservations($limit: Int!, $offset: Int!{decl}) {{
            reporting_reportobservationlink(
                order_by: {{id: desc}}, limit: $limit, offset: $offset{where}
            ) {{
                id, title, description, complete,
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("reporting_reportobservationlink", [])


@mcp.tool
async def list_reports(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List reports."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllReports($limit: Int!{decl}) {{
            report(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, complete, archived, creation, delivered,
                project {{ id, codename, client {{ name }} }},
                findings_aggregate {{ aggregate {{ count }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("report", [])


# ── Infrastructure / Servers / Domains ──────────────────────────────


@mcp.tool
async def get_infrastructure(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
) -> dict:
    """Get a summary of team servers and domains (combined view)."""
    variables: dict[str, Any] = {}
    where = ""
    decl = ""
    if project_id is not None:
        where = ", where: {projectId: {_eq: $projectId}}"
        variables["projectId"] = project_id
        decl = "$projectId: bigint"
    query_decl = f"({decl})" if decl else ""
    result = await _run_query(
        f"""
        query Infrastructure{query_decl} {{
            serverCheckout(order_by: {{id: desc}}, limit: 20{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                serverRole {{ serverRole }},
                server {{ id, ipAddress, name }},
                project {{ codename }}
            }}
            domainCheckout(order_by: {{id: desc}}, limit: 20{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                domain {{ name }},
                project {{ codename }}
            }}
        }}
        """,
        variables,
    )
    return {
        "servers": result.get("serverCheckout", []),
        "domains": result.get("domainCheckout", []),
    }


@mcp.tool
async def list_servers(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List team servers with checkout details."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllServers($limit: Int!{decl}) {{
            serverCheckout(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                serverRole {{ serverRole }},
                server {{ id, ipAddress, name,
                          serverProvider {{ serverProvider }} }},
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("serverCheckout", [])


@mcp.tool
async def list_domains(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List registered domains with checkout details."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit}
    if project_id is not None:
        conditions.append("projectId: {_eq: $projectId}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllDomains($limit: Int!{decl}) {{
            domainCheckout(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                domain {{ id, name, registrar, creation, expiration,
                          healthStatus {{ healthStatus }} }},
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return result.get("domainCheckout", [])


# ── Activity Logs ───────────────────────────────────────────────────


@mcp.tool
async def list_activity_logs(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List operation activity logs (oplog entries)."""
    conditions: list[str] = []
    decls: list[str] = []
    variables: dict[str, Any] = {"limit": limit, "offset": offset}
    if project_id is not None:
        conditions.append("log: {project: {id: {_eq: $projectId}}}")
        decls.append("$projectId: bigint")
        variables["projectId"] = project_id
    where, decl = _where(conditions, decls)
    result = await _run_query(
        f"""
        query AllActivityLogs($limit: Int!, $offset: Int!{decl}) {{
            oplogEntry(
                order_by: {{startDate: desc}},
                limit: $limit, offset: $offset{where}
            ) {{
                id, tool, userContext, command, comments, output,
                sourceIp, destIp, startDate, endDate,
                operatorName,
                log {{ name, project {{ codename }} }}
            }}
        }}
        """,
        variables,
    )
    return result.get("oplogEntry", [])


# ── Notes ───────────────────────────────────────────────────────────


@mcp.tool
async def list_notes(
    note_type: Annotated[str, "Note type: client, project, domain, or server"],
    parent_id: Annotated[int | None, "Filter by parent entity ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List notes for a given entity type (client, project, domain, or server)."""
    if note_type not in NOTE_TABLES:
        return [{"error": f"Invalid note_type '{note_type}'. Must be one of: {', '.join(NOTE_TABLES)}"}]
    table, fk_field = NOTE_TABLES[note_type]
    variables: dict[str, Any] = {"limit": limit}
    where = ""
    decl = ""
    if parent_id is not None:
        where = f", where: {{{fk_field}: {{_eq: $parentId}}}}"
        variables["parentId"] = parent_id
        decl = ", $parentId: bigint"
    result = await _run_query(
        f"""
        query AllNotes($limit: Int!{decl}) {{
            {table}(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, note, timestamp,
                user {{ id, username, name }}
            }}
        }}
        """,
        variables,
    )
    return result.get(table, [])


# ── Search ──────────────────────────────────────────────────────────


@mcp.tool
async def search(
    query: Annotated[str, "Search term"],
    types: Annotated[str | None, "Comma-separated types to search (clients,projects,findings,observations,activity-logs). Default: all"] = None,
    limit: Annotated[int, "Maximum results per type"] = 10,
) -> dict:
    """Search across multiple GhostWriter data types."""
    term = f"%{query}%"
    all_types = {"clients", "projects", "findings", "observations", "activity-logs"}
    search_types = set(types.split(",")) if types else all_types

    queries: dict[str, Any] = {}
    if "clients" in search_types:
        queries["clients"] = _run_query(
            """
            query SearchClients($s: String!, $l: Int!) {
                client(where: {_or: [
                    {name: {_ilike: $s}}, {shortName: {_ilike: $s}},
                    {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, name, shortName
                }
            }""",
            {"s": term, "l": limit},
        )
    if "projects" in search_types:
        queries["projects"] = _run_query(
            """
            query SearchProjects($s: String!, $l: Int!) {
                project(where: {_or: [
                    {codename: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, codename, projectType { projectType },
                    client { name }
                }
            }""",
            {"s": term, "l": limit},
        )
    if "findings" in search_types:
        queries["findings"] = _run_query(
            """
            query SearchFindings($s: String!, $l: Int!) {
                reportedFinding(where: {_or: [
                    {title: {_ilike: $s}}, {description: {_ilike: $s}},
                    {affectedEntities: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, title, severity { severity },
                    report { project { codename } }
                }
            }""",
            {"s": term, "l": limit},
        )
    if "observations" in search_types:
        queries["observations"] = _run_query(
            """
            query SearchObservations($s: String!, $l: Int!) {
                reporting_reportobservationlink(where: {_or: [
                    {title: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, title
                }
            }""",
            {"s": term, "l": limit},
        )
    if "activity-logs" in search_types:
        queries["activity-logs"] = _run_query(
            """
            query SearchLogs($s: String!, $l: Int!) {
                oplogEntry(where: {_or: [
                    {command: {_ilike: $s}}, {output: {_ilike: $s}},
                    {comments: {_ilike: $s}}, {tool: {_ilike: $s}}
                ]}, order_by: {startDate: desc}, limit: $l) {
                    id, tool, command, operatorName, startDate
                }
            }""",
            {"s": term, "l": limit},
        )

    gql_keys = {
        "clients": "client",
        "projects": "project",
        "findings": "reportedFinding",
        "observations": "reporting_reportobservationlink",
        "activity-logs": "oplogEntry",
    }

    keys = list(queries.keys())
    raw = await asyncio.gather(*queries.values(), return_exceptions=True)
    results: dict[str, Any] = {}
    for key, r in zip(keys, raw):
        if isinstance(r, BaseException):
            results[key] = [{"error": str(r)}]
        elif isinstance(r, dict):
            results[key] = r.get(gql_keys.get(key, key), [])
        else:
            results[key] = []
    return results


if __name__ == "__main__":
    mcp.run(transport="stdio")
