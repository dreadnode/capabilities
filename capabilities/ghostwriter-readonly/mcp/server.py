#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "aiohttp>=3.9,<4.0",
#   "pydantic>=2.0,<3.0",
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
from typing import Annotated, Literal, TypeAlias, TypedDict, TypeVar

import aiohttp
from fastmcp import FastMCP
from gql import Client, gql as gql_parse
from gql.client import AsyncClientSession
from gql.transport.aiohttp import AIOHTTPTransport
from pydantic import BaseModel, Field, JsonValue, ValidationInfo, field_validator, model_validator


# ── Type aliases ─────────────────────────────────────────────────────

# GraphQL variables: all values we send to Hasura are ints (IDs / limits /
# offsets) or strings (search terms, severities, ilike patterns).
GqlVariables: TypeAlias = dict[str, int | str]
JsonObject: TypeAlias = dict[str, JsonValue]


class GhostwriterConfig(TypedDict):
    """Connection config loaded from environment variables."""

    url: str
    api_token: str
    username: str
    password: str


# ── Pydantic model base ──────────────────────────────────────────────


class _GWBase(BaseModel):
    """Base model that coerces ``None`` -> a type-appropriate zero value.

    GhostWriter's Hasura API returns null for many optional columns regardless
    of the declared SQL type. We swap nulls for ``""``/``0``/``False`` on
    primitive fields so every row validates cleanly.
    """

    @field_validator("*", mode="before")
    @classmethod
    def _coerce_null(cls, v: JsonValue, info: ValidationInfo) -> JsonValue:
        if v is not None:
            return v
        name = info.field_name
        if name is None:
            return v
        annotation = cls.model_fields[name].annotation
        if annotation is str:
            return ""
        if annotation is bool:
            return False
        if annotation is int:
            return 0
        if annotation is float:
            return 0.0
        return v


class AggregateCount(BaseModel):
    """Flattens Hasura's ``{aggregate: {count: N}}`` wrapper into a plain count."""

    count: int = 0

    @model_validator(mode="before")
    @classmethod
    def _flatten(cls, data: JsonValue) -> JsonValue:
        if isinstance(data, dict) and "aggregate" in data:
            aggregate = data["aggregate"]
            if isinstance(aggregate, dict):
                return {"count": aggregate.get("count", 0)}
        return data


# ── Reference (enum-like) types ──────────────────────────────────────


class ProjectTypeRef(_GWBase):
    projectType: str = ""


class SeverityRef(_GWBase):
    severity: str = ""


class FindingTypeRef(_GWBase):
    findingType: str = ""


class ActivityTypeRef(_GWBase):
    activity: str = ""


class ServerRoleRef(_GWBase):
    serverRole: str = ""


class ServerProviderRef(_GWBase):
    serverProvider: str = ""


class HealthStatusRef(_GWBase):
    healthStatus: str = ""


class ObjectivePriorityRef(_GWBase):
    priority: str = ""


class ObjectiveStatusRef(_GWBase):
    objectiveStatus: str = ""


class DeconflictionStatusRef(_GWBase):
    status: str = ""


# ── Composite reference types (nested lookups) ───────────────────────


class ClientRef(_GWBase):
    id: int = 0
    name: str = ""
    shortName: str = ""


class ProjectRef(_GWBase):
    id: int = 0
    codename: str = ""
    client: ClientRef | None = None


class ReportRef(_GWBase):
    id: int = 0
    title: str = ""
    project: ProjectRef | None = None


class ServerRef(_GWBase):
    id: int = 0
    ipAddress: str = ""
    name: str = ""
    serverProvider: ServerProviderRef | None = None


class DomainRef(_GWBase):
    id: int = 0
    name: str = ""
    registrar: str = ""
    creation: str = ""
    expiration: str = ""
    healthStatus: HealthStatusRef | None = None


class OplogRef(_GWBase):
    name: str = ""
    project: ProjectRef | None = None


class UserRef(_GWBase):
    id: int = 0
    username: str = ""
    name: str = ""


# ── Row models returned by tools ─────────────────────────────────────


class Status(BaseModel):
    url: str
    auth_method: Literal["API token", "JWT login"]
    clients: int
    projects: int
    findings: int


class ClientSummary(_GWBase):
    id: int = 0
    name: str = ""
    shortName: str = ""
    description: str = ""
    projects_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class ClientProjectRef(_GWBase):
    id: int = 0
    codename: str = ""
    projectType: ProjectTypeRef | None = None
    startDate: str = ""
    endDate: str = ""
    complete: bool = False


class ClientDetail(_GWBase):
    id: int = 0
    name: str = ""
    shortName: str = ""
    description: str = ""
    codename: str = ""
    address: str = ""
    timezone: str = ""
    projects: list[ClientProjectRef] = Field(default_factory=list)


class ProjectSummary(_GWBase):
    id: int = 0
    codename: str = ""
    complete: bool = False
    description: str = ""
    startDate: str = ""
    endDate: str = ""
    projectType: ProjectTypeRef | None = None
    client: ClientRef | None = None
    reports_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class ProjectReportFinding(_GWBase):
    id: int = 0
    title: str = ""
    severity: SeverityRef | None = None
    affectedEntities: str = ""


class ProjectReport(_GWBase):
    id: int = 0
    title: str = ""
    complete: bool = False
    delivered: bool = False
    creation: str = ""
    findings: list[ProjectReportFinding] = Field(default_factory=list)


class ProjectOplog(_GWBase):
    id: int = 0
    name: str = ""


class ProjectDetail(_GWBase):
    id: int = 0
    codename: str = ""
    complete: bool = False
    description: str = ""
    slackChannel: str = ""
    startDate: str = ""
    endDate: str = ""
    projectType: ProjectTypeRef | None = None
    client: ClientRef | None = None
    reports: list[ProjectReport] = Field(default_factory=list)
    oplogs: list[ProjectOplog] = Field(default_factory=list)


class FindingSummary(_GWBase):
    id: int = 0
    title: str = ""
    affectedEntities: str = ""
    complete: bool = False
    severity: SeverityRef | None = None
    findingType: FindingTypeRef | None = None
    report: ReportRef | None = None


class FindingEvidenceRef(_GWBase):
    id: int = 0
    document: str = ""


class FindingDetail(_GWBase):
    id: int = 0
    title: str = ""
    position: int = 0
    complete: bool = False
    affectedEntities: str = ""
    description: str = ""
    impact: str = ""
    mitigation: str = ""
    replication_steps: str = ""
    hostDetectionTechniques: str = ""
    networkDetectionTechniques: str = ""
    references: str = ""
    findingGuidance: str = ""
    cvssScore: float = 0.0
    cvssVector: str = ""
    severity: SeverityRef | None = None
    findingType: FindingTypeRef | None = None
    report: ReportRef | None = None
    evidences: list[FindingEvidenceRef] = Field(default_factory=list)


class FindingTemplate(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    severity: SeverityRef | None = None
    type: FindingTypeRef | None = None


class ObjectiveSubTask(_GWBase):
    id: int = 0
    task: str = ""
    complete: bool = False
    deadline: str = ""
    objectiveStatus: ObjectiveStatusRef | None = None


class Objective(_GWBase):
    id: int = 0
    objective: str = ""
    description: str = ""
    complete: bool = False
    deadline: str = ""
    position: int = 0
    result: str = ""
    objectivePriority: ObjectivePriorityRef | None = None
    objectiveStatus: ObjectiveStatusRef | None = None
    project: ProjectRef | None = None
    objectiveSubTasks: list[ObjectiveSubTask] = Field(default_factory=list)


class Target(_GWBase):
    id: int = 0
    hostname: str = ""
    ipAddress: str = ""
    description: str = ""
    compromised: bool = False
    project: ProjectRef | None = None


class Scope(_GWBase):
    id: int = 0
    name: str = ""
    scope: str = ""
    description: str = ""
    disallowed: bool = False
    requiresCaution: bool = False
    project: ProjectRef | None = None


class Deconfliction(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    alertSource: str = ""
    alertTimestamp: str = ""
    reportTimestamp: str = ""
    responseTimestamp: str = ""
    deconflictionStatus: DeconflictionStatusRef | None = None
    project: ProjectRef | None = None


class EvidenceFindingRef(_GWBase):
    id: int = 0
    title: str = ""
    severity: SeverityRef | None = None


class Evidence(_GWBase):
    id: int = 0
    friendlyName: str = ""
    caption: str = ""
    description: str = ""
    document: str = ""
    uploadDate: str = ""
    finding: EvidenceFindingRef | None = None
    report: ReportRef | None = None


class Whitecard(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    issued: str = ""
    project: ProjectRef | None = None


class Observation(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    complete: bool = False
    report: ReportRef | None = None


class Report(_GWBase):
    id: int = 0
    title: str = ""
    complete: bool = False
    archived: bool = False
    creation: str = ""
    delivered: bool = False
    project: ProjectRef | None = None
    findings_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class ServerCheckout(_GWBase):
    id: int = 0
    description: str = ""
    startDate: str = ""
    endDate: str = ""
    activityType: ActivityTypeRef | None = None
    serverRole: ServerRoleRef | None = None
    server: ServerRef | None = None
    project: ProjectRef | None = None


class DomainCheckout(_GWBase):
    id: int = 0
    description: str = ""
    startDate: str = ""
    endDate: str = ""
    activityType: ActivityTypeRef | None = None
    domain: DomainRef | None = None
    project: ProjectRef | None = None


class Infrastructure(BaseModel):
    servers: list[ServerCheckout] = Field(default_factory=list)
    domains: list[DomainCheckout] = Field(default_factory=list)


class ActivityLog(_GWBase):
    id: int = 0
    tool: str = ""
    userContext: str = ""
    command: str = ""
    comments: str = ""
    output: str = ""
    sourceIp: str = ""
    destIp: str = ""
    startDate: str = ""
    endDate: str = ""
    operatorName: str = ""
    log: OplogRef | None = None


class Note(_GWBase):
    id: int = 0
    note: str = ""
    timestamp: str = ""
    user: UserRef | None = None


class SearchResult(BaseModel):
    clients: list[ClientSummary] = Field(default_factory=list)
    projects: list[ProjectSummary] = Field(default_factory=list)
    findings: list[FindingSummary] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    activity_logs: list[ActivityLog] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


# ── FastMCP setup ────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Connect to GhostWriter at startup; fail fast if credentials are bad."""
    await _ensure_connected()
    yield
    if _gql_client is not None:
        await _gql_client.close_async()


mcp = FastMCP("ghostwriter", lifespan=_lifespan)

GRAPHQL_PATH = "/v1/graphql"

NoteType = Literal["client", "project", "domain", "server"]

_NOTE_TABLES: dict[NoteType, tuple[str, str]] = {
    "client": ("clientNote", "clientId"),
    "project": ("projectNote", "projectId"),
    "domain": ("domainNote", "domainId"),
    "server": ("serverNote", "serverId"),
}


# ── Connection state ────────────────────────────────────────────────

_gql_client: Client | None = None
_gql_session: AsyncClientSession | None = None
_config: GhostwriterConfig | None = None


@functools.lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _default_config() -> GhostwriterConfig:
    return GhostwriterConfig(
        url=os.environ.get("GHOSTWRITER_URL", "").rstrip("/"),
        api_token=os.environ.get("GHOSTWRITER_API_TOKEN", ""),
        username=os.environ.get("GHOSTWRITER_USERNAME", ""),
        password=os.environ.get("GHOSTWRITER_PASSWORD", ""),
    )


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
            token = data.get("data", {}).get("login", {}).get("token")
            if not isinstance(token, str) or not token:
                raise RuntimeError(f"GhostWriter login response missing token: {json.dumps(data)}")
            return token


async def _ensure_connected() -> AsyncClientSession:
    global _gql_client, _gql_session, _config
    if _gql_session is not None:
        return _gql_session
    if _config is None:
        _config = _default_config()
    if not _config["url"]:
        raise RuntimeError("GHOSTWRITER_URL env var is required.")
    if not _config["api_token"] and not (_config["username"] and _config["password"]):
        raise RuntimeError(
            "Set GHOSTWRITER_API_TOKEN or both " "GHOSTWRITER_USERNAME and GHOSTWRITER_PASSWORD env vars."
        )

    token = _config["api_token"] or await _login_jwt(_config["url"], _config["username"], _config["password"])
    transport = AIOHTTPTransport(
        url=f"{_config['url']}{GRAPHQL_PATH}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        ssl=_ssl_context(),
    )
    client = Client(transport=transport, fetch_schema_from_transport=False)
    session = await client.connect_async(reconnecting=True)
    # Verify credentials actually work before declaring success
    try:
        await session.execute(gql_parse("{ client_aggregate { aggregate { count } } }"))
    except Exception as exc:
        await client.close_async()
        raise RuntimeError(f"GhostWriter authentication failed: {exc}") from exc

    _gql_client = client
    _gql_session = session
    return _gql_session


async def _run_query(query: str, variables: GqlVariables | None = None) -> JsonObject:
    session = await _ensure_connected()
    result = await session.execute(gql_parse(query), variable_values=variables)
    return result if isinstance(result, dict) else {}


# ── Helpers ──────────────────────────────────────────────────────────


T = TypeVar("T", bound=_GWBase)


def _parse_rows(model: type[T], result: JsonObject, key: str) -> list[T]:
    """Parse a GraphQL result's row list into a list of Pydantic models."""
    value = result.get(key)
    if not isinstance(value, list):
        return []
    return [model.model_validate(row) for row in value if isinstance(row, dict)]


def _parse_row(model: type[T], result: JsonObject, key: str) -> T | None:
    """Parse a single row from a GraphQL ``_by_pk`` style result, or None."""
    value = result.get(key)
    return model.model_validate(value) if isinstance(value, dict) else None


class _Filter(TypedDict):
    """A single optional Hasura filter: predicate fragment and variable value."""

    predicate: str
    value: int | str | None


def _build_where(filters: dict[str, _Filter]) -> tuple[str, str, GqlVariables]:
    """Build dynamic Hasura where-clause fragments.

    ``filters`` maps each variable name to a ``_Filter``. The predicate is
    included (and the variable declared) only when its value is not None.

    Returns ``(where_fragment, decls_fragment, variables)`` where:

    - ``where_fragment`` is ``""`` or ``", where: {...}"`` (ready to
      append to an existing argument list).
    - ``decls_fragment`` is ``""`` or starts with ``", "`` (ready to
      append to the query parameter list).
    """
    conditions: list[str] = []
    variables: GqlVariables = {}
    decls: list[str] = []
    for var_name, flt in filters.items():
        value = flt["value"]
        if value is None:
            continue
        conditions.append(flt["predicate"])
        variables[var_name] = value
        gql_type = "bigint" if isinstance(value, int) else "String"
        decls.append(f"${var_name}: {gql_type}")
    where = f", where: {{{', '.join(conditions)}}}" if conditions else ""
    decls_fragment = ", " + ", ".join(decls) if decls else ""
    return where, decls_fragment, variables


# ── Tools ───────────────────────────────────────────────────────────


@mcp.tool
async def get_status() -> Status:
    """Check connection status and return aggregate counts of clients, projects, and findings."""
    await _ensure_connected()
    assert _config is not None  # set by _ensure_connected
    result = await _run_query(
        """
        query StatusCheck {
            client_aggregate { aggregate { count } }
            project_aggregate { aggregate { count } }
            reportedFinding_aggregate { aggregate { count } }
        }
        """
    )
    return Status(
        url=_config["url"],
        auth_method="API token" if _config["api_token"] else "JWT login",
        clients=AggregateCount.model_validate(result.get("client_aggregate", {})).count,
        projects=AggregateCount.model_validate(result.get("project_aggregate", {})).count,
        findings=AggregateCount.model_validate(result.get("reportedFinding_aggregate", {})).count,
    )


# ── Clients ─────────────────────────────────────────────────────────


@mcp.tool
async def list_clients(
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[ClientSummary]:
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
    return _parse_rows(ClientSummary, result, "client")


@mcp.tool
async def get_client(
    id: Annotated[int, "Client ID"],
) -> ClientDetail | None:
    """Get full details for a single client including associated projects.

    Returns None if no client with the given ID exists.
    """
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
    return _parse_row(ClientDetail, result, "client_by_pk")


# ── Projects ────────────────────────────────────────────────────────


@mcp.tool
async def list_projects(
    client_id: Annotated[int | None, "Filter by client ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[ProjectSummary]:
    """List projects/engagements."""
    where, decls, variables = _build_where(
        {
            "clientId": {"predicate": "clientId: {_eq: $clientId}", "value": client_id},
        }
    )
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllProjects($limit: Int!{decls}) {{
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
    return _parse_rows(ProjectSummary, result, "project")


@mcp.tool
async def get_project(
    id: Annotated[int, "Project ID"],
) -> ProjectDetail | None:
    """Get full project details with associated findings, reports, and oplogs.

    Returns None if no project with the given ID exists.
    """
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
    return _parse_row(ProjectDetail, result, "project_by_pk")


# ── Findings ────────────────────────────────────────────────────────


@mcp.tool
async def list_findings(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    severity: Annotated[str | None, "Filter by severity (e.g. Critical, High)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[FindingSummary]:
    """List reported findings across engagements."""
    where, decls, variables = _build_where(
        {
            "projectId": {
                "predicate": "report: {projectId: {_eq: $projectId}}",
                "value": project_id,
            },
            "severity": {
                "predicate": "severity: {severity: {_ilike: $severity}}",
                "value": severity,
            },
        }
    )
    variables["limit"] = limit
    variables["offset"] = offset
    result = await _run_query(
        f"""
        query AllFindings($limit: Int!, $offset: Int!{decls}) {{
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
    return _parse_rows(FindingSummary, result, "reportedFinding")


@mcp.tool
async def get_finding(
    id: Annotated[int, "Finding ID"],
) -> FindingDetail | None:
    """Get full finding details including CVSS, remediation, and evidence.

    Returns None if no finding with the given ID exists.
    """
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
    return _parse_row(FindingDetail, result, "reportedFinding_by_pk")


@mcp.tool
async def list_finding_templates(
    severity: Annotated[str | None, "Filter by severity (e.g. Critical, High)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[FindingTemplate]:
    """List the finding template library."""
    where, decls, variables = _build_where(
        {
            "severity": {
                "predicate": "severity: {severity: {_ilike: $severity}}",
                "value": severity,
            },
        }
    )
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllFindingTemplates($limit: Int!{decls}) {{
            finding(order_by: {{severityId: asc, id: desc}}, limit: $limit{where}) {{
                id, title, description,
                severity {{ severity }},
                type {{ findingType }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(FindingTemplate, result, "finding")


# ── Objectives / Targets / Scope ────────────────────────────────────


def _project_filter(project_id: int | None) -> dict[str, _Filter]:
    """Standard single-filter ``projectId: {_eq: $projectId}`` helper."""
    return {
        "projectId": {"predicate": "projectId: {_eq: $projectId}", "value": project_id},
    }


@mcp.tool
async def list_objectives(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Objective]:
    """List project objectives and their sub-tasks."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllObjectives($limit: Int!{decls}) {{
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
    return _parse_rows(Objective, result, "objective")


@mcp.tool
async def list_targets(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Target]:
    """List target hosts and systems."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllTargets($limit: Int!{decls}) {{
            target(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, hostname, ipAddress, description, compromised,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Target, result, "target")


@mcp.tool
async def list_scope(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Scope]:
    """List scope definitions (IP ranges, domains, etc.)."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllScope($limit: Int!{decls}) {{
            scope(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, name, scope, description, disallowed, requiresCaution,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Scope, result, "scope")


# ── Deconflictions / Evidence / Whitecards ──────────────────────────


@mcp.tool
async def list_deconflictions(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Deconfliction]:
    """List deconfliction entries."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllDeconflictions($limit: Int!{decls}) {{
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
    return _parse_rows(Deconfliction, result, "deconfliction")


@mcp.tool
async def list_evidence(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    finding_id: Annotated[int | None, "Filter by finding ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Evidence]:
    """List evidence files."""
    where, decls, variables = _build_where(
        {
            "projectId": {
                "predicate": "report: {projectId: {_eq: $projectId}}",
                "value": project_id,
            },
            "findingId": {
                "predicate": "findingId: {_eq: $findingId}",
                "value": finding_id,
            },
        }
    )
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllEvidence($limit: Int!{decls}) {{
            evidence(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, friendlyName, caption, description, document, uploadDate,
                finding {{ id, title, severity {{ severity }} }},
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Evidence, result, "evidence")


@mcp.tool
async def list_whitecards(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Whitecard]:
    """List white cards / exceptions."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllWhitecards($limit: Int!{decls}) {{
            whitecard(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, description, issued,
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Whitecard, result, "whitecard")


# ── Observations / Reports ──────────────────────────────────────────


@mcp.tool
async def list_observations(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[Observation]:
    """List observations/notes from reports."""
    where, decls, variables = _build_where(
        {
            "projectId": {
                "predicate": "report: {projectId: {_eq: $projectId}}",
                "value": project_id,
            },
        }
    )
    variables["limit"] = limit
    variables["offset"] = offset
    result = await _run_query(
        f"""
        query AllObservations($limit: Int!, $offset: Int!{decls}) {{
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
    return _parse_rows(Observation, result, "reporting_reportobservationlink")


@mcp.tool
async def list_reports(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Report]:
    """List reports."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllReports($limit: Int!{decls}) {{
            report(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, complete, archived, creation, delivered,
                project {{ id, codename, client {{ name }} }},
                findings_aggregate {{ aggregate {{ count }} }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Report, result, "report")


# ── Infrastructure / Servers / Domains ──────────────────────────────


@mcp.tool
async def get_infrastructure(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results per category"] = 50,
) -> Infrastructure:
    """Get a summary of team servers and domains (combined view)."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query Infrastructure($limit: Int!{decls}) {{
            serverCheckout(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                serverRole {{ serverRole }},
                server {{ id, ipAddress, name }},
                project {{ id, codename }}
            }}
            domainCheckout(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                domain {{ id, name }},
                project {{ id, codename }}
            }}
        }}
        """,
        variables,
    )
    return Infrastructure(
        servers=_parse_rows(ServerCheckout, result, "serverCheckout"),
        domains=_parse_rows(DomainCheckout, result, "domainCheckout"),
    )


@mcp.tool
async def list_servers(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[ServerCheckout]:
    """List team servers with checkout details."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllServers($limit: Int!{decls}) {{
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
    return _parse_rows(ServerCheckout, result, "serverCheckout")


@mcp.tool
async def list_domains(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[DomainCheckout]:
    """List registered domains with checkout details."""
    where, decls, variables = _build_where(_project_filter(project_id))
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query AllDomains($limit: Int!{decls}) {{
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
    return _parse_rows(DomainCheckout, result, "domainCheckout")


# ── Activity Logs ───────────────────────────────────────────────────


@mcp.tool
async def list_activity_logs(
    project_id: Annotated[int | None, "Filter by project ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[ActivityLog]:
    """List operation activity logs (oplog entries)."""
    where, decls, variables = _build_where(
        {
            "projectId": {
                "predicate": "log: {project: {id: {_eq: $projectId}}}",
                "value": project_id,
            },
        }
    )
    variables["limit"] = limit
    variables["offset"] = offset
    result = await _run_query(
        f"""
        query AllActivityLogs($limit: Int!, $offset: Int!{decls}) {{
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
    return _parse_rows(ActivityLog, result, "oplogEntry")


# ── Notes ───────────────────────────────────────────────────────────


@mcp.tool
async def list_notes(
    note_type: Annotated[NoteType, "Note type: client, project, domain, or server"],
    parent_id: Annotated[int | None, "Filter by parent entity ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Note]:
    """List notes for a given entity type (client, project, domain, or server)."""
    table, fk_field = _NOTE_TABLES[note_type]
    where, decls, variables = _build_where(
        {
            "parentId": {
                "predicate": f"{fk_field}: {{_eq: $parentId}}",
                "value": parent_id,
            },
        }
    )
    variables["limit"] = limit
    result = await _run_query(
        f"""
        query ListNotes($limit: Int!{decls}) {{
            {table}(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, note, timestamp,
                user {{ id, username, name }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Note, result, table)


# ── Search ──────────────────────────────────────────────────────────

SearchType = Literal["clients", "projects", "findings", "observations", "activity-logs"]


# Search dispatch: maps the user-facing name to the GraphQL query, the response
# root key, the Pydantic model, and the ``SearchResult`` field to assign rows
# into. Adding a new search category is one table entry plus a field on
# ``SearchResult``.
class _SearchEntry(TypedDict):
    query: str
    root: str
    model: type[_GWBase]
    field: str


_SEARCH_QUERIES: dict[SearchType, _SearchEntry] = {
    "clients": {
        "query": """
            query SearchClients($s: String!, $l: Int!) {
                client(where: {_or: [
                    {name: {_ilike: $s}}, {shortName: {_ilike: $s}},
                    {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, name, shortName, description,
                    projects_aggregate { aggregate { count } }
                }
            }
        """,
        "root": "client",
        "model": ClientSummary,
        "field": "clients",
    },
    "projects": {
        "query": """
            query SearchProjects($s: String!, $l: Int!) {
                project(where: {_or: [
                    {codename: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, codename, complete, description,
                    startDate, endDate,
                    projectType { projectType },
                    client { id, name },
                    reports_aggregate { aggregate { count } }
                }
            }
        """,
        "root": "project",
        "model": ProjectSummary,
        "field": "projects",
    },
    "findings": {
        "query": """
            query SearchFindings($s: String!, $l: Int!) {
                reportedFinding(where: {_or: [
                    {title: {_ilike: $s}}, {description: {_ilike: $s}},
                    {affectedEntities: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, title, affectedEntities, complete,
                    severity { severity },
                    findingType { findingType },
                    report { id, title, project { id, codename } }
                }
            }
        """,
        "root": "reportedFinding",
        "model": FindingSummary,
        "field": "findings",
    },
    "observations": {
        "query": """
            query SearchObservations($s: String!, $l: Int!) {
                reporting_reportobservationlink(where: {_or: [
                    {title: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, title, description, complete,
                    report { id, title, project { id, codename } }
                }
            }
        """,
        "root": "reporting_reportobservationlink",
        "model": Observation,
        "field": "observations",
    },
    "activity-logs": {
        "query": """
            query SearchLogs($s: String!, $l: Int!) {
                oplogEntry(where: {_or: [
                    {command: {_ilike: $s}}, {output: {_ilike: $s}},
                    {comments: {_ilike: $s}}, {tool: {_ilike: $s}}
                ]}, order_by: {startDate: desc}, limit: $l) {
                    id, tool, userContext, command, comments, output,
                    sourceIp, destIp, startDate, endDate, operatorName,
                    log { name, project { codename } }
                }
            }
        """,
        "root": "oplogEntry",
        "model": ActivityLog,
        "field": "activity_logs",
    },
}


def _valid_search_types(raw: str | None) -> set[SearchType]:
    """Parse and validate the user-supplied comma-separated type filter."""
    all_types: set[SearchType] = set(_SEARCH_QUERIES)
    if raw is None:
        return all_types
    requested = {name.strip() for name in raw.split(",")}
    return {t for t in all_types if t in requested}


@mcp.tool
async def search(
    query: Annotated[str, "Search term"],
    types: Annotated[
        str | None,
        "Comma-separated types to search (clients,projects,findings,observations,activity-logs). Default: all",
    ] = None,
    limit: Annotated[int, "Maximum results per type"] = 10,
) -> SearchResult:
    """Search across clients, projects, findings, observations, and activity logs concurrently."""
    variables: GqlVariables = {"s": f"%{query}%", "l": limit}
    selected = sorted(_valid_search_types(types))
    raw = await asyncio.gather(
        *(_run_query(_SEARCH_QUERIES[key]["query"], variables) for key in selected),
        return_exceptions=True,
    )

    out = SearchResult()
    for key, r in zip(selected, raw):
        if isinstance(r, BaseException):
            out.errors[key] = str(r)
            continue
        if not isinstance(r, dict):
            continue
        entry = _SEARCH_QUERIES[key]
        rows = _parse_rows(entry["model"], r, entry["root"])
        setattr(out, entry["field"], rows)
    return out


if __name__ == "__main__":
    mcp.run(transport="stdio")
