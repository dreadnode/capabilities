#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "aiohttp>=3.9,<4.0",
#   "pydantic>=2.0,<3.0",
# ]
# ///
"""Read-only GhostWriter query tool — no data modified (except Login for auth).

Usage:
    uv run ghostwriter_read.py <command> [options]

Commands:
    status, clients, client, projects, project, findings, finding,
    finding-templates, objectives, targets, scope, deconflictions,
    evidence, whitecards, observations, reports, infrastructure,
    servers, domains, activity-logs, notes, search

Env vars:
    GHOSTWRITER_URL         (required, e.g. https://10.2.10.100)
    GHOSTWRITER_API_TOKEN   (preferred auth method)
    GHOSTWRITER_USERNAME    (for JWT login)
    GHOSTWRITER_PASSWORD    (for JWT login)
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import json
import os
import ssl
import sys
from collections.abc import Awaitable, Callable
from typing import TypeVar

import aiohttp
from gql import Client, gql as gql_parse
from gql.client import AsyncClientSession
from gql.transport.aiohttp import AIOHTTPTransport
from pydantic import BaseModel, Field, ValidationInfo, field_validator

_T = TypeVar("_T", bound=BaseModel)

GRAPHQL_PATH = "/v1/graphql"


# ── Models ───────────────────────────────────────────────────────────


class _GWBase(BaseModel):
    """Base model that coerces None -> "" for string fields.

    GhostWriter's Hasura API returns null for many optional text columns.
    """

    @field_validator("*", mode="before")
    @classmethod
    def _none_to_empty_str(cls, v: object, info: ValidationInfo) -> object:
        if v is None and info.field_name in cls.model_fields:
            field = cls.model_fields[info.field_name]
            if field.annotation is str:
                return ""
        return v


class AggregateCount(BaseModel):
    aggregate: dict[str, int] = Field(default_factory=dict)

    @property
    def count(self) -> int:
        return self.aggregate.get("count", 0)


class NamedRef(_GWBase):
    """Hasura enum/reference object. `label()` returns the first non-id string."""

    id: int | None = None

    def label(self) -> str:
        for k, v in self.model_dump().items():
            if k != "id" and isinstance(v, str) and v:
                return v
        return ""


class ProjectTypeRef(NamedRef):
    projectType: str = ""


class SeverityRef(NamedRef):
    severity: str = ""


class FindingTypeRef(NamedRef):
    findingType: str = ""


class ActivityTypeRef(NamedRef):
    activity: str = ""


class ServerRoleRef(NamedRef):
    serverRole: str = ""


class ServerProviderRef(NamedRef):
    serverProvider: str = ""


class HealthStatusRef(NamedRef):
    healthStatus: str = ""


class ObjectivePriorityRef(NamedRef):
    priority: str = ""


class ObjectiveStatusRef(NamedRef):
    objectiveStatus: str = ""


class DeconflictionStatusRef(NamedRef):
    status: str = ""


class ClientSummary(_GWBase):
    id: int = 0
    name: str = ""
    shortName: str = ""
    description: str = ""
    projects_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class ClientRef(_GWBase):
    id: int | None = None
    name: str = ""
    shortName: str = ""


class ProjectInList(_GWBase):
    id: int = 0
    codename: str = ""
    complete: bool = False
    description: str = ""
    startDate: str | None = None
    endDate: str | None = None
    projectType: ProjectTypeRef | None = None
    client: ClientRef | None = None
    reports_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class ProjectRef(_GWBase):
    id: int | None = None
    codename: str = ""
    client: ClientRef | None = None


class ReportRef(_GWBase):
    id: int | None = None
    title: str = ""
    project: ProjectRef | None = None


class FindingInList(_GWBase):
    id: int = 0
    title: str = ""
    affectedEntities: str = ""
    complete: bool = False
    severity: SeverityRef | None = None
    findingType: FindingTypeRef | None = None
    report: ReportRef | None = None


class ObservationInList(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    complete: bool = False
    report: ReportRef | None = None


class ReportInList(_GWBase):
    id: int = 0
    title: str = ""
    complete: bool = False
    archived: bool = False
    creation: str | None = None
    delivered: bool = False
    project: ProjectRef | None = None
    findings_aggregate: AggregateCount = Field(default_factory=AggregateCount)


class StaticServerRef(_GWBase):
    id: int | None = None
    ipAddress: str = ""
    name: str = ""
    serverProvider: ServerProviderRef | None = None


class DomainRef(_GWBase):
    id: int | None = None
    name: str = ""
    registrar: str = ""
    creation: str | None = None
    expiration: str | None = None
    healthStatus: HealthStatusRef | None = None


class ServerCheckout(_GWBase):
    id: int = 0
    description: str = ""
    startDate: str | None = None
    endDate: str | None = None
    activityType: ActivityTypeRef | None = None
    serverRole: ServerRoleRef | None = None
    server: StaticServerRef | None = None
    project: ProjectRef | None = None


class DomainCheckout(_GWBase):
    id: int = 0
    description: str = ""
    startDate: str | None = None
    endDate: str | None = None
    activityType: ActivityTypeRef | None = None
    domain: DomainRef | None = None
    project: ProjectRef | None = None


class OplogRef(_GWBase):
    name: str = ""
    project: ProjectRef | None = None


class OplogEntry(_GWBase):
    id: int = 0
    tool: str = ""
    userContext: str = ""
    command: str = ""
    comments: str = ""
    output: str = ""
    sourceIp: str = ""
    destIp: str = ""
    startDate: str | None = None
    endDate: str | None = None
    operatorName: str = ""
    log: OplogRef | None = None


class ObjectiveSubTask(_GWBase):
    id: int = 0
    task: str = ""
    complete: bool = False
    deadline: str | None = None
    objectiveStatus: ObjectiveStatusRef | None = None


class ObjectiveInList(_GWBase):
    id: int = 0
    objective: str = ""
    description: str = ""
    complete: bool = False
    deadline: str | None = None
    position: int = 0
    result: str = ""
    objectivePriority: ObjectivePriorityRef | None = None
    objectiveStatus: ObjectiveStatusRef | None = None
    project: ProjectRef | None = None
    objectiveSubTasks: list[ObjectiveSubTask] = Field(default_factory=list)


class TargetInList(_GWBase):
    id: int = 0
    hostname: str = ""
    ipAddress: str = ""
    description: str = ""
    compromised: bool = False
    project: ProjectRef | None = None


class ScopeInList(_GWBase):
    id: int = 0
    name: str = ""
    scope: str = ""
    description: str = ""
    disallowed: bool = False
    requiresCaution: bool = False
    project: ProjectRef | None = None


class DeconflictionInList(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    alertSource: str = ""
    alertTimestamp: str | None = None
    reportTimestamp: str | None = None
    responseTimestamp: str | None = None
    deconflictionStatus: DeconflictionStatusRef | None = None
    project: ProjectRef | None = None


class EvidenceInList(_GWBase):
    id: int = 0
    friendlyName: str = ""
    caption: str = ""
    description: str = ""
    document: str = ""
    uploadDate: str | None = None
    finding: FindingInList | None = None
    report: ReportRef | None = None


class FindingTemplateInList(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    severity: SeverityRef | None = None
    type: FindingTypeRef | None = None


class WhitecardInList(_GWBase):
    id: int = 0
    title: str = ""
    description: str = ""
    issued: str | None = None
    project: ProjectRef | None = None


class UserRef(_GWBase):
    id: int | None = None
    username: str = ""
    name: str = ""


class NoteInList(_GWBase):
    id: int = 0
    note: str = ""
    timestamp: str | None = None
    user: UserRef | None = None


# ── Connection ───────────────────────────────────────────────────────


@functools.lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def connect() -> Client:
    """Establish authenticated GraphQL client connection."""
    base_url = os.environ.get("GHOSTWRITER_URL", "").rstrip("/")
    api_token = os.environ.get("GHOSTWRITER_API_TOKEN", "")
    username = os.environ.get("GHOSTWRITER_USERNAME", "")
    password = os.environ.get("GHOSTWRITER_PASSWORD", "")

    if not base_url:
        print("Error: Set GHOSTWRITER_URL env var.", file=sys.stderr)
        sys.exit(1)

    if not api_token and not (username and password):
        print(
            "Error: Set GHOSTWRITER_API_TOKEN or both GHOSTWRITER_USERNAME" " and GHOSTWRITER_PASSWORD.",
            file=sys.stderr,
        )
        sys.exit(1)

    token = api_token or await _login_jwt(base_url, username, password)

    transport = AIOHTTPTransport(
        url=f"{base_url}{GRAPHQL_PATH}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        ssl=_ssl_context(),
    )
    return Client(transport=transport, fetch_schema_from_transport=False)


async def _login_jwt(base_url: str, username: str, password: str) -> str:
    """Authenticate via GhostWriter's GraphQL login mutation to get a JWT."""
    connector = aiohttp.TCPConnector(ssl=_ssl_context())
    async with aiohttp.ClientSession(connector=connector) as session:
        gql_url = f"{base_url}{GRAPHQL_PATH}"
        mutation = {
            "query": (
                "mutation Login($username: String!, $password: String!) {"
                " login(username: $username, password: $password)"
                " { token expires } }"
            ),
            "variables": {"username": username, "password": password},
        }
        async with session.post(gql_url, json=mutation) as resp:
            if resp.status != 200:
                text = await resp.text()
                print(f"Login failed ({resp.status}): {text}", file=sys.stderr)
                sys.exit(1)
            data = await resp.json()
            if "errors" in data:
                print(
                    f"Login error: {json.dumps(data['errors'])}",
                    file=sys.stderr,
                )
                sys.exit(1)
            token: str | None = data.get("data", {}).get("login", {}).get("token")
            if not token:
                print(
                    f"Login response missing token: {json.dumps(data)}",
                    file=sys.stderr,
                )
                sys.exit(1)
            return token


async def run_query(
    session: AsyncClientSession,
    query: str,
    variables: dict[str, int | str] | None = None,
) -> dict[str, object]:
    """Execute a GraphQL query and return the result dict."""
    result = await session.execute(gql_parse(query), variable_values=variables)
    return result  # type: ignore[return-value]


# ── Helpers ──────────────────────────────────────────────────────────


def print_table(
    headers: list[str],
    rows: list[list[str]],
    max_widths: dict[int, int] | None = None,
) -> None:
    if not rows:
        print("(no results)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    if max_widths:
        for i, mw in max_widths.items():
            if i < len(widths):
                widths[i] = min(widths[i], mw)
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)
            if max_widths and i in max_widths and len(s) > max_widths[i]:
                s = s[: max_widths[i] - 3] + "..."
            cells.append(s)
        print(fmt.format(*cells))


def print_json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def _parse_list(model: type[_T], data: object) -> list[_T]:
    if not isinstance(data, list):
        return []
    return [model.model_validate(d) for d in data]


def _trunc(s: str | None, n: int) -> str:
    val = s or ""
    return val[:n]


def _add_project_filter(
    args: argparse.Namespace,
    variables: dict[str, int | str],
    where_path: str = "projectId: {_eq: $projectId}",
) -> tuple[str, str]:
    """If args.project is set, return (where_clause, decls_fragment)."""
    if not getattr(args, "project", None):
        return "", ""
    variables["projectId"] = args.project
    return f", where: {{{where_path}}}", ", $projectId: bigint"


# ── Commands ─────────────────────────────────────────────────────────


async def cmd_status(session: AsyncClientSession, _args: argparse.Namespace) -> None:
    url = os.environ.get("GHOSTWRITER_URL", "")
    auth = "API token" if os.environ.get("GHOSTWRITER_API_TOKEN") else "JWT login"

    result = await run_query(
        session,
        """
        query StatusCheck {
            client_aggregate { aggregate { count } }
            project_aggregate { aggregate { count } }
            reportedFinding_aggregate { aggregate { count } }
        }
        """,
    )

    clients = AggregateCount.model_validate(result["client_aggregate"]).count
    projects = AggregateCount.model_validate(result["project_aggregate"]).count
    findings = AggregateCount.model_validate(result["reportedFinding_aggregate"]).count

    print(f"Connected to {url} — auth: {auth}")
    print(f"  Clients: {clients}  |  Projects: {projects}  |  Findings: {findings}")


async def cmd_clients(session: AsyncClientSession, args: argparse.Namespace) -> None:
    result = await run_query(
        session,
        """
        query AllClients($limit: Int!) {
            client(order_by: {id: desc}, limit: $limit) {
                id, name, shortName, description,
                projects_aggregate { aggregate { count } }
            }
        }
        """,
        {"limit": args.limit},
    )
    raw = result.get("client", [])
    if args.json or args.detail:
        print_json(raw)
        return

    clients = _parse_list(ClientSummary, raw)
    headers = ["ID", "NAME", "SHORT_NAME", "PROJECTS", "DESCRIPTION"]
    rows = [
        [
            str(c.id),
            c.name,
            c.shortName,
            str(c.projects_aggregate.count),
            _trunc(c.description, 50),
        ]
        for c in clients
    ]
    print_table(headers, rows, max_widths={4: 50})


async def cmd_client(session: AsyncClientSession, args: argparse.Namespace) -> None:
    result = await run_query(
        session,
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
        {"id": args.id},
    )
    raw = result.get("client_by_pk")
    if not raw:
        print(f"No client found with id={args.id}")
        return
    print_json(raw)


async def cmd_projects(session: AsyncClientSession, args: argparse.Namespace) -> None:
    conditions: list[str] = []
    variables: dict[str, int | str] = {"limit": args.limit}
    decls = ""

    if args.client:
        conditions.append("clientId: {_eq: $clientId}")
        variables["clientId"] = args.client
        decls += ", $clientId: bigint"

    where = f", where: {{{', '.join(conditions)}}}" if conditions else ""

    query = f"""
        query AllProjects($limit: Int!{decls}) {{
            project(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, codename, complete, description,
                startDate, endDate,
                projectType {{ projectType }},
                client {{ id, name }},
                reports_aggregate {{ aggregate {{ count }} }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("project", [])
    if args.json or args.detail:
        print_json(raw)
        return

    projects = _parse_list(ProjectInList, raw)
    headers = [
        "ID",
        "CODENAME",
        "CLIENT",
        "TYPE",
        "START",
        "END",
        "COMPLETE",
        "REPORTS",
    ]
    rows = [
        [
            str(p.id),
            p.codename,
            p.client.name if p.client else "",
            p.projectType.label() if p.projectType else "",
            _trunc(p.startDate, 10),
            _trunc(p.endDate, 10),
            "yes" if p.complete else "no",
            str(p.reports_aggregate.count),
        ]
        for p in projects
    ]
    print_table(headers, rows, max_widths={1: 30, 2: 25})


async def cmd_project(session: AsyncClientSession, args: argparse.Namespace) -> None:
    result = await run_query(
        session,
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
        {"id": args.id},
    )
    raw = result.get("project_by_pk")
    if not raw:
        print(f"No project found with id={args.id}")
        return
    print_json(raw)


async def cmd_findings(session: AsyncClientSession, args: argparse.Namespace) -> None:
    conditions: list[str] = []
    variables: dict[str, int | str] = {"limit": args.limit, "offset": args.offset}
    decls = ""

    if args.project:
        conditions.append("report: {projectId: {_eq: $projectId}}")
        variables["projectId"] = args.project
        decls += ", $projectId: bigint"
    if args.severity:
        conditions.append("severity: {severity: {_ilike: $severity}}")
        variables["severity"] = args.severity
        decls += ", $severity: String"

    where = f", where: {{{', '.join(conditions)}}}" if conditions else ""

    query = f"""
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
    """
    result = await run_query(session, query, variables)
    raw = result.get("reportedFinding", [])
    if args.json or args.detail:
        print_json(raw)
        return

    findings = _parse_list(FindingInList, raw)
    headers = ["ID", "SEVERITY", "TITLE", "TYPE", "PROJECT", "AFFECTED"]
    rows = [
        [
            str(f.id),
            f.severity.label() if f.severity else "",
            f.title,
            f.findingType.label() if f.findingType else "",
            f.report.project.codename if f.report and f.report.project else "",
            _trunc(f.affectedEntities, 40),
        ]
        for f in findings
    ]
    print_table(headers, rows, max_widths={2: 50, 5: 40})


async def cmd_finding(session: AsyncClientSession, args: argparse.Namespace) -> None:
    result = await run_query(
        session,
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
        {"id": args.id},
    )
    raw = result.get("reportedFinding_by_pk")
    if not raw:
        print(f"No finding found with id={args.id}")
        return
    print_json(raw)


async def cmd_observations(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit, "offset": args.offset}
    where, decls = _add_project_filter(args, variables, "report: {projectId: {_eq: $projectId}}")

    query = f"""
        query AllObservations($limit: Int!, $offset: Int!{decls}) {{
            reporting_reportobservationlink(
                order_by: {{id: desc}}, limit: $limit, offset: $offset{where}
            ) {{
                id, title, description, complete,
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("reporting_reportobservationlink", [])
    if args.json or args.detail:
        print_json(raw)
        return

    observations = _parse_list(ObservationInList, raw)
    headers = ["ID", "TITLE", "COMPLETE", "PROJECT"]
    rows = [
        [
            str(o.id),
            o.title,
            "yes" if o.complete else "no",
            o.report.project.codename if o.report and o.report.project else "",
        ]
        for o in observations
    ]
    print_table(headers, rows, max_widths={1: 60})


async def cmd_reports(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllReports($limit: Int!{decls}) {{
            report(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, complete, archived, creation, delivered,
                project {{ id, codename, client {{ name }} }},
                findings_aggregate {{ aggregate {{ count }} }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("report", [])
    if args.json or args.detail:
        print_json(raw)
        return

    reports = _parse_list(ReportInList, raw)
    headers = [
        "ID",
        "TITLE",
        "PROJECT",
        "CLIENT",
        "COMPLETE",
        "DELIVERED",
        "FINDINGS",
        "CREATED",
    ]
    rows = [
        [
            str(r.id),
            r.title,
            r.project.codename if r.project else "",
            r.project.client.name if r.project and r.project.client else "",
            "yes" if r.complete else "no",
            "yes" if r.delivered else "no",
            str(r.findings_aggregate.count),
            _trunc(r.creation, 10),
        ]
        for r in reports
    ]
    print_table(headers, rows, max_widths={1: 40, 2: 25})


async def cmd_infrastructure(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {}
    where = ""
    decls = ""

    if getattr(args, "project", None):
        where = ", where: {projectId: {_eq: $projectId}}"
        variables["projectId"] = args.project
        decls = "$projectId: bigint"

    query = f"""
        query Infrastructure{"(" + decls + ")" if decls else ""} {{
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
    """
    result = await run_query(session, query, variables)

    if args.json or args.detail:
        print_json(result)
        return

    servers = _parse_list(ServerCheckout, result.get("serverCheckout", []))
    domains = _parse_list(DomainCheckout, result.get("domainCheckout", []))

    print(f"=== SERVERS ({len(servers)}) ===")
    headers = ["ID", "IP", "NAME", "ROLE", "ACTIVITY", "PROJECT"]
    rows = [
        [
            str(s.id),
            s.server.ipAddress if s.server else "",
            s.server.name if s.server else "",
            s.serverRole.label() if s.serverRole else "",
            s.activityType.label() if s.activityType else "",
            s.project.codename if s.project else "",
        ]
        for s in servers
    ]
    print_table(headers, rows)

    print(f"\n=== DOMAINS ({len(domains)}) ===")
    headers = ["ID", "DOMAIN", "ACTIVITY", "START", "END", "PROJECT"]
    rows = [
        [
            str(d.id),
            d.domain.name if d.domain else "",
            d.activityType.label() if d.activityType else "",
            _trunc(d.startDate, 10),
            _trunc(d.endDate, 10),
            d.project.codename if d.project else "",
        ]
        for d in domains
    ]
    print_table(headers, rows)


async def cmd_servers(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
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
    """
    result = await run_query(session, query, variables)
    raw = result.get("serverCheckout", [])
    if args.json or args.detail:
        print_json(raw)
        return

    servers = _parse_list(ServerCheckout, raw)
    headers = [
        "ID",
        "IP",
        "NAME",
        "ROLE",
        "PROVIDER",
        "ACTIVITY",
        "START",
        "END",
        "PROJECT",
    ]
    rows = [
        [
            str(s.id),
            s.server.ipAddress if s.server else "",
            s.server.name if s.server else "",
            s.serverRole.label() if s.serverRole else "",
            (s.server.serverProvider.label() if s.server and s.server.serverProvider else ""),
            s.activityType.label() if s.activityType else "",
            _trunc(s.startDate, 10),
            _trunc(s.endDate, 10),
            s.project.codename if s.project else "",
        ]
        for s in servers
    ]
    print_table(headers, rows)


async def cmd_domains(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllDomains($limit: Int!{decls}) {{
            domainCheckout(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, description, startDate, endDate,
                activityType {{ activity }},
                domain {{ id, name, registrar, creation, expiration,
                          healthStatus {{ healthStatus }} }},
                project {{ id, codename }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("domainCheckout", [])
    if args.json or args.detail:
        print_json(raw)
        return

    domains = _parse_list(DomainCheckout, raw)
    headers = [
        "ID",
        "DOMAIN",
        "REGISTRAR",
        "ACTIVITY",
        "HEALTH",
        "START",
        "END",
        "PROJECT",
    ]
    rows = [
        [
            str(d.id),
            d.domain.name if d.domain else "",
            d.domain.registrar if d.domain else "",
            d.activityType.label() if d.activityType else "",
            d.domain.healthStatus.label() if d.domain and d.domain.healthStatus else "",
            _trunc(d.startDate, 10),
            _trunc(d.endDate, 10),
            d.project.codename if d.project else "",
        ]
        for d in domains
    ]
    print_table(headers, rows)


async def cmd_activity_logs(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit, "offset": args.offset}
    where, decls = _add_project_filter(args, variables, "log: {project: {id: {_eq: $projectId}}}")

    query = f"""
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
    """
    result = await run_query(session, query, variables)
    raw = result.get("oplogEntry", [])
    if args.json or args.detail:
        print_json(raw)
        return

    entries = _parse_list(OplogEntry, raw)
    headers = [
        "ID",
        "TOOL",
        "COMMAND",
        "SRC_IP",
        "DEST_IP",
        "OPERATOR",
        "TIME",
        "PROJECT",
    ]
    rows = [
        [
            str(e.id),
            e.tool,
            _trunc(e.command, 50),
            e.sourceIp,
            e.destIp,
            e.operatorName,
            _trunc(e.startDate, 16),
            e.log.project.codename if e.log and e.log.project else "",
        ]
        for e in entries
    ]
    print_table(headers, rows, max_widths={2: 50})
    if len(entries) == args.limit:
        print(f"\n(showing {args.limit} entries — use --offset to page)")


async def cmd_objectives(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
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
    """
    result = await run_query(session, query, variables)
    raw = result.get("objective", [])
    if args.json or args.detail:
        print_json(raw)
        return

    objectives = _parse_list(ObjectiveInList, raw)
    headers = [
        "ID",
        "PRIORITY",
        "OBJECTIVE",
        "STATUS",
        "DEADLINE",
        "COMPLETE",
        "PROJECT",
    ]
    rows = [
        [
            str(o.id),
            o.objectivePriority.label() if o.objectivePriority else "",
            o.objective,
            o.objectiveStatus.label() if o.objectiveStatus else "",
            _trunc(o.deadline, 10),
            "yes" if o.complete else "no",
            o.project.codename if o.project else "",
        ]
        for o in objectives
    ]
    print_table(headers, rows, max_widths={2: 50})


async def cmd_targets(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllTargets($limit: Int!{decls}) {{
            target(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, hostname, ipAddress, description, compromised,
                project {{ id, codename }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("target", [])
    if args.json or args.detail:
        print_json(raw)
        return

    targets = _parse_list(TargetInList, raw)
    headers = ["ID", "HOSTNAME", "IP", "COMPROMISED", "PROJECT", "DESCRIPTION"]
    rows = [
        [
            str(t.id),
            t.hostname,
            t.ipAddress,
            "yes" if t.compromised else "no",
            t.project.codename if t.project else "",
            _trunc(t.description, 40),
        ]
        for t in targets
    ]
    print_table(headers, rows, max_widths={5: 40})


async def cmd_scope(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllScope($limit: Int!{decls}) {{
            scope(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, name, scope, description, disallowed, requiresCaution,
                project {{ id, codename }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("scope", [])
    if args.json or args.detail:
        print_json(raw)
        return

    scopes = _parse_list(ScopeInList, raw)
    headers = ["ID", "NAME", "SCOPE", "DISALLOWED", "CAUTION", "PROJECT"]
    rows = [
        [
            str(s.id),
            s.name,
            _trunc(s.scope, 40),
            "yes" if s.disallowed else "no",
            "yes" if s.requiresCaution else "no",
            s.project.codename if s.project else "",
        ]
        for s in scopes
    ]
    print_table(headers, rows, max_widths={2: 40})


async def cmd_deconflictions(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllDeconflictions($limit: Int!{decls}) {{
            deconfliction(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, description, alertSource,
                alertTimestamp, reportTimestamp, responseTimestamp,
                deconflictionStatus {{ status }},
                project {{ id, codename }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("deconfliction", [])
    if args.json or args.detail:
        print_json(raw)
        return

    decons = _parse_list(DeconflictionInList, raw)
    headers = ["ID", "TITLE", "STATUS", "SOURCE", "ALERT_TIME", "PROJECT"]
    rows = [
        [
            str(d.id),
            d.title,
            d.deconflictionStatus.label() if d.deconflictionStatus else "",
            d.alertSource,
            _trunc(d.alertTimestamp, 16),
            d.project.codename if d.project else "",
        ]
        for d in decons
    ]
    print_table(headers, rows, max_widths={1: 40})


async def cmd_evidence(session: AsyncClientSession, args: argparse.Namespace) -> None:
    conditions: list[str] = []
    variables: dict[str, int | str] = {"limit": args.limit}
    decls = ""

    if args.project:
        conditions.append("report: {projectId: {_eq: $projectId}}")
        variables["projectId"] = args.project
        decls += ", $projectId: bigint"
    if args.finding:
        conditions.append("findingId: {_eq: $findingId}")
        variables["findingId"] = args.finding
        decls += ", $findingId: bigint"

    where = f", where: {{{', '.join(conditions)}}}" if conditions else ""

    query = f"""
        query AllEvidence($limit: Int!{decls}) {{
            evidence(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, friendlyName, caption, description, document, uploadDate,
                finding {{ id, title, severity {{ severity }} }},
                report {{ id, title, project {{ id, codename }} }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("evidence", [])
    if args.json or args.detail:
        print_json(raw)
        return

    items = _parse_list(EvidenceInList, raw)
    headers = ["ID", "NAME", "FINDING", "CAPTION", "UPLOADED", "PROJECT"]
    rows = [
        [
            str(e.id),
            e.friendlyName,
            e.finding.title if e.finding else "",
            _trunc(e.caption, 30),
            _trunc(e.uploadDate, 10),
            (e.report.project.codename if e.report and e.report.project else ""),
        ]
        for e in items
    ]
    print_table(headers, rows, max_widths={2: 35, 3: 30})


async def cmd_finding_templates(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    decls = ""
    where = ""
    if args.severity:
        where = ", where: {severity: {severity: {_ilike: $severity}}}"
        variables["severity"] = args.severity
        decls = ", $severity: String"

    query = f"""
        query AllFindingTemplates($limit: Int!{decls}) {{
            finding(order_by: {{severityId: asc, id: desc}}, limit: $limit{where}) {{
                id, title, description,
                severity {{ severity }},
                type {{ findingType }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("finding", [])
    if args.json or args.detail:
        print_json(raw)
        return

    templates = _parse_list(FindingTemplateInList, raw)
    headers = ["ID", "SEVERITY", "TYPE", "TITLE", "DESCRIPTION"]
    rows = [
        [
            str(f.id),
            f.severity.label() if f.severity else "",
            f.type.label() if f.type else "",
            f.title,
            _trunc(f.description, 50),
        ]
        for f in templates
    ]
    print_table(headers, rows, max_widths={3: 40, 4: 50})


async def cmd_whitecards(session: AsyncClientSession, args: argparse.Namespace) -> None:
    variables: dict[str, int | str] = {"limit": args.limit}
    where, decls = _add_project_filter(args, variables)

    query = f"""
        query AllWhitecards($limit: Int!{decls}) {{
            whitecard(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, title, description, issued,
                project {{ id, codename }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get("whitecard", [])
    if args.json or args.detail:
        print_json(raw)
        return

    cards = _parse_list(WhitecardInList, raw)
    headers = ["ID", "TITLE", "ISSUED", "PROJECT", "DESCRIPTION"]
    rows = [
        [
            str(w.id),
            w.title,
            _trunc(w.issued, 16),
            w.project.codename if w.project else "",
            _trunc(w.description, 40),
        ]
        for w in cards
    ]
    print_table(headers, rows, max_widths={4: 40})


async def cmd_notes(session: AsyncClientSession, args: argparse.Namespace) -> None:
    note_type = args.type
    variables: dict[str, int | str] = {"limit": args.limit}

    table_map = {
        "client": ("clientNote", "clientId"),
        "project": ("projectNote", "projectId"),
        "domain": ("domainNote", "domainId"),
        "server": ("serverNote", "serverId"),
    }
    table, fk_field = table_map[note_type]
    where = ""
    decls = ""
    if args.parent_id:
        where = f", where: {{{fk_field}: {{_eq: $parentId}}}}"
        variables["parentId"] = args.parent_id
        decls = ", $parentId: bigint"

    query = f"""
        query AllNotes($limit: Int!{decls}) {{
            {table}(order_by: {{id: desc}}, limit: $limit{where}) {{
                id, note, timestamp,
                user {{ id, username, name }}
            }}
        }}
    """
    result = await run_query(session, query, variables)
    raw = result.get(table, [])
    if args.json or args.detail:
        print_json(raw)
        return

    notes = _parse_list(NoteInList, raw)
    headers = ["ID", "TIMESTAMP", "AUTHOR", "NOTE"]
    rows = [
        [
            str(n.id),
            _trunc(n.timestamp, 10),
            n.user.username if n.user else "",
            _trunc(n.note, 60),
        ]
        for n in notes
    ]
    print_table(headers, rows, max_widths={3: 60})


async def cmd_search(session: AsyncClientSession, args: argparse.Namespace) -> None:
    term = f"%{args.query}%"
    all_types = {"clients", "projects", "findings", "observations", "activity-logs"}
    types = set(args.types.split(",")) if args.types else all_types

    queries: dict[str, Awaitable[dict[str, object]]] = {}
    if "clients" in types:
        queries["clients"] = run_query(
            session,
            """
            query SearchClients($s: String!, $l: Int!) {
                client(where: {_or: [
                    {name: {_ilike: $s}}, {shortName: {_ilike: $s}},
                    {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, name, shortName
                }
            }""",
            {"s": term, "l": args.limit},
        )
    if "projects" in types:
        queries["projects"] = run_query(
            session,
            """
            query SearchProjects($s: String!, $l: Int!) {
                project(where: {_or: [
                    {codename: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, codename, projectType { projectType },
                    client { name }
                }
            }""",
            {"s": term, "l": args.limit},
        )
    if "findings" in types:
        queries["findings"] = run_query(
            session,
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
            {"s": term, "l": args.limit},
        )
    if "observations" in types:
        queries["observations"] = run_query(
            session,
            """
            query SearchObservations($s: String!, $l: Int!) {
                reporting_reportobservationlink(where: {_or: [
                    {title: {_ilike: $s}}, {description: {_ilike: $s}}
                ]}, order_by: {id: desc}, limit: $l) {
                    id, title
                }
            }""",
            {"s": term, "l": args.limit},
        )
    if "activity-logs" in types:
        queries["activity-logs"] = run_query(
            session,
            """
            query SearchLogs($s: String!, $l: Int!) {
                oplogEntry(where: {_or: [
                    {command: {_ilike: $s}}, {output: {_ilike: $s}},
                    {comments: {_ilike: $s}}, {tool: {_ilike: $s}}
                ]}, order_by: {startDate: desc}, limit: $l) {
                    id, tool, command, operatorName, startDate
                }
            }""",
            {"s": term, "l": args.limit},
        )

    keys = list(queries.keys())
    raw = await asyncio.gather(*queries.values(), return_exceptions=True)
    gql_keys = {
        "clients": "client",
        "projects": "project",
        "findings": "reportedFinding",
        "observations": "reporting_reportobservationlink",
        "activity-logs": "oplogEntry",
    }

    if args.json or args.detail:
        results: dict[str, object] = {}
        for key, r in zip(keys, raw):
            if isinstance(r, BaseException):
                results[key] = [{"error": str(r)}]
            elif isinstance(r, dict):
                results[key] = r.get(gql_keys.get(key, key), [])
            else:
                results[key] = []
        print_json(results)
        return

    for key, r in zip(keys, raw):
        if isinstance(r, BaseException):
            print(f"\n=== {key.upper()} === (error: {r})")
            continue
        raw_items = r.get(gql_keys.get(key, key), []) if isinstance(r, dict) else []
        items = raw_items if isinstance(raw_items, list) else []
        print(f"\n=== {key.upper()} ({len(items)} results) ===")
        if not items:
            continue
        _print_search_results(key, items)


def _print_search_results(key: str, items: list[object]) -> None:
    if key == "clients":
        for c in items:
            cs = ClientSummary.model_validate(c)
            print(f"  #{cs.id} {cs.name} ({cs.shortName})")
    elif key == "projects":
        for p in items:
            proj = ProjectInList.model_validate(p)
            ptype = proj.projectType.label() if proj.projectType else ""
            client = proj.client.name if proj.client else ""
            print(f"  #{proj.id} {proj.codename} [{ptype}] — {client}")
    elif key == "findings":
        for f in items:
            finding = FindingInList.model_validate(f)
            sev = finding.severity.label() if finding.severity else ""
            proj = finding.report.project.codename if finding.report and finding.report.project else ""
            print(f"  #{finding.id} [{sev}] {finding.title} — {proj}")
    elif key == "observations":
        for o in items:
            obs = ObservationInList.model_validate(o)
            print(f"  #{obs.id} {obs.title}")
    elif key == "activity-logs":
        for e in items:
            entry = OplogEntry.model_validate(e)
            print(
                f"  #{entry.id} [{entry.tool}] {_trunc(entry.command, 60)}"
                f" by {entry.operatorName} at {_trunc(entry.startDate, 16)}"
            )


# ── CLI ──────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only GhostWriter query tool")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-d", "--detail", action="store_true", help="Print full raw JSON")
    common.add_argument("--json", action="store_true", help="Output raw JSON")

    sub.add_parser("status", parents=[common], help="Show connection info")

    cl = sub.add_parser("clients", parents=[common], help="List clients")
    cl.add_argument("--limit", type=int, default=50)

    cd = sub.add_parser("client", parents=[common], help="Client details")
    cd.add_argument("id", type=int, help="Client ID")

    pl = sub.add_parser("projects", parents=[common], help="List projects")
    pl.add_argument("--client", type=int, default=None, help="Filter by client ID")
    pl.add_argument("--limit", type=int, default=50)

    pd = sub.add_parser("project", parents=[common], help="Project details")
    pd.add_argument("id", type=int, help="Project ID")

    fl = sub.add_parser("findings", parents=[common], help="List findings")
    fl.add_argument("--project", type=int, default=None)
    fl.add_argument("--severity", default=None)
    fl.add_argument("--limit", type=int, default=50)
    fl.add_argument("--offset", type=int, default=0)

    fd = sub.add_parser("finding", parents=[common], help="Finding details")
    fd.add_argument("id", type=int, help="Finding ID")

    obs = sub.add_parser("observations", parents=[common], help="List observations")
    obs.add_argument("--project", type=int, default=None)
    obs.add_argument("--limit", type=int, default=50)
    obs.add_argument("--offset", type=int, default=0)

    rp = sub.add_parser("reports", parents=[common], help="List reports")
    rp.add_argument("--project", type=int, default=None)
    rp.add_argument("--limit", type=int, default=50)

    inf = sub.add_parser("infrastructure", parents=[common], help="Infra summary")
    inf.add_argument("--project", type=int, default=None)

    sv = sub.add_parser("servers", parents=[common], help="List servers")
    sv.add_argument("--project", type=int, default=None)
    sv.add_argument("--limit", type=int, default=50)

    dm = sub.add_parser("domains", parents=[common], help="List domains")
    dm.add_argument("--project", type=int, default=None)
    dm.add_argument("--limit", type=int, default=50)

    al = sub.add_parser("activity-logs", parents=[common], help="Activity logs")
    al.add_argument("--project", type=int, default=None)
    al.add_argument("--limit", type=int, default=50)
    al.add_argument("--offset", type=int, default=0)

    oj = sub.add_parser("objectives", parents=[common], help="Project objectives")
    oj.add_argument("--project", type=int, default=None)
    oj.add_argument("--limit", type=int, default=50)

    tg = sub.add_parser("targets", parents=[common], help="Target hosts")
    tg.add_argument("--project", type=int, default=None)
    tg.add_argument("--limit", type=int, default=50)

    sc = sub.add_parser("scope", parents=[common], help="Scope definitions")
    sc.add_argument("--project", type=int, default=None)
    sc.add_argument("--limit", type=int, default=50)

    dc = sub.add_parser("deconflictions", parents=[common], help="Deconfliction entries")
    dc.add_argument("--project", type=int, default=None)
    dc.add_argument("--limit", type=int, default=50)

    ev = sub.add_parser("evidence", parents=[common], help="Evidence files")
    ev.add_argument("--project", type=int, default=None)
    ev.add_argument("--finding", type=int, default=None)
    ev.add_argument("--limit", type=int, default=50)

    ft = sub.add_parser("finding-templates", parents=[common], help="Finding template library")
    ft.add_argument("--severity", default=None)
    ft.add_argument("--limit", type=int, default=50)

    wc = sub.add_parser("whitecards", parents=[common], help="White cards")
    wc.add_argument("--project", type=int, default=None)
    wc.add_argument("--limit", type=int, default=50)

    nt = sub.add_parser("notes", parents=[common], help="Notes (client/project/domain/server)")
    nt.add_argument("type", choices=["client", "project", "domain", "server"])
    nt.add_argument("--parent-id", type=int, default=None, help="Filter by parent ID")
    nt.add_argument("--limit", type=int, default=50)

    sr = sub.add_parser("search", parents=[common], help="Cross-type search")
    sr.add_argument("query", help="Search term")
    sr.add_argument("--types", default=None)
    sr.add_argument("--limit", type=int, default=10)

    return p


_CommandHandler = Callable[[AsyncClientSession, argparse.Namespace], Awaitable[None]]


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    client = await connect()

    async with client as session:
        commands: dict[str, _CommandHandler] = {
            "status": cmd_status,
            "clients": cmd_clients,
            "client": cmd_client,
            "projects": cmd_projects,
            "project": cmd_project,
            "findings": cmd_findings,
            "finding": cmd_finding,
            "observations": cmd_observations,
            "reports": cmd_reports,
            "infrastructure": cmd_infrastructure,
            "servers": cmd_servers,
            "domains": cmd_domains,
            "activity-logs": cmd_activity_logs,
            "objectives": cmd_objectives,
            "targets": cmd_targets,
            "scope": cmd_scope,
            "deconflictions": cmd_deconflictions,
            "evidence": cmd_evidence,
            "finding-templates": cmd_finding_templates,
            "whitecards": cmd_whitecards,
            "notes": cmd_notes,
            "search": cmd_search,
        }
        await commands[args.command](session, args)


if __name__ == "__main__":
    asyncio.run(main())
