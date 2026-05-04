"""Shared response types for the BloodHound Enterprise API.

The API surfaces a consistent set of shapes across many endpoints:

- **Graphs** — ``{nodes: {...}, edges: [...]}`` returned by Cypher
  endpoints and entity walk responses.
- **Findings** — attack-path findings with ``id``, ``finding``,
  ``domain_sid``, ``principal``, ``accepted`` flag, and a
  ``severity`` rollup.
- **Asset group tags** — tier definitions with selectors and
  members.
- **Pagination envelope** — list endpoints wrap their data in
  ``{count, limit, skip, data: [...]}``.

Pydantic models with ``extra='allow'`` so unfamiliar fields don't
trip parsing — BHE evolves the schema, and we'd rather surface a
field we didn't expect than fail to read a response.
"""

from __future__ import annotations

import typing as t

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class PaginatedEnvelope(BaseModel, t.Generic[t.TypeVar("T")]):  # type: ignore[misc]
    """Standard list-response envelope.

    ``data`` carries the paginated rows; the integers describe the
    offset/window. Callers normally only care about ``data`` —
    pagination is folded into specific tools that need to walk
    every page.
    """

    model_config = ConfigDict(extra="allow")
    count: int | None = None
    limit: int | None = None
    skip: int | None = None
    data: list[t.Any] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Graphs
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    """One node in a returned graph response."""

    model_config = ConfigDict(extra="allow")

    label: str | None = None
    kind: str | None = None
    object_id: str | None = Field(default=None, alias="objectId")
    is_tier_zero: bool | None = Field(default=None, alias="isTierZero")
    is_owned: bool | None = Field(default=None, alias="isOwnedObject")
    last_seen: str | None = Field(default=None, alias="lastSeen")
    properties: dict[str, t.Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """One edge in a returned graph response."""

    model_config = ConfigDict(extra="allow")

    source: str | None = None
    target: str | None = None
    label: str | None = None
    kind: str | None = None
    properties: dict[str, t.Any] = Field(default_factory=dict)


class Graph(BaseModel):
    """A node + edge bundle as returned by Cypher / entity endpoints.

    The API renders ``nodes`` as a mapping keyed by node id; we
    accept both that shape and a list. Use :meth:`node_list` to
    iterate without worrying about the wire shape.
    """

    model_config = ConfigDict(extra="allow")

    nodes: dict[str, GraphNode] | list[GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)

    def node_list(self) -> list[GraphNode]:
        if isinstance(self.nodes, list):
            return list(self.nodes)
        return list(self.nodes.values())


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class AttackPathFinding(BaseModel):
    """A single attack-path finding row.

    Fields not declared explicitly (e.g. ``severity_summary``,
    ``principal_kind``, ``edge_kind``) round-trip through ``extra``.
    """

    model_config = ConfigDict(extra="allow")

    id: int | str | None = None
    finding: str | None = None
    domain_sid: str | None = Field(default=None, alias="domainSid")
    principal: str | None = None
    principal_kind: str | None = Field(default=None, alias="principalKind")
    accepted_until: str | None = Field(default=None, alias="acceptedUntil")
    severity: str | None = None
    is_accepted_risk: bool | None = Field(default=None, alias="isAcceptedRisk")
    impact: float | int | None = None
    exposure: float | int | None = None


class AttackPathType(BaseModel):
    """One row from ``/api/v2/attack-paths/types``."""

    model_config = ConfigDict(extra="allow")

    type: str | None = None
    description: str | None = None
    category: str | None = None


class AttackPathTrendPoint(BaseModel):
    """One sparkline / trend datapoint."""

    model_config = ConfigDict(extra="allow")

    date: str | None = None
    value: float | int | None = None
    finding: str | None = None


# ---------------------------------------------------------------------------
# Asset groups
# ---------------------------------------------------------------------------


class AssetGroupTag(BaseModel):
    """A tier / asset group tag (Tier Zero, Tier One, ...)."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    name: str | None = None
    type: str | None = None
    position: int | None = None
    description: str | None = None
    member_count: int | None = Field(default=None, alias="memberCount")


class AssetGroupSelector(BaseModel):
    """A selector that defines membership for a tag."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    tag_id: int | None = Field(default=None, alias="tagId")
    name: str | None = None
    cypher_query: str | None = Field(default=None, alias="cypherQuery")
    description: str | None = None
    is_default: bool | None = Field(default=None, alias="isDefault")


class AssetGroupMember(BaseModel):
    """One member of a tag — a node by object_id."""

    model_config = ConfigDict(extra="allow")

    object_id: str | None = Field(default=None, alias="objectId")
    name: str | None = None
    kind: str | None = None
    selectors: list[str] = Field(default_factory=list)
    is_certified: bool | None = Field(default=None, alias="isCertified")


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------


class EntityCounts(BaseModel):
    """Per-relationship counts for a node (e.g. how many sessions).

    The API returns these as strings or numbers depending on the
    field; pydantic coerces both into ``int`` where possible.
    """

    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=False)


class EntityInfo(BaseModel):
    """Top-level entity response — a node + relationship counts."""

    model_config = ConfigDict(extra="allow")

    object_id: str | None = Field(default=None, alias="objectid")
    name: str | None = None
    kind: str | None = None
    distinguished_name: str | None = Field(default=None, alias="distinguishedname")
    domain: str | None = None
    enabled: bool | None = None
    counts: dict[str, t.Any] | None = None
    properties: dict[str, t.Any] | None = None


# ---------------------------------------------------------------------------
# Saved queries
# ---------------------------------------------------------------------------


class SavedQuery(BaseModel):
    """A user-defined saved Cypher query."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    name: str | None = None
    description: str | None = None
    query: str | None = None
    user_id: str | None = Field(default=None, alias="userId")


# ---------------------------------------------------------------------------
# Posture / exposure
# ---------------------------------------------------------------------------


class PostureSnapshot(BaseModel):
    """One row from posture endpoints — a domain-level exposure score."""

    model_config = ConfigDict(extra="allow")

    domain_sid: str | None = Field(default=None, alias="domainSid")
    domain: str | None = None
    exposure_index: float | None = Field(default=None, alias="exposureIndex")
    tier_zero_count: int | None = Field(default=None, alias="tierZeroCount")
    critical_count: int | None = Field(default=None, alias="criticalRiskCount")
    captured_at: str | None = Field(default=None, alias="capturedAt")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditLog(BaseModel):
    """One row of the audit log."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    action: str | None = None
    actor_email: str | None = Field(default=None, alias="actorEmail")
    fields: dict[str, t.Any] | None = None
    created_at: str | None = Field(default=None, alias="createdAt")
    request_id: str | None = Field(default=None, alias="requestId")
    status: str | None = None


__all__ = [
    "AssetGroupMember",
    "AssetGroupSelector",
    "AssetGroupTag",
    "AttackPathFinding",
    "AttackPathTrendPoint",
    "AttackPathType",
    "AuditLog",
    "EntityCounts",
    "EntityInfo",
    "Graph",
    "GraphEdge",
    "GraphNode",
    "PaginatedEnvelope",
    "PostureSnapshot",
    "SavedQuery",
]
