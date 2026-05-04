"""Pure-logic helpers for Cypher tooling.

Lives in ``runtime/`` rather than ``tools/`` so unit tests can
import without dragging in the Dreadnode tools SDK. The
:class:`tools.cypher.CypherTools` toolset wraps these.
"""

from __future__ import annotations

import re
import typing as t


_WRITE_CLAUSE_RE = re.compile(
    r"\b(CREATE|MERGE|DELETE|SET|REMOVE|DETACH|DROP)\b",
    re.IGNORECASE,
)
_LIMIT_RE = re.compile(r"\bLIMIT\s+\d+\b", re.IGNORECASE)


def is_write_query(query: str) -> bool:
    """True if ``query`` contains a write clause.

    Heuristic — false positives are possible if a literal string
    in a property happens to contain ``CREATE``. Callers can
    bypass with ``allow_writes=True``.
    """
    return bool(_WRITE_CLAUSE_RE.search(query))


def ensure_limit(query: str, default_limit: int) -> str:
    """Append ``LIMIT N`` to a query that doesn't already have one."""
    if _LIMIT_RE.search(query):
        return query
    return f"{query.rstrip().rstrip(';')} LIMIT {default_limit}"


def summarise_graph(
    payload: t.Any,
    *,
    max_nodes: int,
    max_edges: int,
) -> dict[str, t.Any]:
    """Trim a graph payload to a model-friendly digest.

    The BHE Cypher endpoint returns ``{data: {nodes: {...}, edges: [...]}}``.
    Some endpoints omit the ``data`` envelope, and the ``nodes``
    field can be a dict (id-keyed) or a list. This function
    accepts every shape and returns a fixed-shape summary.
    """
    if not isinstance(payload, dict):
        return {"raw": payload}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    nodes = data.get("nodes") or {}
    edges = data.get("edges") or []
    if isinstance(nodes, dict):
        node_items = list(nodes.items())
    else:
        node_items = [(str(i), n) for i, n in enumerate(nodes or [])]
    summary_nodes = [
        {
            "id": nid,
            "label": (n.get("label") if isinstance(n, dict) else None),
            "kind": (n.get("kind") if isinstance(n, dict) else None),
            "objectId": (n.get("objectId") if isinstance(n, dict) else None),
            "isTierZero": (
                n.get("isTierZero") if isinstance(n, dict) else None
            ),
        }
        for nid, n in node_items[:max_nodes]
    ]
    summary_edges = [
        {
            "source": (e.get("source") if isinstance(e, dict) else None),
            "target": (e.get("target") if isinstance(e, dict) else None),
            "label": (e.get("label") if isinstance(e, dict) else None),
            "kind": (e.get("kind") if isinstance(e, dict) else None),
        }
        for e in (edges or [])[:max_edges]
    ]
    return {
        "node_count": len(node_items),
        "edge_count": len(edges or []),
        "nodes": summary_nodes,
        "edges": summary_edges,
        "node_truncated": len(node_items) > max_nodes,
        "edge_truncated": len(edges or []) > max_edges,
    }
