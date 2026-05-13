"""Tests for the Cypher safety guards.

These keep ``run_cypher`` from being a footgun: write-clause
detection, default LIMIT injection, and the graph-summary
truncation that prevents huge responses through the tool boundary.
"""

from __future__ import annotations

from runtime.cypher_helpers import ensure_limit, is_write_query, summarise_graph


class TestWriteDetection:
    def test_create(self) -> None:
        assert is_write_query("CREATE (n:User) RETURN n")

    def test_merge(self) -> None:
        assert is_write_query("MERGE (n:User {name: 'x'})")

    def test_delete(self) -> None:
        assert is_write_query("MATCH (n) DELETE n")

    def test_set(self) -> None:
        assert is_write_query("MATCH (n) SET n.foo = 'bar' RETURN n")

    def test_remove(self) -> None:
        assert is_write_query("MATCH (n) REMOVE n.label RETURN n")

    def test_detach(self) -> None:
        assert is_write_query("MATCH (n) DETACH DELETE n")

    def test_drop(self) -> None:
        assert is_write_query("DROP INDEX foo")

    def test_case_insensitive(self) -> None:
        assert is_write_query("create (n:X) return n")

    def test_read_only_passes(self) -> None:
        assert not is_write_query("MATCH (n:User) RETURN n LIMIT 100")

    def test_word_boundary_avoids_false_positive(self) -> None:
        # 'created' and 'createdAt' shouldn't trigger.
        assert not is_write_query("MATCH (n:User) WHERE n.createdAt > 0 RETURN n")


class TestEnsureLimit:
    def test_appends_when_missing(self) -> None:
        out = ensure_limit("MATCH (n) RETURN n", 100)
        assert out == "MATCH (n) RETURN n LIMIT 100"

    def test_strips_trailing_semicolon(self) -> None:
        out = ensure_limit("MATCH (n) RETURN n;", 50)
        assert out == "MATCH (n) RETURN n LIMIT 50"

    def test_preserves_existing_limit(self) -> None:
        q = "MATCH (n) RETURN n LIMIT 5"
        assert ensure_limit(q, 100) == q

    def test_case_insensitive_existing_limit(self) -> None:
        q = "MATCH (n) RETURN n limit 5"
        assert ensure_limit(q, 100) == q


class TestGraphSummary:
    def test_handles_dict_node_map(self) -> None:
        payload = {
            "data": {
                "nodes": {
                    "1": {"label": "x", "kind": "User", "objectId": "S-1-5-..."},
                    "2": {"label": "y", "kind": "Computer"},
                },
                "edges": [{"source": "1", "target": "2", "kind": "AdminTo"}],
            }
        }
        out = summarise_graph(payload, max_nodes=10, max_edges=10)
        assert out["node_count"] == 2
        assert out["edge_count"] == 1
        assert out["node_truncated"] is False

    def test_handles_list_nodes(self) -> None:
        payload = {
            "nodes": [{"label": "a"}, {"label": "b"}, {"label": "c"}],
            "edges": [],
        }
        out = summarise_graph(payload, max_nodes=2, max_edges=10)
        assert out["node_count"] == 3
        assert len(out["nodes"]) == 2
        assert out["node_truncated"] is True

    def test_truncates_edges(self) -> None:
        payload = {
            "nodes": {},
            "edges": [{"source": str(i), "target": str(i + 1)} for i in range(50)],
        }
        out = summarise_graph(payload, max_nodes=10, max_edges=5)
        assert out["edge_count"] == 50
        assert len(out["edges"]) == 5
        assert out["edge_truncated"] is True

    def test_handles_unexpected_shape(self) -> None:
        # Some endpoints return a bare list under "data".
        out = summarise_graph([{"x": 1}], max_nodes=10, max_edges=10)
        assert "raw" in out

    def test_handles_missing_data_key(self) -> None:
        # Graph-shaped payload without the "data" envelope.
        payload = {"nodes": {"1": {"label": "x"}}, "edges": []}
        out = summarise_graph(payload, max_nodes=10, max_edges=10)
        assert out["node_count"] == 1
