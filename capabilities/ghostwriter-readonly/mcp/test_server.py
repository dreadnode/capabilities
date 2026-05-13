#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "aiohttp>=3.9,<4.0",
#   "pydantic>=2.0,<3.0",
# ]
# ///
"""Tests for ghostwriter MCP server — no GhostWriter instance required."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import server


class TestToolRegistration:
    def test_expected_tools_registered(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        tool_names = set(tools) if isinstance(tools, dict) else {t.name for t in tools}
        expected = {
            "get_status",
            "list_clients",
            "get_client",
            "list_projects",
            "get_project",
            "list_findings",
            "get_finding",
            "list_finding_templates",
            "list_objectives",
            "list_targets",
            "list_scope",
            "list_deconflictions",
            "list_evidence",
            "list_whitecards",
            "list_observations",
            "list_reports",
            "get_infrastructure",
            "list_servers",
            "list_domains",
            "list_activity_logs",
            "list_notes",
            "search",
        }
        assert expected == tool_names, f"Unexpected: {tool_names - expected}, Missing: {expected - tool_names}"

    def test_tool_count(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        assert len(tools) == 22


class TestConnectionState:
    def setup_method(self):
        server._gql_client = None
        server._gql_session = None
        server._config = None

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("GHOSTWRITER_URL", "https://gw.example.com")
        monkeypatch.setenv("GHOSTWRITER_API_TOKEN", "tok123")
        monkeypatch.setenv("GHOSTWRITER_USERNAME", "admin")
        monkeypatch.setenv("GHOSTWRITER_PASSWORD", "secret")
        cfg = server._default_config()
        assert cfg["url"] == "https://gw.example.com"
        assert cfg["api_token"] == "tok123"
        assert cfg["username"] == "admin"
        assert cfg["password"] == "secret"

    def test_default_config_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("GHOSTWRITER_URL", "https://gw.example.com/")
        cfg = server._default_config()
        assert cfg["url"] == "https://gw.example.com"

    @pytest.mark.asyncio
    async def test_ensure_connected_errors_without_url(self, monkeypatch):
        monkeypatch.delenv("GHOSTWRITER_URL", raising=False)
        monkeypatch.delenv("GHOSTWRITER_API_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="GHOSTWRITER_URL"):
            await server._ensure_connected()

    @pytest.mark.asyncio
    async def test_ensure_connected_errors_without_credentials(self, monkeypatch):
        monkeypatch.setenv("GHOSTWRITER_URL", "https://gw.example.com")
        monkeypatch.delenv("GHOSTWRITER_API_TOKEN", raising=False)
        monkeypatch.delenv("GHOSTWRITER_USERNAME", raising=False)
        monkeypatch.delenv("GHOSTWRITER_PASSWORD", raising=False)
        with pytest.raises(RuntimeError, match="GHOSTWRITER_API_TOKEN"):
            await server._ensure_connected()


class TestNoteTables:
    def test_all_note_types_mapped(self):
        for note_type in ("client", "project", "domain", "server"):
            assert note_type in server._NOTE_TABLES

    def test_table_names_match_convention(self):
        for note_type, (table, fk) in server._NOTE_TABLES.items():
            assert table == f"{note_type}Note"
            assert fk == f"{note_type}Id"


class TestBuildWhere:
    def test_empty_filters(self):
        where, decls, variables = server._build_where({})
        assert where == ""
        assert decls == ""
        assert variables == {}

    def test_none_value_skipped(self):
        where, decls, variables = server._build_where(
            {
                "projectId": {"predicate": "projectId: {_eq: $projectId}", "value": None},
            }
        )
        assert where == ""
        assert decls == ""
        assert variables == {}

    def test_int_filter_uses_bigint(self):
        where, decls, variables = server._build_where(
            {
                "projectId": {"predicate": "projectId: {_eq: $projectId}", "value": 42},
            }
        )
        assert ", where: {projectId: {_eq: $projectId}}" == where
        assert ", $projectId: bigint" == decls
        assert variables == {"projectId": 42}

    def test_str_filter_uses_string(self):
        where, decls, variables = server._build_where(
            {
                "severity": {"predicate": "severity: {severity: {_ilike: $severity}}", "value": "High"},
            }
        )
        assert "severity" in where
        assert ", $severity: String" == decls
        assert variables == {"severity": "High"}

    def test_multiple_filters_combined(self):
        where, decls, variables = server._build_where(
            {
                "projectId": {"predicate": "projectId: {_eq: $projectId}", "value": 1},
                "severity": {"predicate": "severity: {severity: {_ilike: $severity}}", "value": "High"},
            }
        )
        assert "projectId" in where
        assert "severity" in where
        assert "$projectId: bigint" in decls
        assert "$severity: String" in decls
        assert variables == {"projectId": 1, "severity": "High"}


class TestNullCoercion:
    """_GWBase should coerce None to type-appropriate zero values."""

    def test_null_string_becomes_empty(self):
        c = server.ClientSummary.model_validate({"name": None, "description": None})
        assert c.name == ""
        assert c.description == ""

    def test_null_int_becomes_zero(self):
        c = server.ClientSummary.model_validate({"id": None})
        assert c.id == 0

    def test_null_bool_becomes_false(self):
        t = server.Target.model_validate({"compromised": None})
        assert t.compromised is False

    def test_nested_ref_null_becomes_none(self):
        f = server.FindingSummary.model_validate({"severity": None})
        assert f.severity is None

    def test_values_passthrough(self):
        c = server.ClientSummary.model_validate({"id": 5, "name": "Acme", "shortName": "ACM"})
        assert c.id == 5
        assert c.name == "Acme"
        assert c.shortName == "ACM"


class TestAggregateCount:
    def test_flattens_hasura_wrapper(self):
        agg = server.AggregateCount.model_validate({"aggregate": {"count": 42}})
        assert agg.count == 42

    def test_empty_aggregate(self):
        agg = server.AggregateCount.model_validate({"aggregate": {}})
        assert agg.count == 0

    def test_missing_aggregate(self):
        agg = server.AggregateCount.model_validate({})
        assert agg.count == 0


class TestSearchTypes:
    def test_all_search_types_mapped(self):
        expected = {"clients", "projects", "findings", "observations", "activity-logs"}
        assert set(server._SEARCH_QUERIES) == expected

    def test_valid_search_types_none_returns_all(self):
        assert server._valid_search_types(None) == set(server._SEARCH_QUERIES)

    def test_valid_search_types_filters_unknown(self):
        assert server._valid_search_types("clients,bogus,findings") == {"clients", "findings"}

    def test_valid_search_types_strips_whitespace(self):
        assert server._valid_search_types("clients, findings ") == {"clients", "findings"}

    def test_search_entries_have_matching_field(self):
        """Each _SEARCH_QUERIES entry's 'field' must exist on SearchResult."""
        sr_fields = set(server.SearchResult.model_fields)
        for key, entry in server._SEARCH_QUERIES.items():
            assert (
                entry["field"] in sr_fields
            ), f"search entry {key!r} references nonexistent SearchResult.{entry['field']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
