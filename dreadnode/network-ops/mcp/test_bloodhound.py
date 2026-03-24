#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "neo4j>=5.0",
#   "aiohttp>=3.0",
# ]
# ///
"""Tests for bloodhound MCP server — no Neo4j/BloodHound required."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import bloodhound as server


class TestQueryCatalog:
    """Test the standard query catalog and progressive disclosure."""

    def test_all_queries_have_required_fields(self):
        for name, entry in server.STANDARD_QUERIES.items():
            assert "description" in entry, f"{name} missing description"
            assert "category" in entry, f"{name} missing category"
            assert "cypher" in entry, f"{name} missing cypher"

    def test_all_queries_have_nonempty_cypher(self):
        for name, entry in server.STANDARD_QUERIES.items():
            assert entry["cypher"].strip(), f"{name} has empty cypher"
            assert "MATCH" in entry["cypher"] or "RETURN" in entry["cypher"], \
                f"{name} cypher doesn't look like Cypher: {entry['cypher'][:50]}"

    @pytest.mark.asyncio
    async def test_list_queries_returns_all(self):
        results = await server.list_queries()
        assert len(results) == len(server.STANDARD_QUERIES)

    @pytest.mark.asyncio
    async def test_list_queries_filter_by_category(self):
        results = await server.list_queries(category="kerberos")
        assert all(r["category"] == "kerberos" for r in results)
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_list_queries_invalid_category(self):
        results = await server.list_queries(category="nonexistent")
        assert len(results) == 1
        assert "error" in results[0]
        assert "available_categories" in results[0]

    @pytest.mark.asyncio
    async def test_standard_query_unknown_name(self):
        with pytest.raises(ValueError, match="Unknown query"):
            await server.standard_query(name="not_a_real_query")

    def test_categories_cover_expected_domains(self):
        categories = {e["category"] for e in server.STANDARD_QUERIES.values()}
        # At minimum we should have these broad categories
        assert "kerberos" in categories
        assert "tier-zero" in categories
        assert "pki" in categories


class TestConnectionState:
    def setup_method(self):
        server._graph_driver = None
        server._api_token = None
        server._config = {}

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("BLOODHOUND_URL", "http://bh:8080")
        monkeypatch.setenv("BLOODHOUND_PASSWORD", "secret")
        monkeypatch.setenv("NEO4J_URL", "bolt://neo:7687")
        cfg = server._default_config()
        assert cfg["bloodhound_url"] == "http://bh:8080"
        assert cfg["password"] == "secret"
        assert cfg["neo4j_url"] == "bolt://neo:7687"

    @pytest.mark.asyncio
    async def test_ensure_connected_errors_without_password(self, monkeypatch):
        monkeypatch.delenv("BLOODHOUND_PASSWORD", raising=False)
        with pytest.raises(RuntimeError, match="Not connected"):
            await server._ensure_connected()

    @pytest.mark.asyncio
    async def test_query_requires_connection(self, monkeypatch):
        monkeypatch.delenv("BLOODHOUND_PASSWORD", raising=False)
        server._config = {}
        with pytest.raises(RuntimeError, match="Not connected"):
            await server.query(cypher="RETURN 1")


class TestToolRegistration:
    def test_expected_tools_registered(self):
        import asyncio
        tools = asyncio.run(server.mcp.list_tools())
        tool_names = {t.name for t in tools}
        expected = {"connect", "query", "standard_query", "list_queries"}
        assert expected == tool_names, f"Unexpected tools: {tool_names - expected}, Missing: {expected - tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
