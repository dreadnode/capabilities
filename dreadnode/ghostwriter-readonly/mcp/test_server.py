#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "aiohttp>=3.9,<4.0",
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
        # get_tools() returns a dict keyed by tool name
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
        assert expected == tool_names, (
            f"Unexpected: {tool_names - expected}, Missing: {expected - tool_names}"
        )

    def test_tool_count(self):
        import asyncio

        tools = asyncio.run(server.mcp.get_tools())
        assert len(tools) == 22


class TestConnectionState:
    def setup_method(self):
        server._gql_client = None
        server._gql_session = None
        server._config = {}

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


class TestNotesTables:
    def test_all_note_types_mapped(self):
        assert "client" in server.NOTE_TABLES
        assert "project" in server.NOTE_TABLES
        assert "domain" in server.NOTE_TABLES
        assert "server" in server.NOTE_TABLES

    def test_table_names_match_convention(self):
        for note_type, (table, fk) in server.NOTE_TABLES.items():
            assert table == f"{note_type}Note"
            assert fk == f"{note_type}Id"


class TestHelpers:
    def test_where_empty(self):
        where, decl = server._where([], [])
        assert where == ""
        assert decl == ""

    def test_where_single_condition(self):
        where, decl = server._where(
            ["projectId: {_eq: $projectId}"],
            ["$projectId: bigint"],
        )
        assert "where:" in where
        assert "projectId" in where
        assert "$projectId: bigint" in decl

    def test_where_multiple_conditions(self):
        where, decl = server._where(
            ["projectId: {_eq: $projectId}", "severity: {_ilike: $severity}"],
            ["$projectId: bigint", "$severity: String"],
        )
        assert "projectId" in where
        assert "severity" in where
        assert "$projectId: bigint" in decl
        assert "$severity: String" in decl


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
