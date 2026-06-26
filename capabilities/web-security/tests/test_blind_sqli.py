"""Tests for the blind SQLi extraction tools."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "blind_sqli.py"
SPEC = importlib.util.spec_from_file_location("blind_sqli", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

BlindSQLiTools = MODULE.BlindSQLiTools
_resolve_field = MODULE._resolve_field


@pytest.fixture
def toolset() -> BlindSQLiTools:
    return BlindSQLiTools()


class TestToolDiscovery:
    def test_tools_class_exists(self) -> None:
        assert hasattr(MODULE, "BlindSQLiTools")

    def test_is_toolset(self) -> None:
        from dreadnode.agents.tools import Toolset

        assert issubclass(BlindSQLiTools, Toolset)

    def test_tool_methods_registered(self, toolset: BlindSQLiTools) -> None:
        tools = toolset.get_tools()
        names = {t.name for t in tools}
        assert names == {
            "sqli_test_condition",
            "sqli_extract_string",
            "sqli_extract_int",
            "sqli_get_request_count",
            "sqli_reset",
        }


class TestDefaultConfig:
    def test_timeout(self, toolset: BlindSQLiTools) -> None:
        assert toolset.timeout == 30

    def test_delay(self, toolset: BlindSQLiTools) -> None:
        assert toolset.delay == 0.3

    def test_max_length(self, toolset: BlindSQLiTools) -> None:
        assert toolset.max_length == 80


class TestResolveField:
    def test_simple_field(self) -> None:
        assert _resolve_field({"count": 5}, "count") == 5

    def test_nested_field(self) -> None:
        assert _resolve_field({"paging": {"total": 10}}, "paging.total") == 10

    def test_list_index(self) -> None:
        assert _resolve_field({"items": [1, 2, 3]}, "items.1") == 2

    def test_missing_field(self) -> None:
        assert _resolve_field({"a": 1}, "b") is None

    def test_missing_nested(self) -> None:
        assert _resolve_field({"a": {"b": 1}}, "a.c") is None

    def test_list_out_of_bounds(self) -> None:
        assert _resolve_field({"items": [1]}, "items.5") is None

    def test_non_dict_traversal(self) -> None:
        assert _resolve_field({"a": "string"}, "a.b") is None


class TestRequestCount:
    @pytest.mark.asyncio
    async def test_initial_count_zero(self, toolset: BlindSQLiTools) -> None:
        result = await toolset.get_request_count()
        assert "0" in result

    @pytest.mark.asyncio
    async def test_reset_clears_count(self, toolset: BlindSQLiTools) -> None:
        # Ensure _client is properly None (not a PrivateAttr sentinel)
        toolset.__dict__["_request_count"] = 42
        toolset.__dict__["_client"] = None
        result = await toolset.reset()
        assert "0" in result
        assert toolset._request_count == 0
