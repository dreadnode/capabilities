"""Tests for DNS rebinding tools."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest


def _install_dreadnode_tools_stub() -> None:
    existing = sys.modules.get("dreadnode.agents.tools")
    if existing is not None and hasattr(existing, "FunctionCall"):
        return

    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    class _Tool:
        def __init__(self, name: str, description: str, catch: bool) -> None:
            self.name = name
            self.description = description
            self.catch = catch
            self.parameters_schema = {"properties": {}}

    def tool_method(*, name: str, catch: bool = False):
        def decorator(fn):
            fn._tool_metadata = {
                "name": name,
                "catch": catch,
                "description": fn.__doc__ or "",
            }
            return fn

        return decorator

    class Toolset:
        def get_tools(self):
            discovered = []
            for attr_name in dir(self):
                value = getattr(self, attr_name)
                meta = getattr(value, "_tool_metadata", None)
                if meta:
                    discovered.append(_Tool(meta["name"], meta["description"], meta["catch"]))
            return discovered

    tools.Toolset = Toolset
    tools.tool_method = tool_method
    agents.tools = tools
    dreadnode.agents = agents

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.tools"] = tools


_install_dreadnode_tools_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "dns_rebinding.py"
SPEC = importlib.util.spec_from_file_location("dns_rebinding", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DnsRebinding = MODULE.DnsRebinding
_ip_to_hex = MODULE._ip_to_hex
_make_hostname = MODULE._make_hostname


@pytest.fixture
def toolset() -> DnsRebinding:
    return DnsRebinding()


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: DnsRebinding) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "generate_rebinding_hostname",
            "resolve_rebinding_hostname",
            "list_rebinding_presets",
        }


class TestIpConversion:
    def test_localhost(self) -> None:
        assert _ip_to_hex("127.0.0.1") == "7f000001"

    def test_metadata(self) -> None:
        assert _ip_to_hex("169.254.169.254") == "a9fea9fe"

    def test_cloudflare(self) -> None:
        assert _ip_to_hex("1.1.1.1") == "01010101"

    def test_invalid_ip(self) -> None:
        with pytest.raises(OSError):
            _ip_to_hex("not.an.ip.address")


class TestHostnameGeneration:
    def test_basic(self) -> None:
        assert _make_hostname("1.1.1.1", "127.0.0.1") == "01010101.7f000001.rbndr.us"

    def test_metadata(self) -> None:
        assert _make_hostname("1.1.1.1", "169.254.169.254") == "01010101.a9fea9fe.rbndr.us"


class TestGenerateTool:
    @pytest.mark.asyncio
    async def test_generate_basic(self, toolset: DnsRebinding) -> None:
        result = await toolset.generate_rebinding_hostname("8.8.8.8", "127.0.0.1")
        assert "08080808.7f000001.rbndr.us" in result
        assert "8.8.8.8 <-> 127.0.0.1" in result

    @pytest.mark.asyncio
    async def test_generate_metadata_includes_ssrf_payload(self, toolset: DnsRebinding) -> None:
        result = await toolset.generate_rebinding_hostname("1.1.1.1", "169.254.169.254")
        assert "/latest/meta-data/" in result

    @pytest.mark.asyncio
    async def test_generate_non_metadata_no_ssrf_line(self, toolset: DnsRebinding) -> None:
        result = await toolset.generate_rebinding_hostname("1.1.1.1", "127.0.0.1")
        assert "/latest/meta-data/" not in result

    @pytest.mark.asyncio
    async def test_generate_invalid_ip(self, toolset: DnsRebinding) -> None:
        result = await toolset.generate_rebinding_hostname("notanip", "127.0.0.1")
        assert "Error" in result


class TestResolveTool:
    @pytest.mark.asyncio
    async def test_resolve_multiple_ips(self, toolset: DnsRebinding) -> None:
        ips = iter(["1.1.1.1", "127.0.0.1", "1.1.1.1", "127.0.0.1", "1.1.1.1", "127.0.0.1"])
        with patch("socket.gethostbyname", side_effect=ips):
            result = await toolset.resolve_rebinding_hostname("test.rbndr.us")
        assert "rebinding active" in result

    @pytest.mark.asyncio
    async def test_resolve_single_ip(self, toolset: DnsRebinding) -> None:
        with patch("socket.gethostbyname", return_value="1.1.1.1"):
            result = await toolset.resolve_rebinding_hostname("test.rbndr.us")
        assert "single IP" in result

    @pytest.mark.asyncio
    async def test_resolve_failure(self, toolset: DnsRebinding) -> None:
        import socket

        with patch("socket.gethostbyname", side_effect=socket.gaierror("nope")):
            result = await toolset.resolve_rebinding_hostname("bad.host")
        assert "Error" in result


class TestPresetsTool:
    @pytest.mark.asyncio
    async def test_presets_contains_all_entries(self, toolset: DnsRebinding) -> None:
        result = await toolset.list_rebinding_presets()
        for name in ("localhost", "metadata", "docker", "k8s-api", "internal-10", "internal-192"):
            assert name in result
        assert "rbndr.us" in result
