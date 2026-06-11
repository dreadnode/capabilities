from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "mcp" / "bbot.py"


def load_bbot_module():
    spec = importlib.util.spec_from_file_location("asm_bbot_mcp_test", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeNeo4j:
    def __init__(self, responses: list[list[dict]] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, dict | None]] = []

    async def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        self.calls.append((cypher, params))
        if self.responses:
            return self.responses.pop(0)
        return []


def run(coro):
    return asyncio.run(coro)


def test_get_db_schema_collects_labels_relationships_and_properties(monkeypatch):
    bbot = load_bbot_module()
    fake = FakeNeo4j(
        [
            [{"label": "DNS_NAME"}, {"label": "URL"}],
            [{"relationshipType": "A"}, {"relationshipType": "httpx"}],
            [
                {
                    "nodeType": ":DNS_NAME",
                    "propertyName": "data",
                    "propertyTypes": ["String"],
                    "mandatory": False,
                }
            ],
            [
                {
                    "relType": ":A",
                    "propertyName": "module",
                    "propertyTypes": ["String"],
                    "mandatory": False,
                }
            ],
        ]
    )
    monkeypatch.setattr(bbot, "_neo4j", fake)

    result = json.loads(run(bbot.get_db_schema()))

    assert result["node_labels"] == ["DNS_NAME", "URL"]
    assert result["relationship_types"] == ["A", "httpx"]
    assert result["node_properties"]["DNS_NAME"][0]["property"] == "data"
    assert result["relationship_properties"]["A"][0]["property"] == "module"
    assert len(fake.calls) == 4


def test_explore_nodes_builds_parameterized_filter(monkeypatch):
    bbot = load_bbot_module()
    fake = FakeNeo4j([[{"node": {"data": "dev.target.local"}}]])
    monkeypatch.setattr(bbot, "_neo4j", fake)

    result = json.loads(run(bbot.explore_nodes("DNS_NAME", "data CONTAINS dev", 25)))

    cypher, params = fake.calls[0]
    assert "MATCH (node:DNS_NAME)" in cypher
    assert "node.`data`" in cypher
    assert "$value" in cypher
    assert params == {"limit": 25, "value": "dev"}
    assert result[0]["node"]["data"] == "dev.target.local"


def test_explore_nodes_rejects_cypher_identifier_injection():
    bbot = load_bbot_module()

    with pytest.raises(ValueError, match="Invalid label"):
        run(bbot.explore_nodes("DNS_NAME) DETACH DELETE n //", None, 10))

    with pytest.raises(ValueError, match="Invalid property"):
        run(bbot.explore_nodes("DNS_NAME", "data`) MATCH (n) RETURN n //=x", 10))


def test_explore_relationships_validates_identifiers_and_limits(monkeypatch):
    bbot = load_bbot_module()
    fake = FakeNeo4j([[{"source": "a", "relationship": "r", "target": "b"}]])
    monkeypatch.setattr(bbot, "_neo4j", fake)

    run(bbot.explore_relationships("DNS_NAME", "A", "IP_ADDRESS", 3))

    cypher, params = fake.calls[0]
    assert "MATCH (source:DNS_NAME)-[relationship:A]->(target:IP_ADDRESS)" in cypher
    assert params == {"limit": 3}
    with pytest.raises(ValueError, match="Limit"):
        run(bbot.explore_relationships(limit=0))


def test_get_subdomains_and_technologies_use_envelope_fallbacks(monkeypatch):
    bbot = load_bbot_module()
    fake = FakeNeo4j(
        [
            [{"name": "api.target.local"}],
            [{"name": "JBoss Application Server", "version": "4.0", "usage": 1}],
        ]
    )
    monkeypatch.setattr(bbot, "_neo4j", fake)

    assert (
        json.loads(run(bbot.get_subdomains("target.local", 100)))[0]["name"]
        == "api.target.local"
    )
    assert (
        json.loads(run(bbot.get_technologies()))[0]["name"]
        == "JBoss Application Server"
    )

    subdomain_query = fake.calls[0][0]
    technology_query = fake.calls[1][0]
    assert "coalesce(n.name, n.data, n.host)" in subdomain_query
    assert "coalesce(t.name, t.data)" in technology_query


def test_get_screenshot_resolves_bbot_scan_path(monkeypatch, tmp_path):
    bbot = load_bbot_module()
    screenshot = tmp_path / "scans" / "scan-one" / "screenshots" / "app.png"
    screenshot.parent.mkdir(parents=True)
    screenshot.write_bytes(b"png")

    fake = FakeNeo4j(
        [
            [
                {
                    "web_props": {
                        "uuid": "shot-1",
                        "data": json.dumps(
                            {
                                "path": "screenshots/app.png",
                                "url": "https://app.target.local",
                            }
                        ),
                        "scan": "scan-one",
                    },
                    "scan_props": {"data": json.dumps({"name": "scan-one"})},
                }
            ]
        ]
    )
    monkeypatch.setattr(bbot, "_neo4j", fake)
    monkeypatch.setattr(bbot, "BBOT_DATA_DIR", str(tmp_path))

    result = json.loads(run(bbot.get_screenshot(uuid="shot-1")))

    assert result["path"] == str(screenshot)
    assert result["url"] == "https://app.target.local"
    assert result["uuid"] == "shot-1"


def test_get_screenshot_reports_checked_paths_when_missing(monkeypatch, tmp_path):
    bbot = load_bbot_module()
    fake = FakeNeo4j(
        [
            [
                {
                    "web_props": {
                        "uuid": "shot-1",
                        "path": "missing.png",
                        "scan": "scan-one",
                    },
                    "scan_props": {"name": "scan-one"},
                }
            ]
        ]
    )
    monkeypatch.setattr(bbot, "_neo4j", fake)
    monkeypatch.setattr(bbot, "BBOT_DATA_DIR", str(tmp_path))

    result = json.loads(run(bbot.get_screenshot(uuid="shot-1")))

    assert result["error"] == "Screenshot file not found."
    assert (
        str(tmp_path / "scans" / "scan-one" / "missing.png") in result["checked_paths"]
    )


def test_run_bbot_scan_with_graph_api_uses_stdout_not_neo4j(monkeypatch):
    bbot = load_bbot_module()
    captured: list[str] = []
    captured_env: dict | None = None

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return (
                b'{"type":"DNS_NAME","scope_description":"in-scope","module":"dns","data":"api.example.com"}\n',
                b"",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        nonlocal captured_env
        captured.extend(args)
        captured_env = kwargs.get("env")
        return FakeProc()

    monkeypatch.setattr(
        bbot.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    result = run(
        bbot.run_bbot_scan(
            targets=["*.example.com"],
            modules=[
                "subfinder",
                "subdomainfinder",
                "subdomain_bruteforce",
                "subenum",
                "crtsh",
                "dns_zone_transfer",
                "fastdial",
                "find_subdomains",
                "gau",
                "gcp_storage_scan",
                "portscan",
                "s3_scan",
                "azure_blob_scan",
                "technologies",
                "massdns",
                "naabu",
                "nuclei",
                "screenshot",
                "web_screenshots",
                "web_screenshot",
                "webenum",
                "wappalyzer",
                "httpx",
            ],
            flags=["subdomain-enum", "-y", "--t=25"],
            presets=[
                "asset-discovery-and-enrichment",
                "asset-discovery",
                "asset-discovery-web-endpoints",
                "discovery",
                "subdomain_enumeration",
                "subdomain_discovery",
                "web_breach",
                "web_basic",
                "web_discovery",
                "web_scan",
                "web-port-scan-and-tech-detect",
                "web-and-portscan",
                "nuclei",
            ],
            config=[
                "modules.httpx.timeout=10",
                "modules.shodan_dns.enabled=false",
                "scope.distance=1",
                "scope.report_distance=1",
            ],
            extra_args=["--scope-distance", "1"],
            graph_api_url="http://graph.local",
        )
    )

    assert "--json" in captured
    assert "--output-modules" in captured
    assert "stdout" in captured
    assert "--no-deps" in captured
    assert "--exclude-modules" in captured
    assert "portscan" in captured
    assert "gowitness" in captured
    assert "baddns" in captured
    assert "httpx" in captured
    assert "subdomaincenter" in captured
    assert "bucket_amazon" in captured
    assert "bucket_google" in captured
    assert "bucket_microsoft" in captured
    assert "subfinder" not in captured
    assert "subdomainfinder" not in captured
    assert "subdomain_bruteforce" not in captured
    assert "subenum" not in captured
    assert "crtsh" not in captured
    assert "dns_zone_transfer" not in captured
    assert "fastdial" not in captured
    assert "find_subdomains" not in captured
    assert "gau" not in captured
    assert "massdns" not in captured
    assert "naabu" not in captured
    assert "nuclei" not in captured
    assert "screenshot" not in captured
    assert "web_screenshots" not in captured
    assert "web_screenshot" not in captured
    assert "webenum" not in captured
    assert "wappalyzer" not in captured
    assert "-y" not in captured
    assert "--t=25" not in captured
    assert "web-and-portscan" not in captured
    assert "subdomain-enum" in captured
    assert "web-basic" in captured
    assert "web_basic" not in captured
    assert "subdomain_enumeration" not in captured
    assert "asset-discovery" not in captured
    assert "asset-discovery-web-endpoints" not in captured
    assert captured_env is not None
    assert "asm-bbot-home-" in captured_env["HOME"]
    assert "neo4j" not in captured
    assert "example.com" in captured
    assert "*.example.com" not in captured
    assert "modules.http.timeout=10" in captured
    assert "scope.search_distance=1" in captured
    assert "scope.distance=1" not in captured
    assert "scope.report_distance=1" not in captured
    assert "--scope-distance" not in captured
    assert "modules.shodan_dns.enabled=false" not in captured
    assert "modules.neo4j.uri=bolt://localhost:7687" not in captured
    assert "event_count" in result
    assert "api.example.com" in result


def test_run_bbot_scan_with_graph_api_reports_diagnostic_only_output(monkeypatch):
    bbot = load_bbot_module()

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return (
                b"[WARN] Please specify --allow-deadly to continue\n",
                b"",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(
        bbot.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    result = run(
        bbot.run_bbot_scan(
            targets=["example.com"],
            presets=["nuclei-budget"],
            graph_api_url="http://graph.local",
        )
    )

    assert "produced no usable BBOT JSON events" in result
    assert "Please specify --allow-deadly" in result
    assert '"event_count": 0' in result


def test_query_graph_uses_graph_api_when_provided(monkeypatch):
    bbot = load_bbot_module()
    fake = FakeNeo4j([[{"should_not": "be_used"}]])
    calls: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(bbot, "_neo4j", fake)

    def fake_query_graph_api(url, cypher, params=None):
        calls.append((url, cypher, params))
        return [{"count": 3}]

    monkeypatch.setattr(bbot, "_query_graph_api", fake_query_graph_api)

    result = json.loads(
        run(
            bbot.query_graph(
                "MATCH (n) RETURN count(n) AS count",
                {"limit": 10},
                graph_api_url="http://graph.local",
            )
        )
    )

    assert result == [{"count": 3}]
    assert calls == [
        ("http://graph.local", "MATCH (n) RETURN count(n) AS count", {"limit": 10})
    ]
    assert fake.calls == []
