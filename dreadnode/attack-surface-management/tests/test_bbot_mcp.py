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
    fake = FakeNeo4j([
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
    ])
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
    fake = FakeNeo4j([
        [{"name": "api.target.local"}],
        [{"name": "JBoss Application Server", "version": "4.0", "usage": 1}],
    ])
    monkeypatch.setattr(bbot, "_neo4j", fake)

    assert json.loads(run(bbot.get_subdomains("target.local", 100)))[0]["name"] == "api.target.local"
    assert json.loads(run(bbot.get_technologies()))[0]["name"] == "JBoss Application Server"

    subdomain_query = fake.calls[0][0]
    technology_query = fake.calls[1][0]
    assert "coalesce(n.name, n.data, n.host)" in subdomain_query
    assert "coalesce(t.name, t.data)" in technology_query


def test_get_screenshot_resolves_bbot_scan_path(monkeypatch, tmp_path):
    bbot = load_bbot_module()
    screenshot = tmp_path / "scans" / "scan-one" / "screenshots" / "app.png"
    screenshot.parent.mkdir(parents=True)
    screenshot.write_bytes(b"png")

    fake = FakeNeo4j([
        [
            {
                "web_props": {
                    "uuid": "shot-1",
                    "data": json.dumps({
                        "path": "screenshots/app.png",
                        "url": "https://app.target.local",
                    }),
                    "scan": "scan-one",
                },
                "scan_props": {"data": json.dumps({"name": "scan-one"})},
            }
        ]
    ])
    monkeypatch.setattr(bbot, "_neo4j", fake)
    monkeypatch.setattr(bbot, "BBOT_DATA_DIR", str(tmp_path))

    result = json.loads(run(bbot.get_screenshot(uuid="shot-1")))

    assert result["path"] == str(screenshot)
    assert result["url"] == "https://app.target.local"
    assert result["uuid"] == "shot-1"


def test_get_screenshot_reports_checked_paths_when_missing(monkeypatch, tmp_path):
    bbot = load_bbot_module()
    fake = FakeNeo4j([
        [
            {
                "web_props": {"uuid": "shot-1", "path": "missing.png", "scan": "scan-one"},
                "scan_props": {"name": "scan-one"},
            }
        ]
    ])
    monkeypatch.setattr(bbot, "_neo4j", fake)
    monkeypatch.setattr(bbot, "BBOT_DATA_DIR", str(tmp_path))

    result = json.loads(run(bbot.get_screenshot(uuid="shot-1")))

    assert result["error"] == "Screenshot file not found."
    assert str(tmp_path / "scans" / "scan-one" / "missing.png") in result["checked_paths"]
