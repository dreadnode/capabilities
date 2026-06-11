from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import parse


MODULE_PATH = Path(__file__).resolve().parents[1] / "mcp" / "shodan.py"


def load_shodan_module():
    spec = importlib.util.spec_from_file_location("asm_shodan_mcp_test", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MockShodanHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, list[str]]]] = []

    def do_GET(self) -> None:
        parsed = parse.urlparse(self.path)
        query = parse.parse_qs(parsed.query)
        self.requests.append((parsed.path, query))
        body = self.response_for(parsed.path, query)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        return

    @staticmethod
    def response_for(path: str, query: dict[str, list[str]]) -> object:
        if path == "/shodan/host/search":
            return {
                "total": 1,
                "matches": [
                    {
                        "ip_str": "203.0.113.10",
                        "port": 9200,
                        "org": "Target Corp",
                        "hostnames": ["search.target.local"],
                        "domains": ["target.local"],
                        "transport": "tcp",
                        "product": "Elasticsearch",
                        "version": "7.10.0",
                        "vulns": {"CVE-2021-44228": {}},
                    }
                ],
                "facets": {"port": [{"value": 9200, "count": 1}]},
            }
        if path == "/shodan/host/203.0.113.10":
            return {
                "ip_str": "203.0.113.10",
                "org": "Target Corp",
                "ports": [9200],
                "hostnames": ["search.target.local"],
                "domains": ["target.local"],
                "vulns": ["CVE-2021-44228"],
                "country_name": "United States",
                "city": "New York",
                "asn": "AS64500",
                "isp": "Example ISP",
                "data": [
                    {
                        "port": 9200,
                        "product": "Elasticsearch",
                        "version": "7.10.0",
                        "data": "banner",
                    }
                ],
            }
        if path == "/shodan/host/count":
            return {
                "total": 1,
                "facets": {"product": [{"value": "Elasticsearch", "count": 1}]},
            }
        if path == "/dns/resolve":
            return {"search.target.local": "203.0.113.10"}
        if path == "/dns/reverse":
            return {"203.0.113.10": ["search.target.local"]}
        if path == "/exploits/search":
            return {
                "total": 1,
                "matches": [
                    {
                        "_id": "EXP-1",
                        "description": "Elasticsearch exploit",
                        "author": "researcher",
                        "type": "remote",
                        "platform": "linux",
                        "date": "2024-01-01",
                        "source": "mock",
                        "cve": ["CVE-2021-44228"],
                    }
                ],
                "facets": {},
            }
        if path == "/shodan/ports":
            return [80, 443, 9200]
        if path == "/shodan/protocols":
            return {"http": "HTTP"}
        if path == "/api-info":
            return {
                "plan": "mock",
                "query_credits": 100,
                "scan_credits": 0,
                "unlocked": True,
            }
        if path == "/shodan/query/search":
            return {
                "total": 1,
                "matches": [{"title": "Databases", "query": "port:9200"}],
            }
        if path == "/shodan/query/tags":
            return ["database"]
        return {}


def start_mock_server():
    MockShodanHandler.requests = []
    server = HTTPServer(("127.0.0.1", 0), MockShodanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_http_shodan_client_uses_mock_base_url_and_api_key():
    shodan_mcp = load_shodan_module()
    server, base_url = start_mock_server()
    try:
        client = shodan_mcp._HttpShodanClient(base_url, "test-key")

        search = client.search('org:"Target Corp"', facets="port")
        host = client.host("203.0.113.10", history=True)
        count = client.count("port:9200")
        resolved = client.dns.resolve("search.target.local")
        exploits = client.exploits.search("CVE-2021-44228")

        assert search["matches"][0]["ip_str"] == "203.0.113.10"
        assert host["ports"] == [9200]
        assert count["total"] == 1
        assert resolved["search.target.local"] == "203.0.113.10"
        assert exploits["matches"][0]["cve"] == ["CVE-2021-44228"]
        assert all(
            request_query.get("key") == ["test-key"]
            for _, request_query in MockShodanHandler.requests
        )
    finally:
        server.shutdown()


def test_shodan_tool_formatting_with_mock_client(monkeypatch):
    shodan_mcp = load_shodan_module()
    server, base_url = start_mock_server()
    client = shodan_mcp._HttpShodanClient(base_url, "test-key")
    monkeypatch.setattr(shodan_mcp, "_get_client", lambda: client)
    try:
        host = json.loads(shodan_mcp.shodan_host_info("203.0.113.10", history=True))
        search = json.loads(
            shodan_mcp.shodan_host_search('org:"Target Corp"', facets="port")
        )
        exploits = json.loads(shodan_mcp.shodan_exploits_search("CVE-2021-44228"))
        api_info = json.loads(shodan_mcp.shodan_api_info())

        assert host["location"]["asn"] == "AS64500"
        assert host["data"][0]["banner"] == "banner"
        assert search["matches"][0]["vulns"] == ["CVE-2021-44228"]
        assert exploits["matches"][0]["id"] == "EXP-1"
        assert api_info["plan"] == "mock"
    finally:
        server.shutdown()
