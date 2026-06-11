#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "shodan>=1.31.0",
# ]
# ///
"""Shodan internet intelligence tools exposed as an MCP server.

Provides host search, IP reconnaissance, DNS lookups, CVE/exploit
intelligence, and API usage tracking via the Shodan API.

Environment variables:
    SHODAN_API_KEY: Required. Your Shodan API key.
    SHODAN_API_URL: Optional. Base URL for a Shodan-compatible mock service.
"""

from __future__ import annotations

import json
import os
from typing import Annotated
from urllib import parse, request

import shodan
from fastmcp import FastMCP

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_API_URL = os.environ.get("SHODAN_API_URL", "").rstrip("/")

mcp = FastMCP("shodan")


class _HttpNamespace:
    def __init__(self, client: "_HttpShodanClient", prefix: str) -> None:
        self._client = client
        self._prefix = prefix

    def resolve(self, hostnames: str) -> dict:
        return self._client.get_json(
            f"{self._prefix}/resolve", {"hostnames": hostnames}
        )

    def reverse(self, ips: str) -> dict:
        return self._client.get_json(f"{self._prefix}/reverse", {"ips": ips})

    def search(self, query: str, **options: object) -> dict:
        return self._client.get_json(
            f"{self._prefix}/search", {"query": query, **options}
        )

    def tags(self, size: int = 20) -> object:
        return self._client.get_json(f"{self._prefix}/tags", {"size": size})


class _HttpShodanClient:
    """Small Shodan-compatible HTTP adapter for task-local mock services."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.dns = _HttpNamespace(self, "/dns")
        self.exploits = _HttpNamespace(self, "/exploits")
        self.queries = _HttpNamespace(self, "/shodan/query")

    def get_json(self, path: str, params: dict[str, object] | None = None) -> object:
        query_params = dict(params or {})
        if self.api_key:
            query_params["key"] = self.api_key
        query = parse.urlencode(query_params, doseq=True)
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"

        req = request.Request(url, headers={"Accept": "application/json"})
        with request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
        return json.loads(body) if body else {}

    def search(self, query: str, **options: object) -> dict:
        result = self.get_json("/shodan/host/search", {"query": query, **options})
        return result if isinstance(result, dict) else {}

    def host(self, ip: str, history: bool = False) -> dict:
        result = self.get_json(
            f"/shodan/host/{parse.quote(ip, safe='')}",
            {"history": str(history).lower()},
        )
        return result if isinstance(result, dict) else {}

    def count(self, query: str, **options: object) -> dict:
        result = self.get_json("/shodan/host/count", {"query": query, **options})
        return result if isinstance(result, dict) else {}

    def ports(self) -> object:
        return self.get_json("/shodan/ports")

    def protocols(self) -> object:
        return self.get_json("/shodan/protocols")

    def info(self) -> dict:
        result = self.get_json("/api-info")
        return result if isinstance(result, dict) else {}


def _get_client() -> shodan.Shodan | _HttpShodanClient:
    if not SHODAN_API_KEY:
        raise RuntimeError(
            "SHODAN_API_KEY environment variable is not set. "
            "Get your API key at https://account.shodan.io"
        )
    if SHODAN_API_URL:
        return _HttpShodanClient(SHODAN_API_URL, SHODAN_API_KEY)
    return shodan.Shodan(SHODAN_API_KEY)


def _safe_json(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


# ── Core Search ───────────────────────────────────────────────────────


@mcp.tool()
def shodan_host_search(
    query: Annotated[
        str,
        "Shodan search query (e.g., 'apache city:\"San Francisco\"', 'port:502 tag:ics')",
    ],
    facets: Annotated[
        str | None, "Comma-separated facets for aggregation (e.g., 'country,org,port')"
    ] = None,
    page: Annotated[int, "Page number for pagination"] = 1,
) -> str:
    """Search Shodan for hosts matching a query.

    Returns matching hosts with IP, port, org, hostnames, location,
    vulnerabilities, and optional facet aggregations.

    Common queries:
        org:"Target Corp"
        hostname:example.com
        port:3389 org:"Target Corp"
        ssl.cert.subject.cn:example.com
        http.title:"Dashboard"
        vuln:CVE-2021-44228
        product:"Apache" version:"2.4.49"
    """
    api = _get_client()
    options: dict = {"page": page}
    if facets:
        options["facets"] = facets

    results = api.search(query, **options)

    matches = []
    for match in results.get("matches", []):
        entry: dict = {
            "ip": match.get("ip_str"),
            "port": match.get("port"),
            "org": match.get("org"),
            "hostnames": match.get("hostnames", []),
            "domains": match.get("domains", []),
            "transport": match.get("transport"),
            "product": match.get("product"),
            "version": match.get("version"),
        }
        if match.get("vulns"):
            entry["vulns"] = (
                list(match["vulns"].keys())
                if isinstance(match["vulns"], dict)
                else match["vulns"]
            )
        if match.get("location"):
            loc = match["location"]
            entry["location"] = {
                "country": loc.get("country_name"),
                "city": loc.get("city"),
            }
        matches.append(entry)

    return _safe_json(
        {
            "total": results.get("total", 0),
            "matches": matches,
            "facets": results.get("facets", {}),
        }
    )


@mcp.tool()
def shodan_host_info(
    ip: Annotated[str, "IP address to look up (e.g., '8.8.8.8')"],
    history: Annotated[bool, "Include historical banners"] = False,
) -> str:
    """Get detailed information about a specific IP address.

    Returns open ports, services, OS, organization, hostnames, location,
    vulnerabilities, and service banners.
    """
    api = _get_client()
    host = api.host(ip, history=history)

    return _safe_json(
        {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "vulns": host.get("vulns", []),
            "tags": host.get("tags", []),
            "last_update": host.get("last_update"),
            "location": {
                "country": host.get("country_name"),
                "city": host.get("city"),
                "asn": host.get("asn"),
                "isp": host.get("isp"),
            },
            "data": [
                {
                    "port": svc.get("port"),
                    "transport": svc.get("transport"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "banner": (svc.get("data", "")[:500] if svc.get("data") else None),
                }
                for svc in host.get("data", [])
            ],
        }
    )


@mcp.tool()
def shodan_count(
    query: Annotated[str, "Shodan search query"],
    facets: Annotated[
        str | None, "Comma-separated facets for aggregated counts"
    ] = None,
) -> str:
    """Get result count for a query without consuming search credits.

    Always use this before a full search to check scope and avoid
    wasting API credits on overly broad queries.
    """
    api = _get_client()
    options: dict = {}
    if facets:
        options["facets"] = facets

    result = api.count(query, **options)
    return _safe_json(
        {
            "total": result.get("total", 0),
            "facets": result.get("facets", {}),
        }
    )


# ── DNS ───────────────────────────────────────────────────────────────


@mcp.tool()
def shodan_dns_lookup(
    hostnames: Annotated[
        list[str], "Hostnames to resolve (e.g., ['example.com', 'api.example.com'])"
    ],
) -> str:
    """Resolve domain names to IP addresses via Shodan DNS."""
    api = _get_client()
    result = api.dns.resolve(",".join(hostnames))
    return _safe_json(result)


@mcp.tool()
def shodan_dns_reverse(
    ips: Annotated[list[str], "IP addresses to reverse lookup (e.g., ['8.8.8.8'])"],
) -> str:
    """Reverse DNS lookup — find hostnames for IP addresses."""
    api = _get_client()
    result = api.dns.reverse(",".join(ips))
    return _safe_json(result)


# ── Exploits & Intelligence ──────────────────────────────────────────


@mcp.tool()
def shodan_exploits_search(
    query: Annotated[
        str, "Exploit search query (e.g., 'CVE-2021-44228', 'Apache', 'Modbus')"
    ],
    facets: Annotated[
        str | None, "Facets for aggregation (e.g., 'type,platform,author')"
    ] = None,
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """Search the Shodan Exploits database for known exploits and CVEs.

    Returns exploit details including description, author, type, platform,
    affected CVEs, and source references.
    """
    api = _get_client()
    options: dict = {"page": page}
    if facets:
        options["facets"] = facets

    result = api.exploits.search(query, **options)

    matches = []
    for exploit in result.get("matches", []):
        matches.append(
            {
                "id": exploit.get("_id"),
                "description": exploit.get("description", "")[:500],
                "author": exploit.get("author"),
                "type": exploit.get("type"),
                "platform": exploit.get("platform"),
                "date": exploit.get("date"),
                "source": exploit.get("source"),
                "cve": exploit.get("cve", []),
            }
        )

    return _safe_json(
        {
            "total": result.get("total", 0),
            "matches": matches,
            "facets": result.get("facets", {}),
        }
    )


# ── Reference Data ───────────────────────────────────────────────────


@mcp.tool()
def shodan_ports() -> str:
    """List all port numbers that Shodan actively crawls."""
    api = _get_client()
    return _safe_json(api.ports())


@mcp.tool()
def shodan_protocols() -> str:
    """List all protocols Shodan can distinguish in banner grabs."""
    api = _get_client()
    return _safe_json(api.protocols())


# ── Community Queries ────────────────────────────────────────────────


@mcp.tool()
def shodan_query_search(
    query: Annotated[str, "Search term (e.g., 'SCADA', 'webcam', 'database')"],
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """Search community-shared Shodan queries for inspiration."""
    api = _get_client()
    result = api.queries.search(query, page=page)
    return _safe_json(
        {
            "total": result.get("total", 0),
            "matches": [
                {
                    "title": q.get("title"),
                    "description": q.get("description"),
                    "query": q.get("query"),
                    "votes": q.get("votes"),
                    "tags": q.get("tags", []),
                }
                for q in result.get("matches", [])
            ],
        }
    )


@mcp.tool()
def shodan_query_tags(
    size: Annotated[int, "Number of tags to return"] = 20,
) -> str:
    """Get popular tags for community-shared Shodan queries."""
    api = _get_client()
    return _safe_json(api.queries.tags(size=size))


# ── API Status ───────────────────────────────────────────────────────


@mcp.tool()
def shodan_api_info() -> str:
    """Check API plan, remaining credits, and account status."""
    api = _get_client()
    info = api.info()
    return _safe_json(
        {
            "plan": info.get("plan"),
            "query_credits": info.get("query_credits"),
            "scan_credits": info.get("scan_credits"),
            "unlocked": info.get("unlocked"),
        }
    )
