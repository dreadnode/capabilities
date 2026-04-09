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
"""

from __future__ import annotations

import functools
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Annotated, Any

# This file is named `shodan.py`, which collides with the pip-installed
# `shodan` package. Python prepends the script's parent directory to
# `sys.path` when running a script directly, so a bare `import shodan` here
# would re-enter this very file (a partially-initialized self-import) and
# return a module object that has no `Shodan` class — every tool call would
# then crash inside `_get_client()` with `AttributeError: module 'shodan'
# has no attribute 'Shodan'`. Strip our own directory from sys.path before
# the import so we resolve to the real package.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if p and os.path.abspath(p) != _HERE]

import shodan  # noqa: E402
from fastmcp import FastMCP  # noqa: E402

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_API_BASE = "https://api.shodan.io"
# The legacy exploits.shodan.io endpoint that shodan-python 1.31.0 calls has
# been replaced by CVEDB. The library still hits the dead URL and chokes on
# the HTML response, so we call CVEDB directly. CVEDB does not require an
# API key for the lookups we use.
CVEDB_BASE = "https://cvedb.shodan.io"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

mcp = FastMCP("shodan")


def _get_client():  # type: ignore[no-untyped-def]
    """Construct a Shodan API client, failing closed if no key is configured.

    Raises:
        RuntimeError: if `SHODAN_API_KEY` is unset. `_catch_errors` translates
            this to a friendly string for the agent.
    """
    if not SHODAN_API_KEY:
        raise RuntimeError(
            "SHODAN_API_KEY environment variable is not set. "
            "Get your API key at https://account.shodan.io"
        )
    # pyright can't see through the sys.path manipulation above (it does
    # static analysis, not runtime), so it still thinks `shodan` is this
    # very file. The runtime correctly resolves to the pip package.
    return shodan.Shodan(SHODAN_API_KEY)  # pyright: ignore[reportAttributeAccessIssue]


def _safe_json(obj: object) -> str:
    """Serialize to indented JSON, falling back to `str()` for non-JSON types."""
    return json.dumps(obj, indent=2, default=str)


def _redact(msg: str) -> str:
    """Replace the configured Shodan API key with `***` in a string.

    Defense-in-depth: the Shodan REST API requires the key in the URL query
    string, so it lives in `urllib.error.HTTPError.url` and could leak
    through any future exception `__str__` that we don't currently route
    around. Cheaper to scrub every outgoing string than to audit every
    third-party exception class on every dependency upgrade.
    """
    return msg.replace(SHODAN_API_KEY, "***") if SHODAN_API_KEY else msg


def _catch_errors(func):
    """Decorator: convert Shodan/network exceptions into friendly error strings.

    Without this, raw `APIError` / network exceptions propagate as JSON-RPC
    errors with a stack trace, which is noisy and hard for the agent to act on.
    Every return value (success or error) is also passed through `_redact` so
    the API key cannot leak via response payloads or exception messages.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return _redact(func(*args, **kwargs))
        except shodan.APIError as e:  # pyright: ignore[reportAttributeAccessIssue]
            return _redact(f"Error: Shodan API: {e}")
        except urllib.error.HTTPError as e:
            return _redact(f"Error: HTTP {e.code} from Shodan: {e.reason}")
        except urllib.error.URLError as e:
            return _redact(f"Error: network error contacting Shodan: {e.reason}")
        except RuntimeError as e:
            return _redact(f"Error: {e}")
        except Exception as e:
            return _redact(f"Error: {type(e).__name__}: {e}")

    return wrapper


def _shodan_rest(path: str, params: dict[str, str]) -> Any:
    """Call a Shodan REST endpoint that the python library does not wrap.

    `shodan-python` 1.31.0 has no `dns_resolve` / `dns_reverse` methods (and
    `api.dns.resolve` / `api.dns.reverse` do not exist either, despite older
    docs and stale comments suggesting otherwise). The REST endpoints are
    public, so we call them directly.
    """
    if not SHODAN_API_KEY:
        raise RuntimeError(
            "SHODAN_API_KEY environment variable is not set. "
            "Get your API key at https://account.shodan.io"
        )
    query = urllib.parse.urlencode({**params, "key": SHODAN_API_KEY})
    url = f"{SHODAN_API_BASE}{path}?{query}"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _cvedb_get(path: str, params: dict[str, str] | None = None) -> Any:
    """Call the CVEDB API directly. No key required for lookups we use.

    A real-looking User-Agent is required: CVEDB's edge returns 403 for the
    default Python-urllib UA.
    """
    url = f"{CVEDB_BASE}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "dreadnode-asm-mcp/1.0 (+https://dreadnode.io)",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


# ── Core Search ───────────────────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_host_search(
    query: Annotated[str, "Shodan search query (e.g., 'apache city:\"San Francisco\"', 'port:502 tag:ics')"],
    facets: Annotated[str | None, "Comma-separated facets for aggregation (e.g., 'country,org,port')"] = None,
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
            entry["vulns"] = list(match["vulns"].keys()) if isinstance(match["vulns"], dict) else match["vulns"]
        if match.get("location"):
            loc = match["location"]
            entry["location"] = {
                "country": loc.get("country_name"),
                "city": loc.get("city"),
            }
        matches.append(entry)

    return _safe_json({
        "total": results.get("total", 0),
        "matches": matches,
        "facets": results.get("facets", {}),
    })


@mcp.tool()
@_catch_errors
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

    # Shodan returns `vulns` as a dict (CVE → metadata) on detailed host
    # responses and as a list elsewhere. Normalize to a list of CVE IDs so
    # the agent gets a consistent shape across host_info / host_search.
    vulns_raw = host.get("vulns") or []
    if isinstance(vulns_raw, dict):
        vulns = sorted(vulns_raw.keys())
    else:
        vulns = list(vulns_raw)

    return _safe_json({
        "ip": host.get("ip_str"),
        "org": host.get("org"),
        "os": host.get("os"),
        "ports": host.get("ports", []),
        "hostnames": host.get("hostnames", []),
        "domains": host.get("domains", []),
        "vulns": vulns,
        "tags": host.get("tags", []),
        "last_update": host.get("last_update"),
        # `country_name`, `city`, `asn`, `isp` are top-level on the Shodan
        # host object — not nested under a `location` key. Re-grouping them
        # here is purely a presentation choice for the agent.
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
    })


@mcp.tool()
@_catch_errors
def shodan_count(
    query: Annotated[str, "Shodan search query"],
    facets: Annotated[str | None, "Comma-separated facets for aggregated counts"] = None,
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
    return _safe_json({
        "total": result.get("total", 0),
        "facets": result.get("facets", {}),
    })


# ── DNS ───────────────────────────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_dns_lookup(
    hostnames: Annotated[list[str], "Hostnames to resolve (e.g., ['example.com', 'api.example.com'])"],
) -> str:
    """Resolve domain names to IP addresses via Shodan DNS."""
    # shodan-python 1.31.0 has no `dns_resolve` method and `api.dns.resolve`
    # does not exist either (the Dns class only exposes `domain_info` and
    # `parent`). The Shodan REST endpoint is public, so call it directly.
    result = _shodan_rest("/dns/resolve", {"hostnames": ",".join(hostnames)})
    return _safe_json(result)


@mcp.tool()
@_catch_errors
def shodan_dns_reverse(
    ips: Annotated[list[str], "IP addresses to reverse lookup (e.g., ['8.8.8.8'])"],
) -> str:
    """Reverse DNS lookup — find hostnames for IP addresses."""
    # See note on shodan_dns_lookup — same library limitation, same workaround.
    result = _shodan_rest("/dns/reverse", {"ips": ",".join(ips)})
    return _safe_json(result)


@mcp.tool()
@_catch_errors
def shodan_dns_domain_info(
    domain: Annotated[str, "Domain to look up (e.g., 'example.com')"],
) -> str:
    """Get DNS / subdomain intel for a domain via Shodan's domain_info endpoint.

    Returns subdomains, DNS records, and tags Shodan has observed for the
    domain. Often the most useful free Shodan call for ASM enumeration —
    `shodan_dns_lookup` only resolves to IPs, this returns the full
    subdomain inventory Shodan has crawled.
    """
    api = _get_client()
    return _safe_json(api.dns.domain_info(domain))


# ── Exploits & Intelligence ──────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_exploits_search(
    query: Annotated[
        str,
        "CVE ID (e.g., 'CVE-2021-44228') for a single-CVE lookup, or a "
        "product name (e.g., 'apache', 'log4j', 'openssl') for a CVE list",
    ],
    limit: Annotated[int, "Max CVEs to return when querying by product"] = 25,
) -> str:
    """Look up CVE intelligence via Shodan's CVEDB API.

    For a CVE ID, returns full vulnerability detail (CVSS, EPSS, KEV status,
    references, ransomware-campaign tagging, propose_action). For a product
    name, returns a list of recent CVEs affecting that product.

    Note: this used to wrap the legacy `exploits.shodan.io` API, which has
    been replaced by CVEDB. The shodan-python library has not been updated
    and still calls the dead endpoint, so we hit CVEDB directly. CVEDB does
    not consume Shodan API credits.
    """
    if _CVE_RE.match(query):
        result = _cvedb_get(f"/cve/{query.upper()}")
        # CVEDB references lists can be 100+ entries long. Trim to keep the
        # agent's response digestible; the full set is still queryable via
        # `query_graph` or by hitting the URL directly.
        if isinstance(result, dict):
            refs = result.get("references") or []
            if len(refs) > 10:
                result["references"] = refs[:10]
                result["references_truncated"] = True
        return _safe_json(result)

    # Product search — CVEDB returns recent CVEs for the product slug.
    result = _cvedb_get(
        "/cves",
        {"product": query, "limit": str(max(1, min(limit, 100)))},
    )
    cves = result.get("cves", []) if isinstance(result, dict) else []
    matches = [
        {
            "cve_id": c.get("cve_id"),
            "summary": (c.get("summary") or "")[:400],
            "cvss": c.get("cvss"),
            "epss": c.get("epss"),
            "kev": c.get("kev"),
            "ransomware_campaign": c.get("ransomware_campaign"),
            "published_time": c.get("published_time"),
        }
        for c in cves
    ]
    return _safe_json({"total": len(matches), "matches": matches})


# ── Reference Data ───────────────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_ports() -> str:
    """List all port numbers that Shodan actively crawls."""
    api = _get_client()
    return _safe_json(api.ports())


@mcp.tool()
@_catch_errors
def shodan_protocols() -> str:
    """List all protocols Shodan can distinguish in banner grabs."""
    api = _get_client()
    return _safe_json(api.protocols())


# ── Community Queries ────────────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_query_search(
    query: Annotated[str, "Search term (e.g., 'SCADA', 'webcam', 'database')"],
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """Search community-shared Shodan queries for inspiration."""
    api = _get_client()
    # `api.queries` is a method, not a namespace — the real entry points are
    # flat: `api.queries_search(...)` and `api.queries_tags(...)`. The
    # `api.queries.search(...)` shape never worked.
    result = api.queries_search(query=query, page=page)
    return _safe_json({
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
    })


@mcp.tool()
@_catch_errors
def shodan_query_tags(
    size: Annotated[int, "Number of tags to return"] = 20,
) -> str:
    """Get popular tags for community-shared Shodan queries."""
    api = _get_client()
    # See note on shodan_query_search — flat method, not a namespace.
    return _safe_json(api.queries_tags(size=size))


# ── API Status ───────────────────────────────────────────────────────


@mcp.tool()
@_catch_errors
def shodan_api_info() -> str:
    """Check API plan, remaining credits, and account status."""
    api = _get_client()
    info = api.info()
    return _safe_json({
        "plan": info.get("plan"),
        "query_credits": info.get("query_credits"),
        "scan_credits": info.get("scan_credits"),
        "unlocked": info.get("unlocked"),
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
