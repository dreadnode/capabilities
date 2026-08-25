"""Geo-distributed DNS resolution via in-region open resolvers.

Some targets serve region-specific infrastructure: geo-aware authoritative
nameservers, GSLB appliances, and geo-fenced edges hand back different A/AAAA
records depending on where the *resolver* sits. From a single vantage point
that infrastructure is invisible — you only ever see the answer for your own
region.

This toolset discovers open recursive resolvers per country via Shodan or
Censys, resolves caller-supplied hostnames through them, and diffs the answers
against a baseline to surface geo-divergent records.

Orthogonal to IP rotation (``flareprox``/``fireprox``): those change the egress
IP of an HTTP request, this changes the vantage point of a DNS lookup.

Authorization
-------------
Every tool here is gated on ``GEO_RESOLVERS_ENABLED``. Unset means the toolset
reports itself unavailable and performs no network activity. Third-party open
resolvers are someone else's misconfigured infrastructure, so usage is capped:
resolvers are only ever asked to resolve hostnames the caller supplied, query
volume is bounded, and nothing is persisted to disk.

Credentials are read from the environment (``SHODAN_API_KEY``,
``CENSYS_PAT`` / ``CENSYS_API_KEY``, optional ``CENSYS_ORGANIZATION_ID``) and
are redacted from every error path.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import random
import socket
import struct
from typing import Annotated, Any, Literal

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ENABLE_ENV = "GEO_RESOLVERS_ENABLED"
SHODAN_API_KEY_ENV = "SHODAN_API_KEY"
CENSYS_PAT_ENVS: tuple[str, ...] = ("CENSYS_PAT", "CENSYS_API_KEY")
CENSYS_ORG_ENV = "CENSYS_ORGANIZATION_ID"

SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
CENSYS_SEARCH_URL = "https://api.platform.censys.io/v3/global/search/query"

#: Verification hostname. Resolvers that cannot answer this are discarded.
VERIFY_HOSTNAME = "one.one.one.one"
#: Known-good answers for :data:`VERIFY_HOSTNAME`. A resolver returning
#: anything else is lying (captive portal, NXDOMAIN hijack, ad-injecting ISP
#: resolver) and would poison divergence analysis.
VERIFY_EXPECTED: frozenset[str] = frozenset({"1.1.1.1", "1.0.0.1"})

#: Public resolver used to establish the local baseline answer.
DEFAULT_BASELINE_RESOLVER = "1.1.1.1"

MAX_COUNTRIES = 20
MAX_RESOLVERS_PER_COUNTRY = 5
MAX_HOSTNAMES_PER_CALL = 25
MAX_CONCURRENT_DNS = 16

DNS_TIMEOUT_SECONDS = 4.0
DNS_ATTEMPTS = 2
API_TIMEOUT_SECONDS = 20.0

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QTYPE_CNAME = 5
_CLASS_IN = 1
_MAX_LABEL_LEN = 63
_MAX_NAME_LEN = 253
_DNS_HEADER_LEN = 12
_MAX_COMPRESSION_HOPS = 64

RecordType = Literal["A", "AAAA"]
Provider = Literal["shodan", "censys"]

_QTYPE_BY_NAME: dict[str, int] = {"A": _QTYPE_A, "AAAA": _QTYPE_AAAA}


class GeoResolverError(RuntimeError):
    """Raised when a geo-resolver operation cannot be completed."""


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _is_enabled() -> bool:
    """Whether the operator has authorized open-resolver usage."""
    return bool(os.environ.get(ENABLE_ENV, "").strip())


def _require_enabled() -> None:
    if not _is_enabled():
        raise GeoResolverError(
            f"Open-resolver testing is not authorized: {ENABLE_ENV} is unset. "
            "The operator must explicitly enable it for this engagement."
        )


def _env_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def _redact(text: str) -> str:
    """Strip any configured API credential out of a string."""
    for name in (SHODAN_API_KEY_ENV, *CENSYS_PAT_ENVS):
        secret = os.environ.get(name, "").strip()
        if secret and secret in text:
            text = text.replace(secret, "REDACTED")
    return text


def _is_meaningful(value: Any) -> bool:
    """Whether a value earns its place in a tool result.

    Numeric ``0`` and ``False`` are real answers and are kept; ``None`` and
    empty strings/collections are noise the model would otherwise pay tokens
    to read.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    return bool(value)


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop empty values so the model does not pay tokens for nulls."""
    return {key: value for key, value in payload.items() if _is_meaningful(value)}


# ---------------------------------------------------------------------------
# DNS wire format
# ---------------------------------------------------------------------------


def encode_question(qname: str, qtype: int) -> bytes:
    """Encode a DNS question section for ``qname``.

    Raises:
        GeoResolverError: if the hostname is not encodable as a DNS name.
    """
    name = qname.strip().rstrip(".")
    if not name:
        raise GeoResolverError("hostname is empty")
    if len(name) > _MAX_NAME_LEN:
        raise GeoResolverError(
            f"hostname exceeds {_MAX_NAME_LEN} bytes: {name[:60]}..."
        )

    out = bytearray()
    for label in name.split("."):
        if not label:
            raise GeoResolverError(f"hostname has an empty label: {name}")
        try:
            encoded = label.encode("idna")
        except UnicodeError:
            try:
                encoded = label.encode("ascii")
            except UnicodeEncodeError as exc:
                raise GeoResolverError(f"hostname is not encodable: {name}") from exc
        if len(encoded) > _MAX_LABEL_LEN:
            raise GeoResolverError(
                f"DNS label exceeds {_MAX_LABEL_LEN} bytes: {label[:60]}"
            )
        out.append(len(encoded))
        out += encoded
    out.append(0)
    out += struct.pack(">HH", qtype, _CLASS_IN)
    return bytes(out)


def _skip_name(data: bytes, offset: int) -> int:
    """Return the offset just past the DNS name starting at ``offset``.

    Handles compression pointers and refuses to loop forever on hostile input.
    """
    hops = 0
    while True:
        if offset >= len(data):
            raise GeoResolverError("truncated DNS name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise GeoResolverError("truncated DNS compression pointer")
            return offset + 2
        hops += 1
        if hops > _MAX_COMPRESSION_HOPS:
            raise GeoResolverError("DNS name exceeds maximum label count")
        offset += length + 1


def parse_response(
    data: bytes,
    *,
    expected_id: int,
    expected_question: bytes,
) -> dict[str, Any]:
    """Parse a DNS response into records.

    Validates the transaction ID and echoes back the question section before
    trusting any answer, so an off-path or mismatched reply is discarded rather
    than silently folded into results.

    Returns:
        Mapping with ``addresses`` (A/AAAA strings), ``cnames``, and ``rcode``.
    """
    if len(data) < _DNS_HEADER_LEN:
        raise GeoResolverError("DNS response shorter than header")

    resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if resp_id != expected_id:
        raise GeoResolverError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise GeoResolverError("DNS response is not a reply")

    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)

    offset = _DNS_HEADER_LEN
    if qdcount != 1:
        raise GeoResolverError(f"unexpected DNS question count: {qdcount}")
    question_end = offset + len(expected_question)
    if data[offset:question_end] != expected_question:
        raise GeoResolverError("DNS response question does not echo the query")
    offset = question_end

    if rcode != 0:
        return {"addresses": [], "cnames": [], "rcode": rcode, "truncated": truncated}

    addresses: list[str] = []
    cnames: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        if len(rdata) != rdlen:
            break
        offset += rdlen

        if rtype == _QTYPE_A and rdlen == 4:
            addresses.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == _QTYPE_AAAA and rdlen == 16:
            addresses.append(str(ipaddress.IPv6Address(rdata)))
        elif rtype == _QTYPE_CNAME:
            with contextlib.suppress(GeoResolverError):
                target = _decode_name(data, offset - rdlen)
                if target:
                    cnames.append(target)

    return {
        "addresses": addresses,
        "cnames": cnames,
        "rcode": rcode,
        "truncated": truncated,
    }


def _decode_name(data: bytes, offset: int) -> str:
    """Decode a (possibly compressed) DNS name to a dotted string."""
    labels: list[str] = []
    hops = 0
    while True:
        if offset >= len(data):
            raise GeoResolverError("truncated DNS name")
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise GeoResolverError("truncated DNS compression pointer")
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            if hops > _MAX_COMPRESSION_HOPS:
                raise GeoResolverError("DNS compression loop detected")
            continue
        start = offset + 1
        end = start + length
        if end > len(data):
            raise GeoResolverError("truncated DNS label")
        labels.append(data[start:end].decode("ascii", "replace"))
        offset = end
    return ".".join(labels)


class _DnsProtocol(asyncio.DatagramProtocol):
    """Collect a single UDP datagram into a future."""

    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def query_resolver(
    resolver_ip: str,
    hostname: str,
    *,
    record_type: RecordType = "A",
    timeout: float = DNS_TIMEOUT_SECONDS,
    attempts: int = DNS_ATTEMPTS,
) -> dict[str, Any]:
    """Send a DNS query to ``resolver_ip`` over UDP and parse the reply.

    Returns a mapping with ``addresses``/``cnames`` on success, or ``error``
    describing why the lookup failed. Never raises for network conditions —
    unreachable resolvers are an expected outcome, not an exception.
    """
    qtype = _QTYPE_BY_NAME[record_type]
    question = encode_question(hostname, qtype)

    try:
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(resolver_ip).version == 6
            else socket.AF_INET
        )
    except ValueError:
        return {"error": f"invalid resolver IP: {resolver_ip}"}

    loop = asyncio.get_running_loop()
    last_error = "no response"

    for _ in range(max(1, attempts)):
        transaction_id = random.SystemRandom().randrange(0, 0x10000)
        header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        packet = header + question

        future: asyncio.Future[bytes] = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DnsProtocol(future),
                remote_addr=(resolver_ip, 53),
                family=family,
            )
            transport.sendto(packet)
            data = await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            last_error = "timeout"
            continue
        except OSError as exc:
            last_error = f"network error: {exc}"
            continue
        finally:
            if transport is not None:
                transport.close()

        try:
            parsed = parse_response(
                data, expected_id=transaction_id, expected_question=question
            )
        except GeoResolverError as exc:
            last_error = str(exc)
            continue

        if parsed["rcode"] != 0:
            return {"error": f"rcode {parsed['rcode']}", "rcode": parsed["rcode"]}
        return parsed

    return {"error": last_error}


# ---------------------------------------------------------------------------
# Provider discovery
# ---------------------------------------------------------------------------


def _normalize_countries(countries: str | list[str]) -> list[str]:
    """Normalize a country argument to a de-duplicated list of ISO-3166 codes."""
    if isinstance(countries, str):
        raw = countries.replace(",", " ").split()
    else:
        raw = list(countries)

    seen: list[str] = []
    for item in raw:
        code = item.strip().upper()
        if not code:
            continue
        if len(code) != 2 or not code.isalpha():
            raise GeoResolverError(
                f"invalid country code {item!r}: expected a 2-letter ISO-3166 code (e.g. DE)"
            )
        if code not in seen:
            seen.append(code)

    if not seen:
        raise GeoResolverError("no country codes supplied")
    if len(seen) > MAX_COUNTRIES:
        raise GeoResolverError(
            f"too many countries ({len(seen)}); maximum is {MAX_COUNTRIES} per call"
        )
    return seen


def _is_usable_resolver_ip(ip: str) -> bool:
    """Reject non-routable candidates so we never probe our own infrastructure."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


async def _discover_shodan(
    client: httpx.AsyncClient, country: str, limit: int
) -> list[dict[str, Any]]:
    """Find candidate open resolvers in ``country`` via the Shodan REST API."""
    api_key = _env_value(SHODAN_API_KEY_ENV)
    if not api_key:
        raise GeoResolverError(f"{SHODAN_API_KEY_ENV} is not set")

    params = {
        "key": api_key,
        "query": f'port:53 country:{country} "Recursion: enabled"',
        "minify": "true",
    }
    try:
        response = await client.get(SHODAN_SEARCH_URL, params=params)
    except httpx.HTTPError as exc:
        raise GeoResolverError(f"Shodan request failed: {_redact(str(exc))}") from exc

    if response.status_code == 401:
        raise GeoResolverError("Shodan rejected the API key (401)")
    if response.status_code == 403:
        raise GeoResolverError(
            "Shodan denied the request (403) — plan may lack search access"
        )
    if response.status_code != 200:
        raise GeoResolverError(
            f"Shodan returned HTTP {response.status_code}: {_redact(response.text[:200])}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise GeoResolverError("Shodan returned a non-JSON response") from exc

    if isinstance(payload, dict) and payload.get("error"):
        raise GeoResolverError(f"Shodan error: {_redact(str(payload['error']))}")

    candidates: list[dict[str, Any]] = []
    for match in (payload or {}).get("matches", []):
        ip = match.get("ip_str")
        if not ip or not _is_usable_resolver_ip(ip):
            continue
        candidates.append(
            _compact(
                {
                    "ip": ip,
                    "country": (match.get("location") or {}).get("country_code")
                    or country,
                    "asn": match.get("asn") or "",
                    "org": match.get("org") or "",
                    "source": "shodan",
                }
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


async def _discover_censys(
    client: httpx.AsyncClient, country: str, limit: int
) -> list[dict[str, Any]]:
    """Find candidate open resolvers in ``country`` via the Censys Platform API."""
    token = _env_value(*CENSYS_PAT_ENVS)
    if not token:
        raise GeoResolverError(f"{CENSYS_PAT_ENVS[0]} is not set")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    organization_id = _env_value(CENSYS_ORG_ENV)
    if organization_id:
        headers["X-Organization-ID"] = organization_id

    body = {
        "query": (
            "host.services: (port=53 and protocol=DNS) "
            f'and host.location.country_code="{country}"'
        ),
        "page_size": min(max(limit, 1), 100),
        "fields": ["host.ip", "host.location.country_code", "host.autonomous_system"],
    }
    try:
        response = await client.post(CENSYS_SEARCH_URL, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise GeoResolverError(f"Censys request failed: {_redact(str(exc))}") from exc

    if response.status_code == 401:
        raise GeoResolverError("Censys rejected the personal access token (401)")
    if response.status_code == 403:
        raise GeoResolverError(
            "Censys denied the request (403) — the token needs the API Access role"
        )
    if response.status_code == 422:
        raise GeoResolverError(
            "Censys rejected the query (422) — an organization ID may be required; "
            f"set {CENSYS_ORG_ENV}"
        )
    if response.status_code != 200:
        raise GeoResolverError(
            f"Censys returned HTTP {response.status_code}: {_redact(response.text[:200])}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise GeoResolverError("Censys returned a non-JSON response") from exc

    hits = ((payload or {}).get("result") or {}).get("hits") or []
    candidates: list[dict[str, Any]] = []
    for hit in hits:
        resource = (hit.get("host_v1") or {}).get("resource") or {}
        ip = resource.get("ip")
        if not ip or not _is_usable_resolver_ip(ip):
            continue
        autonomous_system = resource.get("autonomous_system") or {}
        asn = autonomous_system.get("asn")
        candidates.append(
            _compact(
                {
                    "ip": ip,
                    "country": (resource.get("location") or {}).get("country_code")
                    or country,
                    "asn": f"AS{asn}" if asn else "",
                    "org": autonomous_system.get("name") or "",
                    "source": "censys",
                }
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


# ---------------------------------------------------------------------------
# Divergence analysis
# ---------------------------------------------------------------------------


def summarize_divergence(
    baseline: list[str], per_country: dict[str, list[str]]
) -> dict[str, Any]:
    """Compare per-country answers against the baseline answer set.

    Returns the countries whose answers differ, the addresses seen only from
    those regions, and whether any geo-differentiation exists at all.
    """
    baseline_set = set(baseline)
    divergent: dict[str, Any] = {}
    region_only: set[str] = set()

    for country, addresses in sorted(per_country.items()):
        address_set = set(addresses)
        if not address_set or address_set == baseline_set:
            continue
        unseen = sorted(address_set - baseline_set)
        divergent[country] = _compact(
            {
                "addresses": sorted(address_set),
                "not_in_baseline": unseen,
                "missing_from_region": sorted(baseline_set - address_set),
            }
        )
        region_only.update(unseen)

    all_addresses = set(baseline_set)
    for addresses in per_country.values():
        all_addresses.update(addresses)

    return _compact(
        {
            "geo_differentiated": bool(divergent),
            "baseline_addresses": sorted(baseline_set),
            "divergent_countries": divergent,
            "addresses_only_seen_regionally": sorted(region_only),
            "distinct_address_count": len(all_addresses),
        }
    )


# ---------------------------------------------------------------------------
# Toolset
# ---------------------------------------------------------------------------


class GeoResolvers(Toolset):
    """Resolve hostnames through in-region open resolvers to expose geo-fenced infrastructure.

    Discovers open recursive resolvers per country via Shodan or Censys, then
    resolves caller-supplied hostnames through them and diffs the answers
    against a local baseline. Use when a target appears to geo-fence content or
    serve region-specific infrastructure that a single vantage point cannot see.

    Requires ``GEO_RESOLVERS_ENABLED`` plus a Shodan or Censys credential.
    """

    api_timeout: float = API_TIMEOUT_SECONDS
    """Timeout in seconds for Shodan/Censys API calls."""
    dns_timeout: float = DNS_TIMEOUT_SECONDS
    """Timeout in seconds for each DNS query."""

    _resolvers: dict[str, list[dict[str, Any]]] = PrivateAttr(default_factory=dict)

    # -- readiness ---------------------------------------------------------

    @tool_method(name="check_geo_resolver_readiness", catch=True)
    async def check_geo_resolver_readiness(self) -> dict[str, Any]:
        """Report whether geo-distributed DNS testing is authorized and usable.

        Shows the authorization gate state, which provider credentials are
        present, and how many resolvers are cached for this session. Call this
        before attempting discovery so you can tell "not authorized" apart from
        "no API key" apart from "no resolvers found".
        """
        providers = _compact(
            {
                "shodan": bool(_env_value(SHODAN_API_KEY_ENV)),
                "censys": bool(_env_value(*CENSYS_PAT_ENVS)),
            }
        )
        enabled = _is_enabled()
        available = sorted(name for name, configured in providers.items() if configured)

        if not enabled:
            guidance = (
                f"Not authorized. The operator must set {ENABLE_ENV} to enable "
                "open-resolver testing for this engagement."
            )
        elif not available:
            guidance = (
                f"Authorized, but no provider credentials found. Set {SHODAN_API_KEY_ENV} "
                f"or {CENSYS_PAT_ENVS[0]}."
            )
        else:
            guidance = (
                f"Ready. Discover resolvers with discover_open_resolvers using: "
                f"{', '.join(available)}."
            )

        return _compact(
            {
                "authorized": enabled,
                "authorization_env": ENABLE_ENV,
                "providers_configured": providers,
                "providers_available": available,
                "cached_countries": sorted(self._resolvers),
                "cached_resolver_count": sum(len(v) for v in self._resolvers.values()),
                "guidance": guidance,
            }
        )

    # -- discovery ---------------------------------------------------------

    @tool_method(name="discover_open_resolvers", catch=True)
    async def discover_open_resolvers(
        self,
        countries: Annotated[
            str,
            "Comma-separated ISO-3166 country codes to source resolvers from (e.g. 'DE,SG,BR')",
        ],
        provider: Annotated[
            str,
            "Discovery source: 'shodan', 'censys', or 'auto' to use whichever is configured",
        ] = "auto",
        max_per_country: Annotated[
            int, "Maximum verified resolvers to keep per country (1-5)"
        ] = 2,
        verify: Annotated[
            bool,
            "Verify each candidate returns the correct answer for a known hostname before caching",
        ] = True,
    ) -> dict[str, Any]:
        """Find open recursive resolvers in specific countries and cache them for this session.

        Queries Shodan or Censys for hosts exposing recursive DNS in each
        country, then (by default) verifies each candidate actually resolves a
        known-good hostname to its correct address. Verification matters:
        hijacking resolvers that answer everything with an ad server would
        otherwise show up as fake geo-divergence.

        Results are cached in memory for this session only — nothing is written
        to disk. Re-running replaces the cache for the countries requested.
        """
        _require_enabled()

        codes = _normalize_countries(countries)
        limit = max(1, min(int(max_per_country), MAX_RESOLVERS_PER_COUNTRY))

        selected = provider.strip().lower()
        if selected not in {"auto", "shodan", "censys"}:
            raise GeoResolverError(
                f"unknown provider {provider!r}: expected 'shodan', 'censys', or 'auto'"
            )
        if selected == "auto":
            if _env_value(SHODAN_API_KEY_ENV):
                selected = "shodan"
            elif _env_value(*CENSYS_PAT_ENVS):
                selected = "censys"
            else:
                raise GeoResolverError(
                    f"no provider credentials found: set {SHODAN_API_KEY_ENV} "
                    f"or {CENSYS_PAT_ENVS[0]}"
                )

        discover = _discover_shodan if selected == "shodan" else _discover_censys
        # Over-fetch when verifying, since most candidates fail verification.
        fetch_limit = min(limit * 5, 100) if verify else limit

        found: dict[str, list[dict[str, Any]]] = {}
        errors: dict[str, str] = {}
        async with httpx.AsyncClient(timeout=self.api_timeout) as client:
            for code in codes:
                try:
                    candidates = await discover(client, code, fetch_limit)
                except GeoResolverError as exc:
                    errors[code] = str(exc)
                    continue
                found[code] = candidates

        verified: dict[str, list[dict[str, Any]]] = {}
        for code, candidates in found.items():
            if not verify:
                verified[code] = candidates[:limit]
                continue
            kept = await self._verify_candidates(candidates, limit)
            if kept:
                verified[code] = kept

        for code, resolvers in verified.items():
            self._resolvers[code] = resolvers

        empty = sorted(set(codes) - set(verified) - set(errors))
        return _compact(
            {
                "provider": selected,
                "verified": verify,
                "countries": {
                    code: [r["ip"] for r in resolvers]
                    for code, resolvers in sorted(verified.items())
                },
                "resolver_details": verified,
                "resolver_count": sum(len(v) for v in verified.values()),
                "countries_without_resolvers": empty,
                "errors": errors,
            }
        )

    async def _verify_candidates(
        self, candidates: list[dict[str, Any]], limit: int
    ) -> list[dict[str, Any]]:
        """Keep candidates that answer :data:`VERIFY_HOSTNAME` correctly, up to ``limit``."""
        kept: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_DNS)

        async def probe(candidate: dict[str, Any]) -> tuple[dict[str, Any], bool]:
            async with semaphore:
                result = await query_resolver(
                    candidate["ip"], VERIFY_HOSTNAME, timeout=self.dns_timeout
                )
            addresses = set(result.get("addresses") or [])
            return candidate, bool(addresses & VERIFY_EXPECTED)

        # Probe in batches so a large candidate pool does not fan out unbounded.
        for start in range(0, len(candidates), MAX_CONCURRENT_DNS):
            batch = candidates[start : start + MAX_CONCURRENT_DNS]
            for candidate, ok in await asyncio.gather(*(probe(c) for c in batch)):
                if ok:
                    kept.append(candidate)
                    if len(kept) >= limit:
                        return kept
        return kept

    @tool_method(name="list_open_resolvers", catch=True)
    async def list_open_resolvers(self) -> dict[str, Any]:
        """List the open resolvers cached for this session, grouped by country.

        Returns what ``discover_open_resolvers`` most recently verified. The
        cache is in-memory and disappears when the session ends.
        """
        _require_enabled()
        return _compact(
            {
                "countries": {
                    code: [r["ip"] for r in resolvers]
                    for code, resolvers in sorted(self._resolvers.items())
                },
                "resolver_details": dict(sorted(self._resolvers.items())),
                "resolver_count": sum(len(v) for v in self._resolvers.values()),
                "guidance": (
                    "No resolvers cached — run discover_open_resolvers first."
                    if not self._resolvers
                    else "Resolve hostnames through these with resolve_via_open_resolvers."
                ),
            }
        )

    # -- resolution --------------------------------------------------------

    @tool_method(name="resolve_via_open_resolvers", catch=True)
    async def resolve_via_open_resolvers(
        self,
        hostnames: Annotated[
            str, "Comma-separated hostnames to resolve (max 25 per call)"
        ],
        countries: Annotated[
            str,
            "Comma-separated country codes to query, or empty to use every cached country",
        ] = "",
        record_type: Annotated[str, "DNS record type to request: 'A' or 'AAAA'"] = "A",
        baseline_resolver: Annotated[
            str, "Resolver used for the local baseline answer"
        ] = DEFAULT_BASELINE_RESOLVER,
    ) -> dict[str, Any]:
        """Resolve hostnames through in-region resolvers and diff against a local baseline.

        For each hostname this queries every cached resolver in the selected
        countries, then compares the per-country answers to the baseline. A
        country whose answers differ indicates geo-differentiated DNS: the
        target hands back different infrastructure depending on where the
        resolver sits, which is the DNS-layer footprint of geo-fencing.

        Addresses reported under ``addresses_only_seen_regionally`` are the
        actionable output — endpoints invisible from the local vantage point.
        Confirm they are in scope before touching them.
        """
        _require_enabled()

        names = [
            h.strip().rstrip(".")
            for h in hostnames.replace(",", " ").split()
            if h.strip()
        ]
        if not names:
            raise GeoResolverError("no hostnames supplied")
        if len(names) > MAX_HOSTNAMES_PER_CALL:
            raise GeoResolverError(
                f"too many hostnames ({len(names)}); maximum is {MAX_HOSTNAMES_PER_CALL} per call"
            )

        rtype = record_type.strip().upper()
        if rtype not in _QTYPE_BY_NAME:
            raise GeoResolverError(
                f"unsupported record type {record_type!r}: use 'A' or 'AAAA'"
            )

        if countries.strip():
            codes = _normalize_countries(countries)
            missing = [c for c in codes if c not in self._resolvers]
            if missing:
                raise GeoResolverError(
                    f"no cached resolvers for {', '.join(missing)} — "
                    "run discover_open_resolvers for those countries first"
                )
        else:
            codes = sorted(self._resolvers)
        if not codes:
            raise GeoResolverError(
                "no resolvers cached — run discover_open_resolvers first"
            )

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_DNS)

        async def lookup(resolver_ip: str, hostname: str) -> dict[str, Any]:
            async with semaphore:
                return await query_resolver(
                    resolver_ip,
                    hostname,
                    record_type=rtype,  # type: ignore[arg-type]
                    timeout=self.dns_timeout,
                )

        # Fail fast on unencodable hostnames before issuing any network traffic.
        for hostname in names:
            encode_question(hostname, _QTYPE_BY_NAME[rtype])

        targets = [
            (code, resolver["ip"])
            for code in codes
            for resolver in self._resolvers[code]
        ]

        results: dict[str, Any] = {}
        for hostname in names:
            baseline_result = await lookup(baseline_resolver, hostname)
            baseline_addresses = baseline_result.get("addresses") or []

            per_country: dict[str, list[str]] = {}
            per_resolver: dict[str, Any] = {}
            unreachable: list[str] = []

            outcomes = await asyncio.gather(
                *(lookup(ip, hostname) for _, ip in targets)
            )

            for (code, ip), outcome in zip(targets, outcomes):
                if outcome.get("error"):
                    unreachable.append(f"{code}/{ip}: {outcome['error']}")
                    continue
                addresses = outcome.get("addresses") or []
                per_resolver[f"{code}/{ip}"] = addresses
                per_country.setdefault(code, [])
                for address in addresses:
                    if address not in per_country[code]:
                        per_country[code].append(address)

            results[hostname] = _compact(
                {
                    **summarize_divergence(baseline_addresses, per_country),
                    "baseline_error": baseline_result.get("error", ""),
                    "answers_by_country": {
                        k: sorted(v) for k, v in sorted(per_country.items())
                    },
                    "answers_by_resolver": per_resolver,
                    "unreachable_resolvers": unreachable,
                }
            )

        differentiated = sorted(
            name for name, data in results.items() if data.get("geo_differentiated")
        )
        return _compact(
            {
                "record_type": rtype,
                "baseline_resolver": baseline_resolver,
                "countries_queried": codes,
                "results": results,
                "geo_differentiated_hostnames": differentiated,
                "guidance": (
                    "No geo-differentiation detected — the target returns the same records "
                    "from every vantage point tested."
                    if not differentiated
                    else (
                        "Geo-differentiated DNS detected. Review "
                        "addresses_only_seen_regionally and confirm scope before probing."
                    )
                ),
            }
        )

    @tool_method(name="clear_open_resolver_cache", catch=True)
    async def clear_open_resolver_cache(self) -> dict[str, Any]:
        """Discard the session's cached open resolvers.

        Use when switching engagements or after finishing geo-differentiated
        testing so a later call cannot silently reuse a previous target's
        vantage points.
        """
        cleared = sum(len(v) for v in self._resolvers.values())
        self._resolvers.clear()
        return {"cleared_resolver_count": cleared, "cached_countries": []}
