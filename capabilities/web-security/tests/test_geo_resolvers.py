"""Tests for geo-distributed DNS resolution toolset.

Covers DNS wire-format encoding/parsing, resolver discovery against both
providers, the authorization gate, verification, divergence analysis, and
all five LLM-facing tools. No real network access — every HTTP and DNS call
is mocked.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import struct
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub bootstrap (conftest installs the dreadnode.agents.tools stub)
# ---------------------------------------------------------------------------

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "geo_resolvers.py"
SPEC = importlib.util.spec_from_file_location("geo_resolvers", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

GeoResolvers = MODULE.GeoResolvers
GeoResolverError = MODULE.GeoResolverError
encode_question = MODULE.encode_question
parse_response = MODULE.parse_response
summarize_divergence = MODULE.summarize_divergence
query_resolver = MODULE.query_resolver
_normalize_countries = MODULE._normalize_countries
_is_usable_resolver_ip = MODULE._is_usable_resolver_ip
_compact = MODULE._compact
_is_meaningful = MODULE._is_meaningful
_redact = MODULE._redact
_discover_shodan = MODULE._discover_shodan
_discover_censys = MODULE._discover_censys

ENABLE_ENV = MODULE.ENABLE_ENV
SHODAN_API_KEY_ENV = MODULE.SHODAN_API_KEY_ENV

_QTYPE_A = MODULE._QTYPE_A
_QTYPE_AAAA = MODULE._QTYPE_AAAA


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_response(
    txid: int,
    question: bytes,
    answers: list[tuple[int, bytes]],
    *,
    rcode: int = 0,
    flags: int = 0x8180,
) -> bytes:
    """Build a minimal DNS response packet from parts."""
    flags_with_rcode = (flags & 0xFFF0) | (rcode & 0x0F)
    header = struct.pack(">HHHHHH", txid, flags_with_rcode, 1, len(answers), 0, 0)
    body = question
    for rtype, rdata in answers:
        body += b"\xc0\x0c"  # pointer to question name
        body += struct.pack(">HHIH", rtype, 1, 300, len(rdata))
        body += rdata
    return header + body


def _a_rdata(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def _aaaa_rdata(ip: str) -> bytes:
    return ipaddress.IPv6Address(ip).packed


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure a clean env for every test."""
    for name in (
        ENABLE_ENV,
        SHODAN_API_KEY_ENV,
        "CENSYS_PAT",
        "CENSYS_API_KEY",
        "CENSYS_ORGANIZATION_ID",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def enabled_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the authorization gate."""
    monkeypatch.setenv(ENABLE_ENV, "1")


@pytest.fixture
def shodan_env(enabled_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SHODAN_API_KEY_ENV, "test-shodan-key-xxx")


@pytest.fixture
def censys_env(enabled_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CENSYS_PAT", "test-censys-pat-yyy")


@pytest.fixture
def toolset() -> GeoResolvers:
    """Fresh GeoResolvers with PrivateAttr manually initialised (test-stub Toolset)."""
    ts = GeoResolvers()
    ts._resolvers = {}
    return ts


# ---------------------------------------------------------------------------
# _compact / _is_meaningful
# ---------------------------------------------------------------------------


class TestCompact:
    def test_drops_none(self) -> None:
        assert _compact({"a": None, "b": 1}) == {"b": 1}

    def test_drops_empty_string(self) -> None:
        assert _compact({"a": "", "b": "x"}) == {"b": "x"}

    def test_drops_empty_list(self) -> None:
        assert _compact({"a": [], "b": [1]}) == {"b": [1]}

    def test_drops_empty_dict(self) -> None:
        assert _compact({"a": {}, "b": {"k": "v"}}) == {"b": {"k": "v"}}

    def test_keeps_zero(self) -> None:
        assert _compact({"a": 0}) == {"a": 0}

    def test_keeps_false(self) -> None:
        assert _compact({"a": False}) == {"a": False}

    def test_keeps_true(self) -> None:
        assert _compact({"a": True}) == {"a": True}

    def test_keeps_float_zero(self) -> None:
        assert _compact({"a": 0.0}) == {"a": 0.0}


# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


class TestRedact:
    def test_redacts_shodan_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(SHODAN_API_KEY_ENV, "SECRET123")
        assert "SECRET123" not in _redact("Shodan error: SECRET123 not valid")

    def test_redacts_censys_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CENSYS_PAT", "CTOKEN")
        assert "CTOKEN" not in _redact("Auth failed: CTOKEN expired")

    def test_noop_when_no_key(self) -> None:
        assert _redact("safe text") == "safe text"


# ---------------------------------------------------------------------------
# Country normalisation
# ---------------------------------------------------------------------------


class TestNormalizeCountries:
    def test_string_csv(self) -> None:
        assert _normalize_countries("de,sg, BR") == ["DE", "SG", "BR"]

    def test_list(self) -> None:
        assert _normalize_countries(["us", "US", "gb"]) == ["US", "GB"]

    def test_rejects_three_letter(self) -> None:
        with pytest.raises(GeoResolverError, match="2-letter"):
            _normalize_countries("DEU")

    def test_rejects_numeric(self) -> None:
        with pytest.raises(GeoResolverError, match="2-letter"):
            _normalize_countries("D1")

    def test_rejects_empty(self) -> None:
        with pytest.raises(GeoResolverError, match="no country"):
            _normalize_countries("")

    def test_enforces_limit(self) -> None:
        codes = ",".join(f"A{chr(65 + i)}" for i in range(21))
        with pytest.raises(GeoResolverError, match="too many"):
            _normalize_countries(codes)


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------


class TestIsUsableResolverIp:
    def test_public_v4(self) -> None:
        assert _is_usable_resolver_ip("93.184.216.34") is True

    def test_private(self) -> None:
        assert _is_usable_resolver_ip("10.0.0.1") is False

    def test_loopback(self) -> None:
        assert _is_usable_resolver_ip("127.0.0.1") is False

    def test_link_local(self) -> None:
        assert _is_usable_resolver_ip("169.254.1.1") is False

    def test_invalid(self) -> None:
        assert _is_usable_resolver_ip("not.an.ip") is False


# ---------------------------------------------------------------------------
# DNS wire format
# ---------------------------------------------------------------------------


class TestEncodeQuestion:
    def test_basic(self) -> None:
        q = encode_question("example.com", _QTYPE_A)
        assert q == bytes.fromhex("076578616d706c6503636f6d0000010001")

    def test_trailing_dot_stripped(self) -> None:
        assert encode_question("example.com.", _QTYPE_A) == encode_question(
            "example.com", _QTYPE_A
        )

    def test_aaaa(self) -> None:
        q = encode_question("example.com", _QTYPE_AAAA)
        assert q[-4:] == struct.pack(">HH", _QTYPE_AAAA, 1)

    def test_rejects_empty(self) -> None:
        with pytest.raises(GeoResolverError, match="empty"):
            encode_question("", _QTYPE_A)

    def test_rejects_long_label(self) -> None:
        with pytest.raises(GeoResolverError, match="63"):
            encode_question("a" * 64 + ".com", _QTYPE_A)

    def test_rejects_long_name(self) -> None:
        long_name = ".".join(["a" * 60] * 5)
        with pytest.raises(GeoResolverError, match="253"):
            encode_question(long_name, _QTYPE_A)


class TestParseResponse:
    def test_a_record(self) -> None:
        q = encode_question("example.com", _QTYPE_A)
        pkt = _build_response(0x1234, q, [(_QTYPE_A, _a_rdata("93.184.216.34"))])
        r = parse_response(pkt, expected_id=0x1234, expected_question=q)
        assert r["addresses"] == ["93.184.216.34"]
        assert r["rcode"] == 0
        assert r["truncated"] is False

    def test_aaaa_record(self) -> None:
        q = encode_question("example.com", _QTYPE_AAAA)
        pkt = _build_response(0x5678, q, [(_QTYPE_AAAA, _aaaa_rdata("2001:db8::1"))])
        r = parse_response(pkt, expected_id=0x5678, expected_question=q)
        assert r["addresses"] == ["2001:db8::1"]

    def test_multiple_a_records(self) -> None:
        q = encode_question("cdn.example.com", _QTYPE_A)
        pkt = _build_response(
            1, q, [(_QTYPE_A, _a_rdata("1.2.3.4")), (_QTYPE_A, _a_rdata("5.6.7.8"))]
        )
        r = parse_response(pkt, expected_id=1, expected_question=q)
        assert sorted(r["addresses"]) == ["1.2.3.4", "5.6.7.8"]

    def test_txid_mismatch_rejects(self) -> None:
        q = encode_question("example.com", _QTYPE_A)
        pkt = _build_response(100, q, [(_QTYPE_A, _a_rdata("1.1.1.1"))])
        with pytest.raises(GeoResolverError, match="transaction ID"):
            parse_response(pkt, expected_id=999, expected_question=q)

    def test_question_mismatch_rejects(self) -> None:
        q = encode_question("good.com", _QTYPE_A)
        evil = encode_question("evil.com", _QTYPE_A)
        pkt = _build_response(1, evil, [(_QTYPE_A, _a_rdata("6.6.6.6"))])
        with pytest.raises(GeoResolverError, match="question"):
            parse_response(pkt, expected_id=1, expected_question=q)

    def test_nxdomain(self) -> None:
        q = encode_question("nope.example.com", _QTYPE_A)
        pkt = _build_response(1, q, [], rcode=3)
        r = parse_response(pkt, expected_id=1, expected_question=q)
        assert r["rcode"] == 3
        assert r["addresses"] == []

    def test_truncated_packet(self) -> None:
        with pytest.raises(GeoResolverError):
            parse_response(b"\x00" * 5, expected_id=0, expected_question=b"")

    def test_cname_record(self) -> None:
        q = encode_question("www.example.com", _QTYPE_A)
        cname_rdata = b"\x03cdn\x07example\x03com\x00"
        pkt = _build_response(
            1,
            q,
            [(5, cname_rdata), (_QTYPE_A, _a_rdata("1.2.3.4"))],
        )
        r = parse_response(pkt, expected_id=1, expected_question=q)
        assert "cdn.example.com" in r["cnames"]
        assert "1.2.3.4" in r["addresses"]


# ---------------------------------------------------------------------------
# Divergence analysis
# ---------------------------------------------------------------------------


class TestSummarizeDivergence:
    def test_identical(self) -> None:
        d = summarize_divergence(["1.2.3.4"], {"DE": ["1.2.3.4"], "SG": ["1.2.3.4"]})
        assert d["geo_differentiated"] is False
        assert d.get("addresses_only_seen_regionally", []) == []

    def test_divergent_one_country(self) -> None:
        d = summarize_divergence(["1.2.3.4"], {"DE": ["1.2.3.4"], "SG": ["9.9.9.9"]})
        assert d["geo_differentiated"] is True
        assert "SG" in d["divergent_countries"]
        assert "DE" not in d["divergent_countries"]
        assert d["addresses_only_seen_regionally"] == ["9.9.9.9"]

    def test_empty_country_answers_skipped(self) -> None:
        d = summarize_divergence(["1.2.3.4"], {"DE": [], "SG": ["1.2.3.4"]})
        assert d["geo_differentiated"] is False

    def test_superset_is_divergent(self) -> None:
        d = summarize_divergence(["1.2.3.4"], {"DE": ["1.2.3.4", "5.5.5.5"]})
        assert d["geo_differentiated"] is True
        assert d["addresses_only_seen_regionally"] == ["5.5.5.5"]

    def test_subset_is_divergent(self) -> None:
        d = summarize_divergence(["1.2.3.4", "5.5.5.5"], {"DE": ["5.5.5.5"]})
        assert d["geo_differentiated"] is True
        assert d["divergent_countries"]["DE"]["missing_from_region"] == ["1.2.3.4"]

    def test_distinct_count(self) -> None:
        d = summarize_divergence(["1.2.3.4"], {"DE": ["5.5.5.5"], "SG": ["6.6.6.6"]})
        assert d["distinct_address_count"] == 3


# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------


class TestAuthorizationGate:
    @pytest.mark.asyncio
    async def test_readiness_when_disabled(self, toolset: GeoResolvers) -> None:
        result = await toolset.check_geo_resolver_readiness()
        assert result["authorized"] is False
        assert "not authorized" in result["guidance"].lower()

    @pytest.mark.asyncio
    async def test_readiness_when_enabled_no_keys(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        result = await toolset.check_geo_resolver_readiness()
        assert result["authorized"] is True
        assert result.get("providers_available", []) == []

    @pytest.mark.asyncio
    async def test_readiness_with_shodan(
        self, toolset: GeoResolvers, shodan_env: None
    ) -> None:
        result = await toolset.check_geo_resolver_readiness()
        assert "shodan" in result["providers_available"]

    @pytest.mark.asyncio
    async def test_readiness_with_censys(
        self, toolset: GeoResolvers, censys_env: None
    ) -> None:
        result = await toolset.check_geo_resolver_readiness()
        assert "censys" in result["providers_available"]

    @pytest.mark.asyncio
    async def test_list_resolvers_blocked_when_disabled(
        self, toolset: GeoResolvers
    ) -> None:
        with pytest.raises(GeoResolverError, match="not authorized"):
            await toolset.list_open_resolvers()

    @pytest.mark.asyncio
    async def test_discover_blocked_when_disabled(self, toolset: GeoResolvers) -> None:
        with pytest.raises(GeoResolverError, match="not authorized"):
            await toolset.discover_open_resolvers(countries="DE")

    @pytest.mark.asyncio
    async def test_resolve_blocked_when_disabled(self, toolset: GeoResolvers) -> None:
        with pytest.raises(GeoResolverError, match="not authorized"):
            await toolset.resolve_via_open_resolvers(hostnames="example.com")


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


class TestToolDiscovery:
    def test_expected_tools_registered(self, toolset: GeoResolvers) -> None:
        names = {t.name for t in toolset.get_tools()}
        assert names == {
            "check_geo_resolver_readiness",
            "discover_open_resolvers",
            "list_open_resolvers",
            "resolve_via_open_resolvers",
            "clear_open_resolver_cache",
        }


# ---------------------------------------------------------------------------
# Provider discovery (mocked HTTP)
# ---------------------------------------------------------------------------

SHODAN_RESPONSE = {
    "matches": [
        {
            "ip_str": "93.184.216.1",
            "port": 53,
            "location": {"country_code": "DE"},
            "asn": "AS15169",
            "org": "TestOrg",
        },
        {
            "ip_str": "93.184.216.2",
            "port": 53,
            "location": {"country_code": "DE"},
            "asn": "AS15170",
            "org": "TestOrg2",
        },
        {
            "ip_str": "10.0.0.1",  # private — should be filtered
            "port": 53,
            "location": {"country_code": "DE"},
        },
    ],
    "total": 3,
}

CENSYS_RESPONSE = {
    "result": {
        "hits": [
            {
                "host_v1": {
                    "resource": {
                        "ip": "185.199.108.1",
                        "location": {"country_code": "SG"},
                        "autonomous_system": {"asn": 13335, "name": "Cloudflare"},
                    }
                }
            },
            {
                "host_v1": {
                    "resource": {
                        "ip": "127.0.0.1",  # loopback — should be filtered
                        "location": {"country_code": "SG"},
                        "autonomous_system": {"asn": 0},
                    }
                }
            },
        ],
        "total_hits": 2,
        "next_page_token": "",
        "previous_page_token": "",
        "query_duration_millis": 42,
    }
}


def _mock_response(json_data: Any, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    return resp


class TestDiscoverShodan:
    @pytest.mark.asyncio
    async def test_parses_matches(self, shodan_env: None) -> None:
        client = AsyncMock()
        client.get = AsyncMock(return_value=_mock_response(SHODAN_RESPONSE))
        result = await _discover_shodan(client, "DE", 5)
        ips = [r["ip"] for r in result]
        assert "93.184.216.1" in ips
        assert "93.184.216.2" in ips
        assert "10.0.0.1" not in ips  # private filtered

    @pytest.mark.asyncio
    async def test_shodan_401(self, shodan_env: None) -> None:
        client = AsyncMock()
        client.get = AsyncMock(return_value=_mock_response({}, 401))
        with pytest.raises(GeoResolverError, match="401"):
            await _discover_shodan(client, "DE", 5)

    @pytest.mark.asyncio
    async def test_shodan_no_key(self) -> None:
        with pytest.raises(GeoResolverError, match="not set"):
            await _discover_shodan(AsyncMock(), "DE", 5)

    @pytest.mark.asyncio
    async def test_shodan_respects_limit(self, shodan_env: None) -> None:
        client = AsyncMock()
        client.get = AsyncMock(return_value=_mock_response(SHODAN_RESPONSE))
        result = await _discover_shodan(client, "DE", 1)
        assert len(result) == 1


class TestDiscoverCensys:
    @pytest.mark.asyncio
    async def test_parses_hits(self, censys_env: None) -> None:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_mock_response(CENSYS_RESPONSE))
        result = await _discover_censys(client, "SG", 5)
        ips = [r["ip"] for r in result]
        assert "185.199.108.1" in ips
        assert "127.0.0.1" not in ips  # loopback filtered

    @pytest.mark.asyncio
    async def test_censys_401(self, censys_env: None) -> None:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_mock_response({}, 401))
        with pytest.raises(GeoResolverError, match="401"):
            await _discover_censys(client, "SG", 5)

    @pytest.mark.asyncio
    async def test_censys_422_suggests_org_id(self, censys_env: None) -> None:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_mock_response({}, 422))
        with pytest.raises(GeoResolverError, match="organization"):
            await _discover_censys(client, "SG", 5)

    @pytest.mark.asyncio
    async def test_censys_no_key(self) -> None:
        with pytest.raises(GeoResolverError, match="not set"):
            await _discover_censys(AsyncMock(), "SG", 5)


# ---------------------------------------------------------------------------
# discover_open_resolvers tool (end-to-end, mocked)
# ---------------------------------------------------------------------------


class TestDiscoverTool:
    @pytest.mark.asyncio
    async def test_auto_selects_shodan(
        self, toolset: GeoResolvers, shodan_env: None
    ) -> None:
        with (
            patch.object(
                MODULE, "_discover_shodan", new_callable=AsyncMock
            ) as mock_disc,
            patch.object(
                toolset, "_verify_candidates", new_callable=AsyncMock
            ) as mock_ver,
        ):
            mock_disc.return_value = [
                {"ip": "1.1.1.1", "country": "DE", "source": "shodan"}
            ]
            mock_ver.return_value = [
                {"ip": "1.1.1.1", "country": "DE", "source": "shodan"}
            ]
            result = await toolset.discover_open_resolvers(countries="DE")
        assert result["provider"] == "shodan"
        assert "DE" in result["countries"]

    @pytest.mark.asyncio
    async def test_auto_selects_censys_when_no_shodan(
        self, toolset: GeoResolvers, censys_env: None
    ) -> None:
        with (
            patch.object(
                MODULE, "_discover_censys", new_callable=AsyncMock
            ) as mock_disc,
            patch.object(
                toolset, "_verify_candidates", new_callable=AsyncMock
            ) as mock_ver,
        ):
            mock_disc.return_value = [
                {"ip": "2.2.2.2", "country": "SG", "source": "censys"}
            ]
            mock_ver.return_value = [
                {"ip": "2.2.2.2", "country": "SG", "source": "censys"}
            ]
            result = await toolset.discover_open_resolvers(countries="SG")
        assert result["provider"] == "censys"

    @pytest.mark.asyncio
    async def test_caches_results_in_session(
        self, toolset: GeoResolvers, shodan_env: None
    ) -> None:
        with (
            patch.object(
                MODULE, "_discover_shodan", new_callable=AsyncMock
            ) as mock_disc,
            patch.object(
                toolset, "_verify_candidates", new_callable=AsyncMock
            ) as mock_ver,
        ):
            resolvers = [{"ip": "3.3.3.3", "country": "BR", "source": "shodan"}]
            mock_disc.return_value = resolvers
            mock_ver.return_value = resolvers
            await toolset.discover_open_resolvers(countries="BR")
        assert "BR" in toolset._resolvers

    @pytest.mark.asyncio
    async def test_rejects_unknown_provider(
        self, toolset: GeoResolvers, shodan_env: None
    ) -> None:
        with pytest.raises(GeoResolverError, match="unknown provider"):
            await toolset.discover_open_resolvers(countries="DE", provider="bing")

    @pytest.mark.asyncio
    async def test_no_provider_keys_errors(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        with pytest.raises(GeoResolverError, match="no provider"):
            await toolset.discover_open_resolvers(countries="DE")

    @pytest.mark.asyncio
    async def test_skip_verify(self, toolset: GeoResolvers, shodan_env: None) -> None:
        with patch.object(
            MODULE, "_discover_shodan", new_callable=AsyncMock
        ) as mock_disc:
            resolvers = [{"ip": "4.4.4.4", "country": "JP", "source": "shodan"}]
            mock_disc.return_value = resolvers
            result = await toolset.discover_open_resolvers(countries="JP", verify=False)
        assert result["verified"] is False
        assert "JP" in result["countries"]

    @pytest.mark.asyncio
    async def test_provider_error_captured(
        self, toolset: GeoResolvers, shodan_env: None
    ) -> None:
        with patch.object(
            MODULE,
            "_discover_shodan",
            new_callable=AsyncMock,
            side_effect=GeoResolverError("API down"),
        ):
            result = await toolset.discover_open_resolvers(countries="DE", verify=False)
        assert "DE" in result.get("errors", {})


# ---------------------------------------------------------------------------
# list / clear tools
# ---------------------------------------------------------------------------


class TestListResolvers:
    @pytest.mark.asyncio
    async def test_empty(self, toolset: GeoResolvers, enabled_env: None) -> None:
        result = await toolset.list_open_resolvers()
        assert result["resolver_count"] == 0

    @pytest.mark.asyncio
    async def test_populated(self, toolset: GeoResolvers, enabled_env: None) -> None:
        toolset._resolvers = {"DE": [{"ip": "1.1.1.1"}], "SG": [{"ip": "2.2.2.2"}]}
        result = await toolset.list_open_resolvers()
        assert result["resolver_count"] == 2
        assert "DE" in result["countries"]


class TestClearCache:
    @pytest.mark.asyncio
    async def test_clears(self, toolset: GeoResolvers, enabled_env: None) -> None:
        toolset._resolvers = {"DE": [{"ip": "1.1.1.1"}]}
        result = await toolset.clear_open_resolver_cache()
        assert result["cleared_resolver_count"] == 1
        assert toolset._resolvers == {}


# ---------------------------------------------------------------------------
# resolve_via_open_resolvers (mocked DNS)
# ---------------------------------------------------------------------------


class TestResolveTool:
    @pytest.mark.asyncio
    async def test_detects_divergence(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {
            "DE": [{"ip": "9.9.9.9"}],
            "SG": [{"ip": "8.8.8.8"}],
        }

        async def fake_query(ip: str, hostname: str, **kw: Any) -> dict[str, Any]:
            if ip == "1.1.1.1":
                return {"addresses": ["10.0.0.1"], "cnames": [], "rcode": 0}
            if ip == "9.9.9.9":
                return {"addresses": ["10.0.0.1"], "cnames": [], "rcode": 0}
            if ip == "8.8.8.8":
                return {"addresses": ["10.0.0.99"], "cnames": [], "rcode": 0}
            return {"error": "unknown"}

        with patch.object(MODULE, "query_resolver", side_effect=fake_query):
            result = await toolset.resolve_via_open_resolvers(hostnames="example.com")
        assert result["geo_differentiated_hostnames"] == ["example.com"]
        info = result["results"]["example.com"]
        assert info["geo_differentiated"] is True
        assert "10.0.0.99" in info["addresses_only_seen_regionally"]

    @pytest.mark.asyncio
    async def test_no_divergence(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "9.9.9.9"}]}

        async def fake_query(ip: str, hostname: str, **kw: Any) -> dict[str, Any]:
            return {"addresses": ["1.2.3.4"], "cnames": [], "rcode": 0}

        with patch.object(MODULE, "query_resolver", side_effect=fake_query):
            result = await toolset.resolve_via_open_resolvers(hostnames="example.com")
        assert result.get("geo_differentiated_hostnames", []) == []

    @pytest.mark.asyncio
    async def test_no_resolvers_error(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        with pytest.raises(GeoResolverError, match="no resolvers cached"):
            await toolset.resolve_via_open_resolvers(hostnames="example.com")

    @pytest.mark.asyncio
    async def test_too_many_hostnames(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "1.1.1.1"}]}
        names = ",".join(f"h{i}.example.com" for i in range(30))
        with pytest.raises(GeoResolverError, match="too many hostnames"):
            await toolset.resolve_via_open_resolvers(hostnames=names)

    @pytest.mark.asyncio
    async def test_missing_country_error(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "1.1.1.1"}]}
        with pytest.raises(GeoResolverError, match="no cached resolvers"):
            await toolset.resolve_via_open_resolvers(
                hostnames="example.com", countries="JP"
            )

    @pytest.mark.asyncio
    async def test_invalid_record_type(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "1.1.1.1"}]}
        with pytest.raises(GeoResolverError, match="unsupported"):
            await toolset.resolve_via_open_resolvers(
                hostnames="example.com", record_type="MX"
            )

    @pytest.mark.asyncio
    async def test_unreachable_resolver_reported(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "9.9.9.9"}]}

        async def fake_query(ip: str, hostname: str, **kw: Any) -> dict[str, Any]:
            if ip == "9.9.9.9":
                return {"error": "timeout"}
            return {"addresses": ["1.2.3.4"], "cnames": [], "rcode": 0}

        with patch.object(MODULE, "query_resolver", side_effect=fake_query):
            result = await toolset.resolve_via_open_resolvers(hostnames="example.com")
        assert result["results"]["example.com"]["unreachable_resolvers"]

    @pytest.mark.asyncio
    async def test_multiple_hostnames(
        self, toolset: GeoResolvers, enabled_env: None
    ) -> None:
        toolset._resolvers = {"DE": [{"ip": "9.9.9.9"}]}

        async def fake_query(ip: str, hostname: str, **kw: Any) -> dict[str, Any]:
            return {
                "addresses": [f"10.0.0.{hash(hostname) % 255}"],
                "cnames": [],
                "rcode": 0,
            }

        with patch.object(MODULE, "query_resolver", side_effect=fake_query):
            result = await toolset.resolve_via_open_resolvers(
                hostnames="a.example.com, b.example.com"
            )
        assert "a.example.com" in result["results"]
        assert "b.example.com" in result["results"]
