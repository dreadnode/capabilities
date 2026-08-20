"""Tests for the HTTP desync reconnaissance and payload construction tools."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import httpx
import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "desync.py"
SPEC = importlib.util.spec_from_file_location("desync", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DesyncTools = MODULE.DesyncTools
build_payload = MODULE.build_payload
analyze_responses = MODULE.analyze_responses

FAMILIES = (
    "byteranges",
    "cl-whitespace",
    "cl-duplicate",
    "cl-bodyless",
    "connect-cl",
    "te-gzip",
    "cl.te",
    "te.cl",
    "expect-dup",
    "te-obfuscated",
    "vrt",
)


@pytest.fixture
def toolset() -> DesyncTools:
    return DesyncTools()


def _mock_client(handler) -> Any:
    """Patch MODULE._client so probes hit an in-process MockTransport."""

    def factory(proxy: str, timeout: float = 10.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=True
        )

    return factory


# ---------------------------------------------------------------------------
# Discovery / contract
# ---------------------------------------------------------------------------


class TestToolDiscovery:
    def test_is_toolset(self) -> None:
        from dreadnode.agents.tools import Toolset

        assert issubclass(DesyncTools, Toolset)

    def test_tool_methods_registered(self, toolset: DesyncTools) -> None:
        assert {t.name for t in toolset.get_tools()} == {
            "desync_fingerprint",
            "desync_probe_cache",
            "desync_build_payload",
            "desync_analyze_responses",
        }

    def test_every_tool_has_a_description(self, toolset: DesyncTools) -> None:
        assert all(t.description.strip() for t in toolset.get_tools())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("target.com", "https://target.com"),
            ("https://target.com/", "https://target.com"),
            ("http://target.com:8080/", "http://target.com:8080"),
            ("  target.com  ", "https://target.com"),
        ],
    )
    def test_base_url_normalisation(self, raw: str, expected: str) -> None:
        assert MODULE._base_url(raw) == expected

    def test_compact_drops_empty_keeps_falsy_signals(self) -> None:
        result = MODULE._compact(
            {"a": None, "b": "", "c": [], "d": 0, "e": False, "f": "x"}
        )
        assert result == {"d": 0, "e": False, "f": "x"}

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("a" * 20, "aaaaaaaa...aaaa"),
            ("abcdef", "ab..."),
            ("abcd", "***"),
            ("", "***"),
        ],
    )
    def test_redact(self, value: str, expected: str) -> None:
        assert MODULE._redact(value) == expected

    def test_redact_never_leaks_middle_of_long_secret(self) -> None:
        secret = "SUPERSECRETSESSIONVALUE123456"
        assert secret[10:20] not in MODULE._redact(secret)

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("max-age=600", 600),
            ("public, max-age=30, must-revalidate", 30),
            ("s-maxage=90", None),
            ("s-max-age=90", 90),
            ("no-store", None),
            (None, None),
            ("max-age=abc", None),
        ],
    )
    def test_parse_max_age(self, header: str | None, expected: int | None) -> None:
        assert MODULE._parse_max_age(header) == expected


# ---------------------------------------------------------------------------
# Payload construction — the correctness-critical surface
# ---------------------------------------------------------------------------


def _split(raw: str) -> tuple[list[str], str]:
    head, _, body = raw.partition("\r\n\r\n")
    return head.split("\r\n"), body


def _header(lines: list[str], name: str) -> str | None:
    for line in lines:
        key, _, value = line.partition(":")
        if key.strip().lower() == name:
            return value.strip()
    return None


class TestBuildPayload:
    @pytest.mark.parametrize("family", FAMILIES)
    def test_every_family_builds(self, family: str) -> None:
        result = build_payload(family, "target.com")
        assert result["family"] == family
        assert result["note"]
        assert result["byte_length"] == len(result["raw_request"].encode())

    @pytest.mark.parametrize("family", FAMILIES)
    def test_uses_crlf_line_endings_only(self, family: str) -> None:
        raw = build_payload(family, "target.com")["raw_request"]
        assert "\n" not in raw.replace("\r\n", "")

    @pytest.mark.parametrize("family", FAMILIES)
    def test_has_request_line_host_and_header_terminator(self, family: str) -> None:
        raw = build_payload(family, "target.com")["raw_request"]
        lines, _ = _split(raw)
        assert lines[0].endswith(" HTTP/1.1")
        assert _header(lines, "host") == "target.com"
        assert "\r\n\r\n" in raw

    @pytest.mark.parametrize("family", ["byteranges", "cl.te", "te-obfuscated", "vrt"])
    def test_content_length_matches_actual_body_bytes(self, family: str) -> None:
        lines, body = _split(build_payload(family, "target.com")["raw_request"])
        assert int(_header(lines, "content-length")) == len(body.encode())

    def test_te_cl_declares_short_content_length(self) -> None:
        """TE.CL depends on CL being shorter than the chunked body."""
        lines, body = _split(build_payload("te.cl", "target.com")["raw_request"])
        assert int(_header(lines, "content-length")) < len(body.encode())

    def test_te_cl_chunk_size_is_hex_and_matches_prefix(self) -> None:
        _, body = _split(build_payload("te.cl", "target.com")["raw_request"])
        size_line, _, rest = body.partition("\r\n")
        prefix = rest.split("\r\n0\r\n")[0]
        assert int(size_line, 16) == len(prefix.encode())

    def test_cl_te_terminates_chunked_stream_before_prefix(self) -> None:
        _, body = _split(build_payload("cl.te", "target.com")["raw_request"])
        assert body.startswith("0\r\n\r\nGET /admin")

    def test_cl_whitespace_keeps_obfuscated_header_raw(self) -> None:
        raw = build_payload("cl-whitespace", "target.com")["raw_request"]
        assert "\r\n Content-Length:" in raw

    def test_cl_duplicate_emits_two_conflicting_lengths(self) -> None:
        lines, _ = _split(build_payload("cl-duplicate", "target.com")["raw_request"])
        values = [
            line.split(":")[1].strip()
            for line in lines
            if line.lower().startswith("content-length")
        ]
        assert len(values) == 2
        assert values[0] != values[1]

    def test_cl_bodyless_uses_get(self) -> None:
        lines, _ = _split(
            build_payload("cl-bodyless", "target.com", method="POST")["raw_request"]
        )
        assert lines[0].startswith("GET ")

    def test_connect_targets_host_port(self) -> None:
        lines, _ = _split(build_payload("connect-cl", "target.com")["raw_request"])
        assert lines[0] == "CONNECT target.com:443 HTTP/1.1"

    def test_expect_dup_emits_two_expect_headers(self) -> None:
        lines, _ = _split(build_payload("expect-dup", "target.com")["raw_request"])
        assert sum(line.lower().startswith("expect:") for line in lines) == 2

    def test_byteranges_boundary_closes_before_smuggled_prefix(self) -> None:
        _, body = _split(build_payload("byteranges", "target.com")["raw_request"])
        assert body.index("--SMUGGLE--") < body.index("GET /admin")

    def test_vrt_absorbs_victim_headers_with_oversized_length(self) -> None:
        _, body = _split(build_payload("vrt", "target.com")["raw_request"])
        assert "Content-Length: 300" in body

    def test_custom_path_and_method_propagate(self) -> None:
        raw = build_payload("cl.te", "target.com", path="/internal/flag", method="PUT")[
            "raw_request"
        ]
        assert raw.startswith("PUT / HTTP/1.1")
        assert "GET /internal/flag HTTP/1.1" in raw

    def test_long_path_still_produces_matching_length(self) -> None:
        lines, body = _split(
            build_payload("cl.te", "target.com", path="/" + "a" * 500)["raw_request"]
        )
        assert int(_header(lines, "content-length")) == len(body.encode())

    def test_unknown_family_raises_with_valid_options(self) -> None:
        with pytest.raises(ValueError, match="Unknown family"):
            build_payload("nope", "target.com")


# ---------------------------------------------------------------------------
# Stolen-response analysis
# ---------------------------------------------------------------------------

# Assembled at runtime rather than written inline: a literal three-part JWT in
# the source trips secret scanners even though it is a synthetic fixture.
_JWT = ".".join(["eyJ" + "h" * 12, "e" * 16, "s" * 20])


def _resp(headers: dict[str, Any] | None = None, body: str = "") -> dict[str, Any]:
    return {"status": 200, "headers": headers or {}, "body": body}


class TestAnalyzeResponses:
    def test_empty_input_is_low(self) -> None:
        result = analyze_responses([])
        assert result["severity"] == "low"
        assert result["total_responses"] == 0
        assert result["unique_victims"] == 0

    def test_session_cookie_is_critical(self) -> None:
        result = analyze_responses(
            [_resp({"Set-Cookie": "PHPSESSID=abcdef1234567890; HttpOnly"})]
        )
        assert result["severity"] == "critical"
        assert "session_token" in result["categories"]

    def test_session_value_is_redacted(self) -> None:
        value = "s" * 12 + "MIDDLE" + "e" * 12
        result = analyze_responses([_resp({"Set-Cookie": f"JSESSIONID={value}"})])
        assert value not in str(result)
        assert "MIDDLE" not in str(result)

    def test_header_name_matching_is_case_insensitive(self) -> None:
        result = analyze_responses(
            [_resp({"set-cookie": "connect.sid=aaaaaaaaaaaaaaaa"})]
        )
        assert result["severity"] == "critical"

    def test_duplicate_set_cookie_list_is_handled(self) -> None:
        result = analyze_responses(
            [_resp({"Set-Cookie": ["PHPSESSID=aaaaaaaaaaaaaaaa", "theme=dark"]})]
        )
        assert result["unique_victims"] == 1

    def test_non_session_cookie_is_ignored(self) -> None:
        result = analyze_responses([_resp({"Set-Cookie": "theme=dark; Path=/"})])
        assert result["severity"] == "low"

    def test_jwt_in_body_is_critical(self) -> None:
        result = analyze_responses([_resp(body=f'{{"token":"{_JWT}"}}')])
        assert result["severity"] == "critical"
        assert result["findings"][0]["location"] == "body"

    def test_bearer_token_is_critical(self) -> None:
        result = analyze_responses(
            [_resp({"Authorization": "Bearer abcdefghijklmnop"})]
        )
        assert "bearer_token" in result["categories"]

    def test_csrf_token_is_high(self) -> None:
        body = '<form><input type="hidden" name="csrf_token" value="tok1234567890abcd"></form>'
        result = analyze_responses([_resp(body=body)])
        assert result["severity"] == "high"

    def test_pii_is_medium(self) -> None:
        result = analyze_responses([_resp(body="Contact: victim@realcorp.io")])
        assert result["severity"] == "medium"

    def test_placeholder_email_domains_are_not_pii(self) -> None:
        result = analyze_responses([_resp(body="user@example.com and admin@test.com")])
        assert result["severity"] == "low"

    def test_severity_takes_the_most_severe_category(self) -> None:
        result = analyze_responses(
            [
                _resp(body="a@realcorp.io"),
                _resp({"Set-Cookie": "PHPSESSID=aaaaaaaaaaaaaaaa"}),
            ]
        )
        assert result["severity"] == "critical"

    def test_unique_victims_counts_distinct_sessions(self) -> None:
        result = analyze_responses(
            [
                _resp({"Set-Cookie": "PHPSESSID=aaaaaaaaaaaaaaaa"}),
                _resp({"Set-Cookie": "PHPSESSID=bbbbbbbbbbbbbbbb"}),
                _resp({"Set-Cookie": "PHPSESSID=aaaaaaaaaaaaaaaa"}),
            ]
        )
        assert result["unique_victims"] == 2
        assert result["total_responses"] == 3

    def test_pii_reported_once_per_response(self) -> None:
        result = analyze_responses([_resp(body="a@x.io b@y.io c@z.io")])
        assert sum(f["category"] == "pii" for f in result["findings"]) == 1

    def test_host_appears_in_summary_payload(self) -> None:
        result = analyze_responses([_resp()], host="target.com")
        assert result["host"] == "target.com"

    def test_missing_keys_do_not_raise(self) -> None:
        assert analyze_responses([{}])["severity"] == "low"


# ---------------------------------------------------------------------------
# Network probes (mocked transport)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestFingerprint:
    async def test_reports_stack_and_accepted_framing(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "HEAD":
                return httpx.Response(
                    200, headers={"Server": "nginx/1.24", "CF-RAY": "abc-LHR"}
                )
            if request.method == "POST":
                encoding = request.headers.get("transfer-encoding", "")
                return httpx.Response(200 if encoding == "chunked" else 501)
            if "nonexistent" in str(request.url):
                return httpx.Response(404, text="<center>nginx/1.24</center>")
            return httpx.Response(400)  # duplicate CL + bodyless CL rejected

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        result = await toolset.desync_fingerprint("target.com")

        assert result["host"] == "https://target.com"
        assert result["server"] == "nginx/1.24"
        assert result["cdn"] == "cloudflare"
        assert result["error_page_sig"] == "nginx"
        assert result["te_chunked"] is True
        assert result["te_gzip"] is False
        assert result["duplicate_cl"] == "reject"
        assert result["bodyless_cl"] == "reject"

    async def test_accepting_target_opens_families_three_and_four(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            MODULE, "_client", _mock_client(lambda r: httpx.Response(200))
        )
        result = await toolset.desync_fingerprint("target.com")
        assert result["duplicate_cl"] == "accept"
        assert result["bodyless_cl"] == "accept"

    async def test_one_failing_probe_does_not_abort_the_rest(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "HEAD":
                raise httpx.ConnectError("refused")
            return httpx.Response(200, headers={"Server": "envoy"})

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        result = await toolset.desync_fingerprint("target.com")
        assert result["te_chunked"] is True
        assert "server" not in result  # HEAD probe failed, field omitted


@pytest.mark.asyncio
class TestProbeCache:
    async def test_increasing_age_confirms_cache(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ages = iter(["1", "5", "9"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Age": next(ages, "9"),
                    "Cache-Control": "max-age=600",
                    "X-Varnish": "1 2",
                },
            )

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        result = await toolset.desync_probe_cache("target.com")

        assert result["has_cache"] is True
        assert result["ttl_seconds"] == 600
        assert result["cache_type"] == "varnish"

    async def test_no_cache_headers_reports_no_cache(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            MODULE,
            "_client",
            _mock_client(
                lambda r: httpx.Response(200, headers={"Cache-Control": "no-store"})
            ),
        )
        result = await toolset.desync_probe_cache("target.com")
        assert result["has_cache"] is False
        assert "keyed_headers" not in result

    async def test_cf_cache_status_confirms_cache(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            MODULE,
            "_client",
            _mock_client(
                lambda r: httpx.Response(200, headers={"CF-Cache-Status": "HIT"})
            ),
        )
        assert (await toolset.desync_probe_cache("target.com"))["has_cache"] is True

    async def test_cache_key_analysis_splits_keyed_and_unkeyed(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            # A probe carrying Cookie gets a fresh (Age 0) response -> keyed.
            age = "0" if "cookie" in {k.lower() for k in request.headers} else "50"
            return httpx.Response(200, headers={"Age": age})

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        result = await toolset.desync_probe_cache("target.com")

        assert result["keyed_headers"] == ["Cookie"]
        assert "User-Agent" in result["unkeyed_headers"]

    async def test_total_failure_returns_error_not_exception(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        result = await toolset.desync_probe_cache("target.com")
        assert result["has_cache"] is False
        assert "error" in result

    async def test_path_is_normalised(
        self, toolset: DesyncTools, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            return httpx.Response(200)

        monkeypatch.setattr(MODULE, "_client", _mock_client(handler))
        await toolset.desync_probe_cache("target.com", path="static/app.js")
        assert seen[0] == "/static/app.js"


@pytest.mark.asyncio
class TestToolWrappers:
    async def test_build_payload_tool_returns_raw_request(
        self, toolset: DesyncTools
    ) -> None:
        result = await toolset.desync_build_payload("cl.te", "target.com")
        assert result["raw_request"].startswith("POST / HTTP/1.1\r\n")

    async def test_analyze_tool_matches_pure_function(
        self, toolset: DesyncTools
    ) -> None:
        payload = [_resp({"Set-Cookie": "PHPSESSID=aaaaaaaaaaaaaaaa"})]
        assert await toolset.desync_analyze_responses(payload) == analyze_responses(
            payload
        )
