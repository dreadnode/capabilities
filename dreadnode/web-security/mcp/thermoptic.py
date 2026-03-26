#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.28",
# ]
# ///
"""Thermoptic MCP server.

Host-side wrapper around a Thermoptic proxy running locally, typically via
Docker. This keeps Thermoptic outside the sandbox runtime while exposing a
small MCP tool surface to the agent.
"""

from __future__ import annotations

import os
import random
from typing import Annotated

import httpx
from fastmcp import FastMCP

DEFAULT_PROXY_URL = os.environ.get("THERMOPTIC_PROXY_URL", "http://localhost:1234")
DEFAULT_TIMEOUT = 60
MAX_OUTPUT_CHARS = 50_000

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]


class _ThermopticClient:
    def __init__(self) -> None:
        self.proxy_url = DEFAULT_PROXY_URL
        self.timeout = DEFAULT_TIMEOUT
        self._client: httpx.AsyncClient | None = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                proxy=self.proxy_url,
                verify=False,
            )
        return self._client

    async def reset(self) -> int:
        if self._client is None:
            return 0
        cookie_count = len(self._client.cookies)
        await self._client.aclose()
        self._client = None
        return cookie_count


_thermoptic = _ThermopticClient()
mcp = FastMCP("thermoptic")


@mcp.tool
async def thermoptic_health() -> str:
    """Check whether the Thermoptic proxy is running and reachable."""
    try:
        async with httpx.AsyncClient(
            timeout=5,
            proxy=_thermoptic.proxy_url,
            verify=False,
        ) as client:
            response = await client.get("https://httpbin.org/ip")
    except httpx.ConnectError:
        return (
            f"Error: Cannot connect to Thermoptic at {_thermoptic.proxy_url}. "
            "Start the Thermoptic proxy on the host first."
        )
    except Exception as exc:
        return f"Error: Thermoptic health check failed: {exc}"

    if response.status_code == 200:
        return f"Thermoptic proxy is reachable at {_thermoptic.proxy_url}."
    return f"Error: Thermoptic returned HTTP {response.status_code}."


@mcp.tool
async def thermoptic_request(
    url: Annotated[str, "Full URL to request"],
    method: Annotated[str, "HTTP method"] = "GET",
    headers: Annotated[dict[str, str] | None, "Optional request headers"] = None,
    body: Annotated[str | None, "Optional request body"] = None,
    timeout: Annotated[int | None, "Override timeout in seconds"] = None,
) -> str:
    """Execute an HTTP request through the Thermoptic proxy."""
    method = method.upper()
    request_headers = dict(headers or {})
    request_timeout = timeout or _thermoptic.timeout

    if "user-agent" not in {key.lower() for key in request_headers}:
        request_headers["User-Agent"] = random.choice(_USER_AGENTS)

    try:
        client = _thermoptic._ensure_client()
        response = await client.request(
            method=method,
            url=url,
            headers=request_headers,
            content=body.encode() if body else None,
            timeout=request_timeout,
        )
    except httpx.ConnectError as exc:
        return (
            f"Error: Connection failed through Thermoptic ({_thermoptic.proxy_url}): {exc}\n"
            "Ensure the Thermoptic proxy is running on the host."
        )
    except httpx.TimeoutException:
        return f"Error: Request timed out after {request_timeout}s (via Thermoptic)"
    except Exception as exc:
        return f"Error: Request failed (via Thermoptic): {exc}"

    response_text = response.text
    if len(response_text) > MAX_OUTPUT_CHARS:
        total = len(response_text)
        response_text = response_text[:MAX_OUTPUT_CHARS]
        response_text += f"\n\n... [TRUNCATED: {total} chars total]"

    return f"HTTP {response.status_code} (via Thermoptic)\n\n{response_text}"


@mcp.tool
async def thermoptic_reset() -> str:
    """Reset the Thermoptic session by clearing proxy cookies."""
    cookie_count = await _thermoptic.reset()
    if cookie_count:
        return f"Thermoptic session reset. Cleared {cookie_count} cookies."
    return "No active Thermoptic session."


if __name__ == "__main__":
    mcp.run()
