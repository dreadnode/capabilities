"""Thermoptic stealth proxy for bypassing WAF/bot fingerprinting.

Thermoptic routes HTTP requests through a real Chrome browser via CDP,
producing authentic TLS/HTTP fingerprints (JA4+) that bypass detection
by Cloudflare and similar services. Runs as a local Docker container.

See: https://github.com/mandatoryprogrammer/thermoptic
"""

from __future__ import annotations

import random

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]

_DEFAULT_PROXY_URL = "http://localhost:1234"


class ThermopticTools(Toolset):
    """Execute HTTP requests through the Thermoptic stealth proxy.

    Thermoptic runs a real Chrome instance and replays requests through it
    via CDP, producing authentic browser fingerprints at every network layer.
    Use this when targets block non-browser HTTP clients via JA4+ fingerprinting.
    """

    proxy_url: str = _DEFAULT_PROXY_URL
    """Thermoptic proxy URL (default: http://localhost:1234)."""
    timeout: int = 60
    """Default timeout — higher than execute_http since requests go through Chrome."""
    max_output_chars: int = 50_000
    """Maximum characters returned from response body."""

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                proxy=self.proxy_url,
                verify=False,
            )
        return self._client

    @tool_method(name="thermoptic_health", catch=True)
    async def thermoptic_health(self) -> str:
        """Check if the Thermoptic proxy is running and reachable.

        Call this before using thermoptic_request. If it fails, the proxy
        container is not running — fall back to execute_http or agent-browser.
        """
        try:
            async with httpx.AsyncClient(
                timeout=5, proxy=self.proxy_url, verify=False
            ) as client:
                response = await client.get("https://httpbin.org/ip")
                if response.status_code == 200:
                    return f"Thermoptic proxy is reachable at {self.proxy_url}."
                return f"Error: Thermoptic returned HTTP {response.status_code}."
        except httpx.ConnectError:
            return (
                f"Error: Cannot connect to Thermoptic at {self.proxy_url}. "
                f"Start it with: docker compose up --build"
            )
        except Exception as e:
            return f"Error: Thermoptic health check failed: {e}"

    @tool_method(name="thermoptic_request", catch=True)
    async def thermoptic_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Execute an HTTP request through the Thermoptic stealth proxy.

        The request is replayed through a real Chrome browser, producing
        authentic TLS and HTTP fingerprints that bypass WAF bot detection.
        Cookies persist across requests within this proxy session.

        Use this instead of execute_http when the target blocks requests
        based on TLS/HTTP fingerprinting (Cloudflare, Akamai, etc.).

        Args:
            url: Full URL to request (must include http:// or https://)
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
            headers: Optional HTTP headers as key-value pairs
            body: Optional request body (for POST/PUT/PATCH)
            timeout: Override default timeout in seconds (default: 60)
        """
        method = method.upper()
        headers = headers or {}
        request_timeout = timeout or self.timeout

        if "user-agent" not in {k.lower() for k in headers}:
            headers["User-Agent"] = random.choice(_USER_AGENTS)

        try:
            client = self._ensure_client()
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
                timeout=request_timeout,
            )

            response_text = response.text
            if len(response_text) > self.max_output_chars:
                total = len(response_text)
                response_text = (
                    response_text[: self.max_output_chars]
                    + f"\n\n... [TRUNCATED: {total} chars total]"
                )

            return f"HTTP {response.status_code} (via Thermoptic)\n\n{response_text}"

        except httpx.ConnectError as e:
            return (
                f"Error: Connection failed through Thermoptic ({self.proxy_url}): {e}\n"
                f"Is the proxy running? Start with: docker compose up --build"
            )
        except httpx.TimeoutException:
            return f"Error: Request timed out after {request_timeout}s (via Thermoptic)"
        except Exception as e:
            return f"Error: Request failed (via Thermoptic): {e}"

    @tool_method(name="thermoptic_reset", catch=True)
    async def thermoptic_reset(self) -> str:
        """Reset the Thermoptic session by clearing cookies.

        Thermoptic's Chrome instance persists cookies across requests.
        Use this to clear them when switching test contexts.
        """
        if self._client is not None:
            cookie_count = len(self._client.cookies)
            await self._client.aclose()
            self._client = None
            return f"Thermoptic session reset. Cleared {cookie_count} cookies."
        return "No active Thermoptic session."
