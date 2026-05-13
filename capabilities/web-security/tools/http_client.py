"""HTTP client with persistent session management for web security testing.

Provides execute_http with automatic cookie persistence, user-agent rotation,
response formatting, and session management.
"""

from __future__ import annotations

import random

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]


class HttpTools(Toolset):
    """Execute HTTP requests with persistent session management and cookie tracking."""

    timeout: int = 30
    """Default timeout for HTTP requests in seconds."""
    max_output_chars: int = 50_000
    """Maximum characters returned from response body."""

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)

    def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure persistent HTTP client exists, creating it if needed."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
            )
        return self._client

    @tool_method(name="execute_http", catch=True)
    async def execute_http(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Execute an HTTP request with automatic cookie persistence.

        Cookies are preserved across requests. The same session is reused
        for all requests, maintaining authentication state.

        Args:
            url: Full URL to request (must include http:// or https://)
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
            headers: Optional HTTP headers as key-value pairs
            body: Optional request body (for POST/PUT/PATCH)
            timeout: Override default timeout in seconds
        """
        method = method.upper()
        headers = headers or {}
        request_timeout = timeout or self.timeout

        # Add random user agent if not already set
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
                response_text = response_text[: self.max_output_chars] + f"\n\n... [TRUNCATED: {total} chars total]"

            return f"HTTP {response.status_code}\n\n{response_text}"

        except httpx.TimeoutException:
            return f"Error: Request timed out after {request_timeout}s"
        except httpx.ConnectError as e:
            return f"Error: Connection failed: {e}"
        except Exception as e:
            return f"Error: Request failed: {e}"

    @tool_method(name="reset_http_session", catch=True)
    async def reset_http_session(self) -> str:
        """Reset the HTTP session by clearing all cookies.

        Use when switching user accounts, clearing auth state between tests,
        or starting fresh after completing an attack vector.
        """
        if self._client is not None:
            cookie_count = len(self._client.cookies)
            await self._client.aclose()
            self._client = None
            return f"HTTP session reset. Cleared {cookie_count} cookies."
        return "No active HTTP session. Next request will create a new one."

    @tool_method(name="get_http_cookies", catch=True)
    async def get_http_cookies(self) -> str:
        """View all cookies currently stored in the HTTP session.

        Useful for debugging authentication, verifying session tokens,
        and analyzing cookie attributes for security issues.
        """
        client = self._ensure_client()

        if not client.cookies:
            return "No cookies in current HTTP session."

        lines = [f"HTTP Session Cookies ({len(client.cookies.jar)} total):", ""]
        for i, cookie in enumerate(client.cookies.jar, 1):
            value = cookie.value[:50] + "..." if len(cookie.value) > 50 else cookie.value
            lines.append(f"{i}. {cookie.name} = {value}")
            lines.append(f"   Domain: {cookie.domain}, Path: {cookie.path}")

            flags = []
            if hasattr(cookie, "secure") and cookie.secure:
                flags.append("Secure")
            if hasattr(cookie, "expires") and cookie.expires:
                flags.append(f"Expires: {cookie.expires}")
            if flags:
                lines.append(f"   Flags: {', '.join(flags)}")
            lines.append("")

        return "\n".join(lines)
