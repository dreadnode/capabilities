#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.28",
# ]
# ///
"""SecurityContext MCP proxy.

Stdio bridge to the remote SecurityContext Streamable HTTP server at
https://securitycontext.dev/mcp. Runs locally as a stdio MCP server
so the Dreadnode runtime can connect reliably, and proxies tool calls
to the remote endpoint.
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
from fastmcp import FastMCP

REMOTE_URL = os.environ.get(
    "SECURITYCONTEXT_URL", "https://securitycontext.dev/mcp"
)
API_KEY = os.environ.get("SECURITYCONTEXT_API_KEY", "")
TIMEOUT = 120

mcp = FastMCP("securitycontext")


class _RemoteSession:
    """Manages a single MCP session against the remote server."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=TIMEOUT)
        self._session_id: str | None = None
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return

        headers = self._base_headers()
        # Step 1: initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "dreadnode-agent", "version": "1.0"},
            },
        }
        r = await self._client.post(REMOTE_URL, headers=headers, json=init_req)
        r.raise_for_status()
        self._session_id = r.headers.get("mcp-session-id")

        # Step 2: send initialized notification
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        headers = self._base_headers()
        r2 = await self._client.post(REMOTE_URL, headers=headers, json=notif)
        # 202 expected for notifications
        self._initialized = True

    def _base_headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["mcp-session-id"] = self._session_id
        if API_KEY:
            h["X-Api-Key"] = API_KEY
        return h

    async def call_tool(self, name: str, arguments: dict) -> str:
        await self._ensure_initialized()
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        r = await self._client.post(
            REMOTE_URL, headers=self._base_headers(), json=req
        )
        r.raise_for_status()
        return self._parse_response(r.text)

    @staticmethod
    def _parse_response(body: str) -> str:
        """Extract text content from SSE or plain JSON response."""
        # Try SSE format first
        for line in body.split("\n"):
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                    if "result" in data:
                        parts = []
                        for c in data["result"].get("content", []):
                            if c.get("type") == "text":
                                parts.append(c["text"])
                        if parts:
                            return "\n".join(parts)
                    if "error" in data:
                        return f"Error: {data['error']}"
                except json.JSONDecodeError:
                    continue

        # Fall back to plain JSON
        try:
            data = json.loads(body)
            if "result" in data:
                parts = []
                for c in data["result"].get("content", []):
                    if c.get("type") == "text":
                        parts.append(c["text"])
                if parts:
                    return "\n".join(parts)
            if "error" in data:
                return f"Error: {data['error']}"
        except json.JSONDecodeError:
            pass

        return body


_session = _RemoteSession()


@mcp.tool
async def get_security_context(
    repo: str,
    wait: int = 30,
) -> str:
    """Get ready-to-use security context for a GitHub repo: the project's
    history of fixed vulnerabilities, disclosed CVEs, recurring weak spots,
    a hunting brief, and a preview of the top variant leads.

    Call this before auditing, fuzzing, or reviewing a repo. If no context
    exists yet, call create_security_context first.

    Args:
        repo: GitHub repo in owner/name format (e.g. "vercel/next.js").
        wait: Seconds to wait if context is still building (max 60).
    """
    return await _session.call_tool(
        "get_security_context", {"repo": repo, "wait": wait}
    )


@mcp.tool
async def create_security_context(
    repo: str,
    wait: int = 60,
) -> str:
    """Build (or refresh) the security context for a GitHub repo. Use this
    when get_security_context reports that none exists yet. A build typically
    takes ~30-60s; this tool waits for completion.

    Args:
        repo: GitHub repo in owner/name format (e.g. "vercel/next.js").
        wait: Seconds to wait for completion (max 60).
    """
    return await _session.call_tool(
        "create_security_context", {"repo": repo, "wait": wait}
    )


@mcp.tool
async def get_vulnerability_leads(
    repo: str,
    severity: str = "",
    limit: int = 25,
) -> str:
    """List the ranked variant-lead backlog for a GitHub repo: concrete spots
    in the CURRENT code that match a past fix's dangerous pattern.

    Args:
        repo: GitHub repo in owner/name format.
        severity: Filter by severity (critical, high, medium, low). Empty for all.
        limit: Max leads to return.
    """
    args: dict = {"repo": repo, "limit": limit}
    if severity:
        args["severity"] = severity
    return await _session.call_tool("get_vulnerability_leads", args)


if __name__ == "__main__":
    mcp.run()
