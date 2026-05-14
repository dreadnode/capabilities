"""Callback client for out-of-band vulnerability testing.

Registers callback URLs via webhook.site (primary) or interactsh-client CLI
(fallback) for detecting SSRF, XXE, SSTI, and blind injection vulnerabilities.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr


class CallbackClient(Toolset):
    """OOB vulnerability testing via callback URLs.

    Registers with webhook.site (primary) or interactsh (fallback) to provide
    callback URLs for SSRF, XXE, SSTI, and blind injection testing.
    """

    _callback_url: str | None = PrivateAttr(default=None)
    _provider: str | None = PrivateAttr(default=None)
    _token_id: str | None = PrivateAttr(default=None)
    _seen_ids: set[str] = PrivateAttr(default_factory=set)

    async def _register_webhook_site(self) -> bool:
        """Register with webhook.site and return True on success."""
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.post(
                    "https://webhook.site/token",
                    json={
                        "default_content": "OK",
                        "default_status": 200,
                        "default_content_type": "text/plain",
                    },
                )
                if response.status_code != 201:
                    return False
                data = response.json()
                token_id = data.get("uuid")
                if not token_id:
                    return False
                self._token_id = token_id
                self._callback_url = f"https://webhook.site/{token_id}"
                self._provider = "webhook_site"
                return True
        except Exception:
            return False

    def _register_interactsh(self) -> bool:
        """Register with interactsh-client CLI as fallback."""
        try:
            proc = subprocess.run(
                ["interactsh-client", "-json", "-n", "1"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in proc.stdout.splitlines():
                try:
                    data = json.loads(line)
                    if "url" in data:
                        self._callback_url = data["url"]
                        self._provider = "interactsh"
                        return True
                except json.JSONDecodeError:
                    if ".oast." in line or ".interact." in line:
                        url = line.strip()
                        if not url.startswith("http"):
                            url = f"https://{url}"
                        self._callback_url = url
                        self._provider = "interactsh"
                        return True
            return False
        except Exception:
            return False

    async def _ensure_registered(self) -> bool:
        """Ensure a callback URL is registered, trying providers in order."""
        if self._callback_url:
            return True
        if await self._register_webhook_site():
            return True
        return self._register_interactsh()

    @tool_method(name="get_callback_url", catch=True)
    async def get_callback_url(self, protocol: str = "http") -> str:
        """Get a callback URL for out-of-band testing.

        Inject this URL in SSRF, XXE, SSTI, and blind injection payloads,
        then use check_callbacks to detect if the target contacted it.

        Args:
            protocol: Preferred protocol — 'http', 'https', or 'dns'
        """
        if not await self._ensure_registered():
            return "Error: Could not register with any callback provider."

        url = self._callback_url
        if protocol == "https" and url.startswith("http://"):
            url = url.replace("http://", "https://", 1)
        elif protocol == "dns":
            url = url.replace("http://", "").replace("https://", "")

        return (
            f"{url}\n\n"
            f"Provider: {self._provider}. "
            f"Inject this URL in payloads, then use check_callbacks to see if the target contacted it."
        )

    @tool_method(name="check_callbacks", catch=True)
    async def check_callbacks(self, since_seconds: int = 300) -> str:
        """Check for callback interactions received from the target application.

        Call after injecting callback URLs to see if the target made requests.

        Args:
            since_seconds: Only show interactions from last N seconds (default: 300)
        """
        if not self._callback_url:
            return "Error: No callback URL registered. Use get_callback_url first."

        if self._provider == "webhook_site":
            return await self._poll_webhook_site(since_seconds)
        if self._provider == "interactsh":
            return (
                "For interactsh, run in bash: interactsh-client -json | head -20\n\n"
                "The CLI will show any interactions with your callback domain."
            )
        return f"Error: Unknown provider: {self._provider}"

    async def _poll_webhook_site(self, since_seconds: int) -> str:
        """Poll webhook.site for new interactions."""
        if not self._token_id:
            return "Error: No webhook.site token."

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"https://webhook.site/token/{self._token_id}/requests",
                    params={"sorting": "newest"},
                )
                if response.status_code != 200:
                    return f"Error: Poll failed: HTTP {response.status_code}"

                data = response.json()
                requests_data = data.get("data", [])
                if not requests_data:
                    return "No callback interactions received yet."

                cutoff = time.time() - since_seconds
                interactions = []

                for item in requests_data:
                    req_id = item.get("uuid", "")
                    if req_id in self._seen_ids:
                        continue

                    created_at = item.get("created_at", "")
                    try:
                        ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        if ts.timestamp() < cutoff:
                            continue
                    except (ValueError, AttributeError):
                        pass

                    self._seen_ids.add(req_id)
                    method = item.get("method", "GET")
                    url = item.get("url", "")
                    ip = item.get("ip", "unknown")
                    content = item.get("content", "")
                    headers = item.get("headers", {})

                    path = "/"
                    try:
                        parsed = urlparse(url)
                        path = parsed.path or "/"
                        if parsed.query:
                            path += f"?{parsed.query}"
                    except Exception:
                        pass

                    raw = f"{method} {path} HTTP/1.1\n"
                    if headers:
                        for k, v in headers.items():
                            if isinstance(v, list):
                                v = ", ".join(str(x) for x in v)
                            raw += f"{k}: {v}\n"
                    if content:
                        raw += f"\n{content}"

                    interactions.append(
                        {
                            "time": created_at,
                            "method": method,
                            "path": path,
                            "ip": ip,
                            "raw_request": raw[:1000],
                        }
                    )

                if not interactions:
                    return "No new callback interactions since last check."

                lines = [f"Received {len(interactions)} callback interactions:"]
                for i, ix in enumerate(interactions[:10], 1):
                    lines.append(
                        f"  {i}. [{ix['time']}] {ix['method']} {ix['path']} from {ix['ip']}"
                    )

                if interactions:
                    lines.append(
                        f"\nMost recent request:\n{interactions[-1]['raw_request']}"
                    )

                return "\n".join(lines)

        except Exception as e:
            return f"Error: Poll error: {e}"

    @tool_method(name="reset_callback", catch=True)
    async def reset_callback(self) -> str:
        """Reset callback state. Next get_callback_url will register a new URL."""
        self._callback_url = None
        self._provider = None
        self._token_id = None
        self._seen_ids.clear()
        return "Callback state reset. Next get_callback_url will register a new URL."
