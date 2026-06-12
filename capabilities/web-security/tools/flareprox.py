"""Flareprox: self-contained Cloudflare Workers IP rotation tool.

Deploys Cloudflare Worker proxies on-demand for IP rotation during web
security testing. No external flareprox binary is required — the worker
script is embedded and deployed via the Cloudflare REST API.

Required environment variables:
    CF_API_TOKEN  - Cloudflare API token with Workers Scripts read/write.
    CF_ACCOUNT_ID - Cloudflare account ID that owns the workers.

Optional:
    FLAREPROX_STATE_FILE - Path to persisted worker state (default: ~/.flareprox/workers.json)
    IPROTATE_ENABLED     - Set to opt into IP rotation usage; the skill gates on this.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Annotated

import httpx
from dreadnode.agents.tools import Toolset, tool_method

# Minimal Cloudflare Worker that proxies requests to a target specified via
# X-Target-URL header or ?url= query parameter. Only a small allowlist of
# headers is forwarded to keep the implementation simple and safe.
_WORKER_SCRIPT = """
export default {
  async fetch(request, env) {
    const url = request.headers.get("X-Target-URL") || new URL(request.url).searchParams.get("url");
    if (!url) {
      return new Response("Missing X-Target-URL header or url query parameter", { status: 400 });
    }

    const headers = new Headers();
    for (const name of ["accept", "authorization", "content-type", "cookie", "user-agent", "x-bug-bounty", "x-poc-step"]) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }

    const init = { method: request.method, headers, redirect: "follow" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    return fetch(url, init);
  }
};
""".strip()

# Headers the worker forwards; mirror this client-side so requests behave predictably.
_PASSTHROUGH_HEADERS = {
    "accept",
    "authorization",
    "content-type",
    "cookie",
    "user-agent",
    "x-bug-bounty",
    "x-poc-step",
}

_DEFAULT_TIMEOUT = 30
_MAX_OUTPUT_CHARS = 50_000


class Flareprox(Toolset):
    """Cloudflare Workers IP rotation for bypassing rate limits and IP bans.

    Deploys worker proxies on demand, routes requests through them, and tears
    them down when finished. Requires CF_API_TOKEN and CF_ACCOUNT_ID.
    """

    account_id: str | None = None
    """Cloudflare account ID. Falls back to CF_ACCOUNT_ID env var."""
    api_token: str | None = None
    """Cloudflare API token. Falls back to CF_API_TOKEN env var."""
    state_file: str = ""
    """Path to persisted worker state. Defaults to ~/.flareprox/workers.json."""

    def model_post_init(self, __context: object) -> None:  # type: ignore[override]
        """Initialize runtime state after pydantic construction."""
        self.account_id = (self.account_id or os.environ.get("CF_ACCOUNT_ID", "")).strip()
        self.api_token = (self.api_token or os.environ.get("CF_API_TOKEN", "")).strip()
        if not self.state_file:
            self.state_file = str(Path.home() / ".flareprox" / "workers.json")
        self._subdomain: str | None = None
        self._load_state()

    def _load_state(self) -> None:
        path = Path(self.state_file)
        if path.exists():
            try:
                self._state = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                self._state = {"workers": []}
        else:
            self._state = {"workers": []}

    def _save_state(self) -> None:
        path = Path(self.state_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._state, indent=2))

    def _client(self) -> httpx.AsyncClient:
        if not self.api_token:
            raise RuntimeError("CF_API_TOKEN not configured")
        if not self.account_id:
            raise RuntimeError("CF_ACCOUNT_ID not configured")
        return httpx.AsyncClient(
            base_url=f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/javascript+module",
            },
            timeout=_DEFAULT_TIMEOUT,
        )

    async def _get_subdomain(self) -> str | None:
        if self._subdomain:
            return self._subdomain
        try:
            async with self._client() as client:
                response = await client.get("/workers/subdomain")
                data = response.json()
                if data.get("success"):
                    self._subdomain = data.get("result", {}).get("subdomain")
                    return self._subdomain
        except Exception:
            return None
        return None

    def _worker_url(self, name: str, subdomain: str) -> str:
        return f"https://{name}.{subdomain}.workers.dev"

    def _configured(self) -> bool:
        return bool(self.api_token and self.account_id)

    @tool_method(name="flareprox_status", catch=True)
    async def flareprox_status(self) -> str:
        """Check Flareprox configuration and count deployed workers.

        Reports whether CF_API_TOKEN and CF_ACCOUNT_ID are set and how many
        active workers are tracked in local state.
        """
        if not self._configured():
            return (
                "Flareprox is not configured. Set CF_API_TOKEN and CF_ACCOUNT_ID\n"
                "environment variables before creating workers."
            )

        subdomain = await self._get_subdomain()
        workers = self._state.get("workers", [])

        lines = [
            "Flareprox status:",
            "  configured: yes",
            f"  account_id: {self.account_id}",
            f"  workers.dev subdomain: {subdomain or 'unknown (verify token/permissions)'}",
            f"  active workers: {len(workers)}",
        ]
        for worker in workers:
            lines.append(f"    - {worker['name']} ({worker.get('url', 'no url')})")
        return "\n".join(lines)

    @tool_method(name="flareprox_create", catch=True)
    async def flareprox_create(
        self,
        count: Annotated[int, "Number of worker proxies to create (default: 1)"] = 1,
    ) -> str:
        """Deploy Cloudflare Worker proxies for IP rotation.

        Each worker gets a unique name and a workers.dev URL. Multiple workers
        provide more egress IPs to rotate through.

        Args:
            count: Number of workers to create.
        """
        if not self._configured():
            return "Error: CF_API_TOKEN and CF_ACCOUNT_ID must be configured."

        count = max(1, count)
        subdomain = await self._get_subdomain()
        if not subdomain:
            return (
                "Error: Could not determine workers.dev subdomain. "
                "Verify CF_API_TOKEN has Workers Scripts read permission and workers.dev is enabled."
            )

        created = []
        async with self._client() as client:
            for _ in range(count):
                name = f"flareprox-{secrets.token_hex(4)}"
                try:
                    response = await client.put(
                        f"/workers/scripts/{name}",
                        content=_WORKER_SCRIPT,
                        headers={"Content-Type": "application/javascript+module"},
                    )
                    data = response.json()
                    if not data.get("success"):
                        errors = data.get("errors", [])
                        return f"Error deploying worker {name}: {errors}"

                    url = self._worker_url(name, subdomain)
                    self._state["workers"].append({"name": name, "url": url})
                    created.append(url)
                except Exception as exc:
                    return f"Error deploying worker: {exc}"

        self._save_state()
        return "Created Flareprox workers:\n" + "\n".join(f"  {url}" for url in created)

    @tool_method(name="flareprox_list", catch=True)
    async def flareprox_list(self) -> str:
        """List active Flareprox workers tracked in local state."""
        workers = self._state.get("workers", [])
        if not workers:
            return "No active Flareprox workers. Use flareprox_create to deploy one."

        lines = [f"Active Flareprox workers ({len(workers)}):"]
        for worker in workers:
            lines.append(f"  {worker['name']}: {worker['url']}")
        return "\n".join(lines)

    @tool_method(name="flareprox_proxy_url", catch=True)
    async def flareprox_proxy_url(self) -> str:
        """Return a worker URL to use as an HTTP proxy.

        The URL rotates round-robin across active workers. Use it with curl or
        execute_http by sending the target URL in the X-Target-URL header or as
        the ?url= query parameter.
        """
        workers = self._state.get("workers", [])
        if not workers:
            return "Error: No active workers. Run flareprox_create first."

        idx = self._state.get("_rr_index", 0) % len(workers)
        self._state["_rr_index"] = idx + 1
        self._save_state()
        return workers[idx]["url"]

    @tool_method(name="flareprox_request", catch=True)
    async def flareprox_request(
        self,
        url: Annotated[str, "Target URL to fetch through the Flareprox worker"],
        method: Annotated[str, "HTTP method"] = "GET",
        headers: Annotated[dict[str, str] | None, "Optional request headers"] = None,
        body: Annotated[str | None, "Optional request body"] = None,
    ) -> str:
        """Send an HTTP request through a Flareprox worker.

        Routes the request via a deployed Cloudflare Worker, which forwards to
        the target URL specified in the X-Target-URL header. Useful for
        bypassing IP-based rate limits and WAF blocks.

        Args:
            url: Target URL to fetch.
            method: HTTP method.
            headers: Optional headers to forward.
            body: Optional request body.
        """
        workers = self._state.get("workers", [])
        if not workers:
            return "Error: No active Flareprox workers. Run flareprox_create first."

        idx = self._state.get("_rr_index", 0) % len(workers)
        self._state["_rr_index"] = idx + 1
        self._save_state()
        worker_url = workers[idx]["url"]

        method = method.upper()
        request_headers = {k.lower(): v for k, v in (headers or {}).items()}
        # Always set the target via header; the worker prefers this over query param.
        request_headers["x-target-url"] = url

        # Drop headers that should not be forwarded through the worker unless
        # explicitly allowed.
        request_headers = {
            k: v for k, v in request_headers.items() if k in _PASSTHROUGH_HEADERS or k == "x-target-url"
        }

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT, follow_redirects=True) as client:
                response = await client.request(
                    method=method,
                    url=worker_url,
                    headers=request_headers,
                    content=body.encode() if body else None,
                )
        except httpx.TimeoutException:
            return f"Error: Request timed out after {_DEFAULT_TIMEOUT}s (via Flareprox)"
        except httpx.ConnectError as exc:
            return f"Error: Could not connect to Flareprox worker {worker_url}: {exc}"
        except Exception as exc:
            return f"Error: Request failed via Flareprox: {exc}"

        response_text = response.text
        if len(response_text) > _MAX_OUTPUT_CHARS:
            total = len(response_text)
            response_text = response_text[:_MAX_OUTPUT_CHARS] + f"\n\n... [TRUNCATED: {total} chars total]"

        return f"HTTP {response.status_code} (via Flareprox {worker_url})\n\n{response_text}"

    @tool_method(name="flareprox_cleanup", catch=True)
    async def flareprox_cleanup(self) -> str:
        """Delete all deployed Flareprox workers.

        Always run this when IP rotation is no longer needed to avoid leaving
        scripts in the Cloudflare account.
        """
        workers = self._state.get("workers", [])
        if not workers:
            return "No active Flareprox workers to clean up."

        removed = []
        errors = []
        async with self._client() as client:
            for worker in workers:
                name = worker["name"]
                try:
                    response = await client.delete(f"/workers/scripts/{name}")
                    data = response.json()
                    if data.get("success"):
                        removed.append(name)
                    else:
                        errors.append(f"{name}: {data.get('errors', [])}")
                except Exception as exc:
                    errors.append(f"{name}: {exc}")

        self._state["workers"] = []
        self._state["_rr_index"] = 0
        self._save_state()

        result = f"Removed {len(removed)} Flareprox worker(s)."
        if removed:
            result += "\n" + "\n".join(f"  - {name}" for name in removed)
        if errors:
            result += "\nErrors:\n" + "\n".join(f"  - {err}" for err in errors)
        return result
