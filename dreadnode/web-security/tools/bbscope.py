"""BBScope client for bug bounty scope intelligence.

Queries the bbscope.com API to find bug bounty programs covering a target,
retrieve program scope details, and enumerate targets across platforms.
"""

from __future__ import annotations

import typing as t

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

_BASE_URL = "https://bbscope.com/api/v1"
_VALID_PLATFORMS = {"h1", "bc", "it", "ywh"}
_VALID_TARGET_TYPES = {"wildcards", "domains", "urls", "ips", "cidrs"}


class BBScope(Toolset):
    """Bug bounty scope intelligence via bbscope.com.

    Queries aggregated scope data from HackerOne, Bugcrowd, Intigriti, and
    YesWeHack to determine whether a target is in scope, retrieve program
    details, and enumerate targets.
    """

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=_BASE_URL,
                timeout=30.0,
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
        return self._client

    @tool_method(name="bbscope_find", catch=True)
    async def find(
        self,
        query: t.Annotated[str, "Hostname or domain to search for (e.g. 'example.com')"],
    ) -> str:
        """Find bug bounty programs whose scope includes a given domain.

        Use this at the start of an engagement to check if the target is
        covered by any bug bounty program, and to retrieve program URLs and
        platform details.
        """
        client = await self._get_client()
        resp = await client.get("/find", params={"q": query})
        if resp.status_code != 200:
            return f"Error: bbscope API returned HTTP {resp.status_code}"

        data = resp.json()
        programs = data.get("programs", [])
        total = data.get("total_count", len(programs))

        if not programs:
            return f"No bug bounty programs found covering '{query}'."

        lines = [f"Found {total} program(s) covering '{query}':\n"]
        for p in programs:
            platform = p.get("platform", "?").upper()
            handle = p.get("handle", "?")
            url = p.get("url", "")
            lines.append(f"  - [{platform}] {handle}: {url}")

        lines.append(
            f"\nUse bbscope_program with platform and handle to get full scope details."
        )
        return "\n".join(lines)

    @tool_method(name="bbscope_program", catch=True)
    async def program(
        self,
        platform: t.Annotated[str, "Platform code: 'h1', 'bc', 'it', or 'ywh'"],
        handle: t.Annotated[str, "Program handle/slug as returned by bbscope_find"],
    ) -> str:
        """Get full scope details for a specific bug bounty program.

        Returns in-scope and out-of-scope targets, program type (BBP vs VDP),
        and direct link to the program page.
        """
        platform = platform.lower()
        if platform not in _VALID_PLATFORMS:
            return f"Error: Invalid platform '{platform}'. Use one of: {', '.join(sorted(_VALID_PLATFORMS))}"

        client = await self._get_client()
        resp = await client.get(f"/programs/{platform}/{handle}")
        if resp.status_code == 404:
            return f"Program '{handle}' not found on platform '{platform}'."
        if resp.status_code != 200:
            return f"Error: bbscope API returned HTTP {resp.status_code}"

        data = resp.json()

        prog_type = "Bug Bounty" if data.get("is_bbp") else "VDP"
        url = data.get("url", "")
        in_count = data.get("in_scope_count", 0)
        out_count = data.get("out_of_scope_count", 0)
        targets = data.get("targets", [])
        categories = data.get("categories", [])

        lines = [
            f"Program: {handle} ({platform.upper()})",
            f"Type: {prog_type}",
            f"URL: {url}",
            f"In-scope targets: {in_count}",
            f"Out-of-scope targets: {out_count}",
        ]

        if categories:
            lines.append(f"Categories: {', '.join(categories)}")

        if targets:
            lines.append(f"\nTargets ({len(targets)}):")
            for target in targets[:50]:
                lines.append(f"  - {target}")
            if len(targets) > 50:
                lines.append(f"  ... and {len(targets) - 50} more")

        return "\n".join(lines)

    @tool_method(name="bbscope_targets", catch=True)
    async def targets(
        self,
        target_type: t.Annotated[
            str,
            "Target type: 'wildcards', 'domains', 'urls', 'ips', or 'cidrs'",
        ],
        platform: t.Annotated[
            str | None,
            "Filter by platform: 'h1', 'bc', 'it', or 'ywh'. None for all.",
        ] = None,
        scope: t.Annotated[
            str,
            "Scope filter: 'in' (default), 'out', or 'all'",
        ] = "in",
        program_type: t.Annotated[
            str | None,
            "Program type filter: 'bbp' for bug bounty, 'vdp' for disclosure. None for all.",
        ] = None,
        limit: t.Annotated[
            int,
            "Max number of targets to return (default 100)",
        ] = 100,
    ) -> str:
        """List targets of a specific type across all bug bounty programs.

        Useful for building target lists for subdomain enumeration (wildcards),
        direct scanning (domains/urls/ips), or network mapping (cidrs).
        """
        if target_type not in _VALID_TARGET_TYPES:
            return f"Error: Invalid target_type '{target_type}'. Use one of: {', '.join(sorted(_VALID_TARGET_TYPES))}"

        if platform and platform.lower() not in _VALID_PLATFORMS:
            return f"Error: Invalid platform '{platform}'. Use one of: {', '.join(sorted(_VALID_PLATFORMS))}"

        params: dict[str, str] = {"format": "json", "scope": scope}
        if platform:
            params["platform"] = platform.lower()
        if program_type:
            params["type"] = program_type

        client = await self._get_client()
        resp = await client.get(f"/targets/{target_type}", params=params)
        if resp.status_code != 200:
            return f"Error: bbscope API returned HTTP {resp.status_code}"

        targets = resp.json()
        if not targets:
            return f"No {target_type} targets found with the given filters."

        total = len(targets)
        shown = targets[:limit]

        lines = [f"Found {total} {target_type} target(s):\n"]
        for t_ in shown:
            lines.append(f"  {t_}")
        if total > limit:
            lines.append(f"\n... {total - limit} more (increase limit to see all)")

        return "\n".join(lines)

    @tool_method(name="bbscope_updates", catch=True)
    async def updates(
        self,
        since: t.Annotated[
            str,
            "Time filter: 'today', 'yesterday', or YYYY-MM-DD date",
        ] = "today",
        platform: t.Annotated[
            str | None,
            "Filter by platform: 'h1', 'bc', 'it', or 'ywh'. None for all.",
        ] = None,
        search: t.Annotated[
            str | None,
            "Text search within updates",
        ] = None,
    ) -> str:
        """Check recent bug bounty scope changes (new targets added, programs removed).

        Useful for finding freshly added attack surface that may not yet be
        well-tested by other researchers.
        """
        params: dict[str, str] = {"since": since, "per_page": "50"}
        if platform:
            params["platform"] = platform.lower()
        if search:
            params["search"] = search

        client = await self._get_client()
        resp = await client.get("/updates", params=params)
        if resp.status_code != 200:
            return f"Error: bbscope API returned HTTP {resp.status_code}"

        data = resp.json()
        updates = data.get("updates", [])
        total = data.get("total_count", 0)

        if not updates:
            return f"No scope updates found since {since}."

        lines = [f"Found {total} scope update(s) since {since}:\n"]
        for u in updates:
            change = u.get("change_type", "?")
            target = u.get("target", "?")
            plat = u.get("platform", "?").upper()
            handle = u.get("handle", "?")
            scope_type = u.get("scope_type", "?")
            ts = u.get("timestamp", "")
            lines.append(f"  [{plat}/{handle}] {change}: {target} (scope: {scope_type}) @ {ts}")

        if total > len(updates):
            lines.append(f"\n... showing {len(updates)} of {total} total updates")

        return "\n".join(lines)
