#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.28",
# ]
# ///
"""GitHub issue tools for web-security report export.

Auth: GITHUB_TOKEN with Issues write permission for target repositories.
Use these tools only after a web-security finding has passed validation,
and avoid posting sensitive exploit detail to public repositories unless the
user explicitly confirms that disclosure is intended.
"""

from __future__ import annotations

import os
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP

_DEFAULT_API_URL = "https://api.github.com"
_API_VERSION = "2022-11-28"
MAX_OUTPUT_CHARS = 30_000

mcp = FastMCP("github")


class _GitHubClient:
    """Lazy GitHub REST API client."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _settings(self) -> tuple[str, str]:
        api_url = os.environ.get("GITHUB_API_URL", _DEFAULT_API_URL).strip().rstrip("/")
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "GitHub credentials not configured. Set GITHUB_TOKEN with "
                "Issues write permission for the target repository."
            )
        return api_url, token

    async def get(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client

        api_url, token = self._settings()
        self._client = httpx.AsyncClient(
            base_url=api_url,
            timeout=30.0,
            follow_redirects=True,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _API_VERSION,
            },
        )
        return self._client


_github = _GitHubClient()


def _raise_for_github(resp: httpx.Response, action: str) -> None:
    if 200 <= resp.status_code < 300:
        return
    detail = resp.text[:1000]
    raise RuntimeError(f"GitHub {action} failed: HTTP {resp.status_code}: {detail}")


def _truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... [TRUNCATED: {len(value)} chars total]"


def _drop_empty(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if item is not None and item != "" and item != [] and item != {}
    }


def _issue_line(issue: dict[str, Any]) -> str:
    number = issue.get("number", "?")
    state = issue.get("state", "?")
    title = issue.get("title", "?")
    url = issue.get("html_url", "")
    return f"#{number}\t{state}\t{title}\t{url}"


@mcp.tool
async def github_health() -> str:
    """Check GitHub API connectivity and show the authenticated user."""
    client = await _github.get()
    resp = await client.get("/user")
    _raise_for_github(resp, "health check")
    data = resp.json()
    return (
        "Connected to GitHub\n"
        f"  Login: {data.get('login', '?')}\n"
        f"  ID:    {data.get('id', '?')}\n"
        f"  URL:   {data.get('html_url', '?')}"
    )


@mcp.tool
async def github_list_labels(
    owner: Annotated[str, "Repository owner or organization"],
    repo: Annotated[str, "Repository name"],
    per_page: Annotated[int, "Maximum labels to return"] = 100,
) -> str:
    """List labels for a GitHub repository."""
    client = await _github.get()
    resp = await client.get(
        f"/repos/{owner}/{repo}/labels",
        params={"per_page": min(per_page, 100)},
    )
    _raise_for_github(resp, "label list")
    labels = resp.json()
    if not labels:
        return f"No labels found for {owner}/{repo}."

    lines = [f"Labels for {owner}/{repo}:"]
    for label in labels:
        description = label.get("description") or ""
        line = f"  {label.get('name', '?')}"
        if description:
            line += f"\t{description[:120]}"
        lines.append(line)
    return "\n".join(lines)


@mcp.tool
async def github_create_issue(
    owner: Annotated[str, "Repository owner or organization"],
    repo: Annotated[str, "Repository name"],
    title: Annotated[str, "Issue title"],
    body: Annotated[str, "Validated finding or report body in Markdown"],
    labels: Annotated[list[str] | None, "Optional label names"] = None,
    assignees: Annotated[list[str] | None, "Optional GitHub usernames"] = None,
    milestone: Annotated[int | None, "Optional milestone number"] = None,
) -> str:
    """Create a GitHub issue from a validated web-security finding."""
    payload = _drop_empty(
        {
            "title": title,
            "body": body,
            "labels": labels,
            "assignees": assignees,
            "milestone": milestone,
        }
    )
    client = await _github.get()
    resp = await client.post(f"/repos/{owner}/{repo}/issues", json=payload)
    _raise_for_github(resp, "issue create")
    issue = resp.json()
    return f"Created GitHub issue {_issue_line(issue)}"


@mcp.tool
async def github_get_issue(
    owner: Annotated[str, "Repository owner or organization"],
    repo: Annotated[str, "Repository name"],
    issue_number: Annotated[int, "Issue number"],
) -> str:
    """Get a GitHub issue summary and body."""
    client = await _github.get()
    resp = await client.get(f"/repos/{owner}/{repo}/issues/{issue_number}")
    _raise_for_github(resp, "issue fetch")
    issue = resp.json()
    lines = [
        _issue_line(issue),
        f"Author: {(issue.get('user') or {}).get('login', '?')}",
        f"Labels: {', '.join(label.get('name', '?') for label in issue.get('labels', []))}",
        "",
        "--- Body ---",
        issue.get("body") or "",
    ]
    return _truncate("\n".join(lines))


@mcp.tool
async def github_add_comment(
    owner: Annotated[str, "Repository owner or organization"],
    repo: Annotated[str, "Repository name"],
    issue_number: Annotated[int, "Issue number"],
    body: Annotated[str, "Markdown comment body"],
) -> str:
    """Add a comment to an existing GitHub issue."""
    client = await _github.get()
    resp = await client.post(
        f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        json={"body": body},
    )
    _raise_for_github(resp, "comment create")
    comment = resp.json()
    return f"Added GitHub comment {comment.get('id', '?')}: {comment.get('html_url', '')}".strip()


if __name__ == "__main__":
    mcp.run()
