#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.28",
# ]
# ///
"""Linear issue tools for web-security report export.

Auth: LINEAR_API_KEY for personal API keys or LINEAR_ACCESS_TOKEN for OAuth.
Use these tools only after a web-security finding has passed validation.
"""

from __future__ import annotations

import os
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP

_DEFAULT_API_URL = "https://api.linear.app/graphql"
MAX_OUTPUT_CHARS = 30_000

mcp = FastMCP("linear")


class _LinearClient:
    """Lazy Linear GraphQL client."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _settings(self) -> tuple[str, str]:
        api_url = os.environ.get("LINEAR_API_URL", _DEFAULT_API_URL).strip()
        access_token = os.environ.get("LINEAR_ACCESS_TOKEN", "").strip()
        api_key = os.environ.get("LINEAR_API_KEY", "").strip()

        if access_token:
            return api_url, f"Bearer {access_token}"
        if api_key:
            return api_url, api_key
        raise RuntimeError(
            "Linear credentials not configured. "
            "Set LINEAR_API_KEY or LINEAR_ACCESS_TOKEN."
        )

    async def get(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client

        api_url, authorization = self._settings()
        self._client = httpx.AsyncClient(
            base_url=api_url,
            timeout=30.0,
            follow_redirects=True,
            headers={
                "Authorization": authorization,
                "Content-Type": "application/json",
            },
        )
        return self._client

    async def graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        client = await self.get()
        resp = await client.post(
            "", json={"query": query, "variables": variables or {}}
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Linear GraphQL request failed: HTTP {resp.status_code}: "
                f"{resp.text[:1000]}"
            )

        data = resp.json()
        errors = data.get("errors")
        if errors:
            messages = "; ".join(str(error.get("message", error)) for error in errors)
            raise RuntimeError(f"Linear GraphQL error: {messages}")
        return data.get("data") or {}


_linear = _LinearClient()


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


@mcp.tool
async def linear_health() -> str:
    """Check Linear API connectivity and show the authenticated viewer."""
    data = await _linear.graphql(
        """
        query Viewer {
          viewer {
            id
            name
            displayName
            email
          }
        }
        """
    )
    viewer = data.get("viewer") or {}
    return (
        "Connected to Linear\n"
        f"  ID:      {viewer.get('id', '?')}\n"
        f"  Name:    {viewer.get('displayName') or viewer.get('name', '?')}\n"
        f"  Email:   {viewer.get('email', '?')}"
    )


@mcp.tool
async def linear_list_teams(
    first: Annotated[int, "Maximum teams to return"] = 50,
) -> str:
    """List Linear teams available to the authenticated token."""
    data = await _linear.graphql(
        """
        query Teams($first: Int!) {
          teams(first: $first) {
            nodes {
              id
              key
              name
            }
          }
        }
        """,
        {"first": min(first, 100)},
    )
    teams = ((data.get("teams") or {}).get("nodes")) or []
    if not teams:
        return "No Linear teams found."

    lines = ["Linear teams:"]
    for team in teams:
        lines.append(
            f"  {team.get('id', '?')}\t{team.get('key', '?')}\t{team.get('name', '?')}"
        )
    return "\n".join(lines)


@mcp.tool
async def linear_create_issue(
    team_id: Annotated[str, "Linear team UUID"],
    title: Annotated[str, "Issue title"],
    description: Annotated[str, "Validated finding or report body in Markdown"],
    priority: Annotated[
        int | None,
        "Optional Linear priority: 0 none, 1 urgent, 2 high, 3 medium, 4 low",
    ] = None,
    assignee_id: Annotated[str | None, "Optional Linear user UUID"] = None,
    project_id: Annotated[str | None, "Optional Linear project UUID"] = None,
    state_id: Annotated[str | None, "Optional Linear workflow status UUID"] = None,
    label_ids: Annotated[list[str] | None, "Optional Linear label UUIDs"] = None,
) -> str:
    """Create a Linear issue from a validated web-security finding."""
    input_data = _drop_empty(
        {
            "teamId": team_id,
            "title": title,
            "description": description,
            "priority": priority,
            "assigneeId": assignee_id,
            "projectId": project_id,
            "stateId": state_id,
            "labelIds": label_ids,
        }
    )

    data = await _linear.graphql(
        """
        mutation IssueCreate($input: IssueCreateInput!) {
          issueCreate(input: $input) {
            success
            issue {
              id
              identifier
              title
              url
            }
          }
        }
        """,
        {"input": input_data},
    )
    result = data.get("issueCreate") or {}
    if not result.get("success"):
        raise RuntimeError("Linear issueCreate returned success=false")

    issue = result.get("issue") or {}
    return (
        f"Created Linear issue {issue.get('identifier', issue.get('id', '?'))}: "
        f"{issue.get('url', '')}"
    ).strip()


@mcp.tool
async def linear_get_issue(
    issue_id: Annotated[str, "Linear issue UUID or identifier, e.g. ENG-123"],
) -> str:
    """Get a Linear issue summary and description."""
    data = await _linear.graphql(
        """
        query Issue($id: String!) {
          issue(id: $id) {
            id
            identifier
            title
            url
            priority
            state { name }
            assignee { name }
            description
          }
        }
        """,
        {"id": issue_id},
    )
    issue = data.get("issue")
    if not issue:
        raise RuntimeError(f"Linear issue not found: {issue_id}")

    lines = [
        f"{issue.get('identifier', issue.get('id', '?'))}\t"
        f"{(issue.get('state') or {}).get('name', '?')}\t"
        f"priority={issue.get('priority', '?')}\t"
        f"{issue.get('title', '?')}",
        f"URL: {issue.get('url', '')}",
        f"Assignee: {(issue.get('assignee') or {}).get('name', 'unassigned')}",
        "",
        "--- Description ---",
        issue.get("description") or "",
    ]
    return _truncate("\n".join(lines))


@mcp.tool
async def linear_add_comment(
    issue_id: Annotated[str, "Linear issue UUID or identifier, e.g. ENG-123"],
    body: Annotated[str, "Markdown comment body"],
) -> str:
    """Add a comment to an existing Linear issue."""
    data = await _linear.graphql(
        """
        mutation CommentCreate($input: CommentCreateInput!) {
          commentCreate(input: $input) {
            success
            comment {
              id
              url
            }
          }
        }
        """,
        {"input": {"issueId": issue_id, "body": body}},
    )
    result = data.get("commentCreate") or {}
    if not result.get("success"):
        raise RuntimeError("Linear commentCreate returned success=false")

    comment = result.get("comment") or {}
    return f"Added Linear comment {comment.get('id', '?')}: {comment.get('url', '')}".strip()


if __name__ == "__main__":
    mcp.run()
