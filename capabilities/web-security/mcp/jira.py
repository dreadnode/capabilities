#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.28",
# ]
# ///
"""Jira Cloud issue tools for web-security report export.

Auth: HTTP Basic via JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN.
Use these tools only after a web-security finding has passed validation.
"""

from __future__ import annotations

import base64
import os
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP

MAX_OUTPUT_CHARS = 30_000

mcp = FastMCP("jira")


class _JiraClient:
    """Lazy Jira Cloud API client."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _settings(self) -> tuple[str, str, str]:
        base_url = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
        email = os.environ.get("JIRA_EMAIL", "").strip()
        token = os.environ.get("JIRA_API_TOKEN", "").strip()

        missing = [
            name
            for name, value in (
                ("JIRA_BASE_URL", base_url),
                ("JIRA_EMAIL", email),
                ("JIRA_API_TOKEN", token),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Jira credentials not configured. "
                f"Set {', '.join(missing)} environment variables."
            )
        return base_url, email, token

    async def get(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client

        base_url, email, token = self._settings()
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=30.0,
            follow_redirects=True,
            headers={
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        return self._client


_jira = _JiraClient()


def _raise_for_jira(resp: httpx.Response, action: str) -> None:
    if 200 <= resp.status_code < 300:
        return
    detail = resp.text[:1000]
    raise RuntimeError(f"Jira {action} failed: HTTP {resp.status_code}: {detail}")


def _adf_text(text: str) -> dict[str, Any]:
    """Convert plain text or Markdown-ish text into simple Jira ADF."""
    content: list[dict[str, Any]] = []
    for block in text.split("\n\n"):
        lines = block.splitlines() or [""]
        paragraph_content: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if line:
                paragraph_content.append({"type": "text", "text": line})
            if index < len(lines) - 1:
                paragraph_content.append({"type": "hardBreak"})
        content.append({"type": "paragraph", "content": paragraph_content})

    if not content:
        content.append({"type": "paragraph", "content": []})

    return {"type": "doc", "version": 1, "content": content}


def _issue_summary(issue: dict[str, Any]) -> str:
    key = issue.get("key") or issue.get("id") or "?"
    fields = issue.get("fields") or {}
    summary = fields.get("summary") or issue.get("summary") or "?"
    status = (fields.get("status") or {}).get("name", "?")
    priority = (fields.get("priority") or {}).get("name", "?")
    return f"{key}\t{status}\t{priority}\t{summary}"


def _truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... [TRUNCATED: {len(value)} chars total]"


@mcp.tool
async def jira_health() -> str:
    """Check Jira API connectivity and show the authenticated user."""
    client = await _jira.get()
    resp = await client.get("/rest/api/3/myself")
    _raise_for_jira(resp, "health check")
    data = resp.json()
    return (
        "Connected to Jira\n"
        f"  Account ID: {data.get('accountId', '?')}\n"
        f"  Display:    {data.get('displayName', '?')}\n"
        f"  Email:      {data.get('emailAddress', '?')}"
    )


@mcp.tool
async def jira_get_create_metadata(
    project_key: Annotated[str, "Jira project key, e.g. ENG"],
) -> str:
    """List issue types available for creating issues in a Jira project."""
    client = await _jira.get()
    resp = await client.get(f"/rest/api/3/issue/createmeta/{project_key}/issuetypes")
    _raise_for_jira(resp, "create metadata lookup")
    issue_types = resp.json().get("issueTypes", [])
    if not issue_types:
        return f"No issue types found for project {project_key}."

    lines = [f"Creatable issue types for {project_key}:"]
    for issue_type in issue_types:
        name = issue_type.get("name", "?")
        issue_type_id = issue_type.get("id", "?")
        description = issue_type.get("description", "")
        line = f"  {issue_type_id}\t{name}"
        if description:
            line += f"\t{description[:120]}"
        lines.append(line)
    return "\n".join(lines)


@mcp.tool
async def jira_create_issue(
    project_key: Annotated[str, "Jira project key, e.g. ENG"],
    issue_type: Annotated[str, "Jira issue type name, e.g. Bug or Task"],
    summary: Annotated[str, "Issue summary/title"],
    description: Annotated[str, "Validated finding or report body"],
    priority: Annotated[str | None, "Optional Jira priority name"] = None,
    labels: Annotated[list[str] | None, "Optional Jira labels"] = None,
    assignee_account_id: Annotated[
        str | None,
        "Optional Jira account ID to assign the issue to",
    ] = None,
    components: Annotated[list[str] | None, "Optional component names"] = None,
) -> str:
    """Create a Jira issue from a validated web-security finding."""
    fields: dict[str, Any] = {
        "project": {"key": project_key},
        "issuetype": {"name": issue_type},
        "summary": summary,
        "description": _adf_text(description),
    }
    if priority:
        fields["priority"] = {"name": priority}
    if labels:
        fields["labels"] = labels
    if assignee_account_id:
        fields["assignee"] = {"accountId": assignee_account_id}
    if components:
        fields["components"] = [{"name": name} for name in components]

    client = await _jira.get()
    resp = await client.post("/rest/api/3/issue", json={"fields": fields})
    _raise_for_jira(resp, "issue create")
    data = resp.json()
    key = data.get("key", "?")
    url = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
    return f"Created Jira issue {key}: {url}/browse/{key}"


@mcp.tool
async def jira_get_issue(
    issue_key: Annotated[str, "Jira issue key, e.g. ENG-123"],
) -> str:
    """Get a Jira issue summary and description."""
    client = await _jira.get()
    resp = await client.get(f"/rest/api/3/issue/{issue_key}")
    _raise_for_jira(resp, "issue fetch")
    data = resp.json()
    fields = data.get("fields") or {}
    description = fields.get("description")
    return _truncate(
        "\n".join(
            [
                _issue_summary(data),
                "",
                "--- Description ADF ---",
                str(description or ""),
            ]
        )
    )


@mcp.tool
async def jira_add_comment(
    issue_key: Annotated[str, "Jira issue key, e.g. ENG-123"],
    body: Annotated[str, "Comment text to add to the issue"],
) -> str:
    """Add a comment to an existing Jira issue."""
    client = await _jira.get()
    resp = await client.post(
        f"/rest/api/3/issue/{issue_key}/comment",
        json={"body": _adf_text(body)},
    )
    _raise_for_jira(resp, "comment create")
    data = resp.json()
    return f"Added comment {data.get('id', '?')} to Jira issue {issue_key}."


if __name__ == "__main__":
    mcp.run()
