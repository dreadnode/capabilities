#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "httpx>=0.27",
# ]
# ///
"""HackerOne API tools — query programs, scopes, reports, and hacktivity.

Auth: HTTP Basic via H1_USERNAME + H1_API_TOKEN env vars.
Obtain a token from https://hackerone.com/settings/api_token/edit

All endpoints hit the HackerOne Hacker API v1 (JSON:API format).
"""

from __future__ import annotations

import base64
import os
from typing import Annotated

import httpx
from fastmcp import FastMCP

_BASE_URL = "https://api.hackerone.com/v1"
MAX_OUTPUT_CHARS = 50_000
MAX_AUTO_PAGES = 10


class _H1Client:
    """Lazy HackerOne API client — authenticates on first use."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_auth_header(self) -> str | None:
        username = os.environ.get("H1_USERNAME")
        token = os.environ.get("H1_API_TOKEN")
        if not username or not token:
            return None
        return base64.b64encode(f"{username}:{token}".encode()).decode()

    async def get(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client

        auth = self._get_auth_header()
        if not auth:
            raise RuntimeError(
                "HackerOne credentials not configured. "
                "Set H1_USERNAME and H1_API_TOKEN environment variables. "
                "Get your token at https://hackerone.com/settings/api_token/edit"
            )

        self._client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=30.0,
            follow_redirects=True,
            headers={
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
            },
        )
        return self._client

    async def safe_get(self) -> tuple[httpx.AsyncClient | None, str | None]:
        try:
            return await self.get(), None
        except Exception as exc:
            self._client = None
            return None, f"Error: {exc}"


_h1 = _H1Client()

mcp = FastMCP("hackerone")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attr(resource: dict, key: str, default: str = "") -> str:
    """Extract an attribute from a JSON:API resource."""
    return str(resource.get("attributes", {}).get(key, default))


def _rel_data(resource: dict, rel_name: str) -> dict | None:
    """Extract relationship data from a JSON:API resource."""
    rel = resource.get("relationships", {}).get(rel_name, {})
    return rel.get("data")


async def _paginate_all(
    client: httpx.AsyncClient,
    path: str,
    params: dict | None = None,
    max_pages: int = MAX_AUTO_PAGES,
    page_size: int = 100,
) -> list[dict]:
    """Auto-paginate a JSON:API collection endpoint."""
    params = dict(params or {})
    params["page[size]"] = str(page_size)
    all_items: list[dict] = []

    for page_num in range(1, max_pages + 1):
        params["page[number]"] = str(page_num)
        resp = await client.get(path, params=params)
        if resp.status_code != 200:
            break
        data = resp.json()
        items = data.get("data", [])
        if not items:
            break
        all_items.extend(items)
        # Stop if we got fewer than a full page
        if len(items) < page_size:
            break

    return all_items


# ---------------------------------------------------------------------------
# Health / Profile
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_health() -> str:
    """Check HackerOne API connection and show hacker profile."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get("/hackers/me")
    if resp.status_code != 200:
        return f"Error: HackerOne API returned HTTP {resp.status_code}"

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    return (
        f"Connected to HackerOne API\n"
        f"  Username:   {attrs.get('username', '?')}\n"
        f"  Reputation: {attrs.get('reputation', '?')}\n"
        f"  Signal:     {attrs.get('signal', '?')}\n"
        f"  Impact:     {attrs.get('impact', '?')}\n"
        f"  Rank:       {attrs.get('rank', '?')}"
    )


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_list_programs(
    page_size: Annotated[int, "Results per page (max 100)"] = 50,
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """List bug bounty programs you have access to on HackerOne."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get(
        "/hackers/programs",
        params={"page[size]": str(min(page_size, 100)), "page[number]": str(page)},
    )
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    programs = resp.json().get("data", [])
    if not programs:
        return "No programs found."

    lines: list[str] = []
    for p in programs:
        handle = _attr(p, "handle")
        name = _attr(p, "name")
        bounties = "BBP" if _attr(p, "offers_bounties") == "True" else "VDP"
        state = _attr(p, "submission_state")
        lines.append(f"  {handle}\t{name}\t{bounties}\t{state}")

    return f"Programs (page {page}):\n" + "\n".join(lines)


@mcp.tool
async def hackerone_get_program(
    program_handle: Annotated[str, "Program handle (e.g. 'security')"],
) -> str:
    """Get detailed info about a specific HackerOne program including policy and response metrics."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get(f"/hackers/programs/{program_handle}")
    if resp.status_code == 404:
        return f"Program '{program_handle}' not found."
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})

    bounties = "Bug Bounty" if attrs.get("offers_bounties") else "VDP"
    lines = [
        f"Program: {attrs.get('name', '?')} ({attrs.get('handle', '?')})",
        f"Type: {bounties}",
        f"State: {attrs.get('state', '?')} / {attrs.get('submission_state', '?')}",
        f"Started: {attrs.get('started_accepting_at', '?')}",
        f"Response efficiency: {attrs.get('response_efficiency_percentage', '?')}%",
        f"Avg time to first response: {attrs.get('average_time_to_first_program_response', '?')}",
        f"Avg time to resolution: {attrs.get('average_time_to_report_resolved', '?')}",
        f"Avg time to bounty: {attrs.get('average_time_to_bounty_awarded', '?')}",
        f"Bounty splitting: {attrs.get('allow_bounty_splitting', '?')}",
    ]

    policy = attrs.get("policy", "")
    if policy:
        truncated = policy[:3000]
        if len(policy) > 3000:
            truncated += f"\n... [TRUNCATED: {len(policy)} chars total]"
        lines.append(f"\n--- Policy ---\n{truncated}")

    return "\n".join(lines)


@mcp.tool
async def hackerone_get_program_scope(
    program_handle: Annotated[str, "Program handle"],
    page_size: Annotated[int, "Results per page (max 100)"] = 100,
) -> str:
    """Get in-scope assets for a HackerOne program.

    Returns asset types, identifiers, bounty eligibility, max severity,
    and any special instructions. Use this to understand exactly what
    you can test before starting an engagement.
    """
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    items = await _paginate_all(
        client,
        f"/hackers/programs/{program_handle}/structured_scopes",
        page_size=min(page_size, 100),
    )

    if not items:
        return f"No scope assets found for '{program_handle}'."

    lines = [f"Scope for {program_handle} ({len(items)} assets):\n"]
    for item in items:
        attrs = item.get("attributes", {})
        asset_type = attrs.get("asset_type", "?")
        identifier = attrs.get("asset_identifier", "?")
        bounty = "bounty" if attrs.get("eligible_for_bounty") else "no-bounty"
        max_sev = attrs.get("max_severity", "?")
        instruction = attrs.get("instruction", "")

        line = f"  [{asset_type}] {identifier}  ({bounty}, max: {max_sev})"
        if instruction:
            line += f"\n    Note: {instruction[:200]}"
        lines.append(line)

    return "\n".join(lines)


@mcp.tool
async def hackerone_get_program_weaknesses(
    program_handle: Annotated[str, "Program handle"],
) -> str:
    """Get accepted weakness/CWE types for a HackerOne program.

    Useful for understanding which vulnerability categories the program
    accepts before writing a report.
    """
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    items = await _paginate_all(
        client,
        f"/hackers/programs/{program_handle}/weaknesses",
    )

    if not items:
        return f"No weakness types found for '{program_handle}'."

    lines = [f"Accepted weaknesses for {program_handle} ({len(items)}):\n"]
    for item in items:
        attrs = item.get("attributes", {})
        name = attrs.get("name", "?")
        ext_id = attrs.get("external_id", "")
        desc = attrs.get("description", "")
        line = f"  {ext_id}: {name}" if ext_id else f"  {name}"
        if desc:
            line += f" — {desc[:120]}"
        lines.append(line)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_search_reports(
    program: Annotated[str | None, "Filter by program handle"] = None,
    severity: Annotated[
        str | None,
        "Filter by severity: 'none', 'low', 'medium', 'high', 'critical'",
    ] = None,
    state: Annotated[
        str | None,
        "Filter by state: 'new', 'triaged', 'resolved', 'not-applicable', 'informative', 'duplicate'",
    ] = None,
    page_size: Annotated[int, "Results per page (max 100)"] = 25,
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """Search your submitted HackerOne reports with optional filters."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    params: dict[str, str] = {
        "page[size]": str(min(page_size, 100)),
        "page[number]": str(page),
    }
    if program:
        params["filter[program][]"] = program
    if severity:
        params["filter[severity][]"] = severity
    if state:
        params["filter[state][]"] = state

    resp = await client.get("/hackers/me/reports", params=params)
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    reports = resp.json().get("data", [])
    if not reports:
        return "No reports found matching filters."

    lines = [f"Reports (page {page}):\n"]
    for r in reports:
        attrs = r.get("attributes", {})
        rid = r.get("id", "?")
        title = attrs.get("title", "?")
        r_state = attrs.get("state", "?")
        sev = attrs.get("severity_rating") or "none"
        created = attrs.get("created_at", "?")[:10]
        bounty = attrs.get("bounty_awarded_amount")
        bounty_str = f"${bounty}" if bounty else "-"

        lines.append(f"  #{rid}\t{r_state}\t{sev}\t{bounty_str}\t{created}\t{title}")

    return "\n".join(lines)


@mcp.tool
async def hackerone_get_report(
    report_id: Annotated[str, "HackerOne report ID"],
) -> str:
    """Get full details of a specific HackerOne report including vulnerability info, impact, and CVSS."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get(f"/hackers/reports/{report_id}")
    if resp.status_code == 404:
        return f"Report #{report_id} not found."
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})

    lines = [
        f"Report #{data.get('id', '?')}: {attrs.get('title', '?')}",
        f"State: {attrs.get('state', '?')} / {attrs.get('substate', '?')}",
        f"Severity: {attrs.get('severity_rating', 'none')}",
        f"Created: {attrs.get('created_at', '?')}",
        f"Disclosed: {attrs.get('disclosed_at', 'not disclosed')}",
    ]

    # Bounty
    bounty = attrs.get("bounty_awarded_amount")
    if bounty:
        bonus = attrs.get("bounty_bonus_amount", "0")
        lines.append(f"Bounty: ${bounty} + ${bonus} bonus")

    # CVSS
    cvss = attrs.get("cvss_score")
    if cvss:
        lines.append(f"CVSS: {cvss}")

    # Weakness
    weakness_data = _rel_data(data, "weakness")
    if weakness_data:
        lines.append(f"Weakness ID: {weakness_data.get('id', '?')}")

    # Scope
    scope_data = _rel_data(data, "structured_scope")
    if scope_data:
        lines.append(f"Scope ID: {scope_data.get('id', '?')}")

    # Vulnerability info
    vuln_info = attrs.get("vulnerability_information", "")
    if vuln_info:
        truncated = vuln_info[:MAX_OUTPUT_CHARS]
        if len(vuln_info) > MAX_OUTPUT_CHARS:
            truncated += f"\n... [TRUNCATED: {len(vuln_info)} chars total]"
        lines.append(f"\n--- Vulnerability Information ---\n{truncated}")

    # Impact
    impact = attrs.get("impact", "")
    if impact:
        truncated = impact[:5000]
        if len(impact) > 5000:
            truncated += f"\n... [TRUNCATED: {len(impact)} chars total]"
        lines.append(f"\n--- Impact ---\n{truncated}")

    return "\n".join(lines)


@mcp.tool
async def hackerone_get_report_activities(
    report_id: Annotated[str, "HackerOne report ID"],
    page_size: Annotated[int, "Max activities to return"] = 25,
) -> str:
    """Get the activity timeline for a report (comments, state changes, bounty awards).

    Use this to follow the triage conversation and understand the
    current status of a report.
    """
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get(
        f"/hackers/reports/{report_id}/activities",
        params={"page[size]": str(min(page_size, 100))},
    )
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    activities = resp.json().get("data", [])
    if not activities:
        return f"No activities found for report #{report_id}."

    lines = [f"Activities for report #{report_id}:\n"]
    for act in activities:
        attrs = act.get("attributes", {})
        act_type = act.get("type", "?")
        created = attrs.get("created_at", "?")[:19]
        message = attrs.get("message", "")
        internal = " [internal]" if attrs.get("internal") else ""
        auto = " [auto]" if attrs.get("automated_response") else ""

        header = f"  [{created}] {act_type}{internal}{auto}"
        if message:
            msg_preview = message[:300].replace("\n", " ")
            if len(message) > 300:
                msg_preview += "..."
            lines.append(f"{header}\n    {msg_preview}")
        else:
            lines.append(header)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report Actions (write operations)
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_submit_report(
    program_handle: Annotated[str, "Target program handle"],
    title: Annotated[str, "Report title"],
    vulnerability_information: Annotated[str, "Detailed vulnerability description with reproduction steps"],
    impact: Annotated[str, "Security impact statement"],
    severity_rating: Annotated[
        str,
        "Severity: 'none', 'low', 'medium', 'high', 'critical'",
    ],
    weakness_id: Annotated[str | None, "CWE weakness ID (from hackerone_get_program_weaknesses)"] = None,
    structured_scope_id: Annotated[str | None, "Scope asset ID (from hackerone_get_program_scope)"] = None,
) -> str:
    """Submit a new vulnerability report to a HackerOne program.

    Only use this after the full reporting pipeline: assess_confidence
    returned CONFIRMED, report-preflight passed, and exploit-verifier
    completed the triple-check.
    """
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    payload: dict = {
        "data": {
            "type": "report",
            "attributes": {
                "title": title,
                "vulnerability_information": vulnerability_information,
                "impact": impact,
                "severity_rating": severity_rating,
            },
            "relationships": {
                "program": {
                    "data": {"type": "program", "id": program_handle},
                },
            },
        },
    }

    if weakness_id:
        payload["data"]["relationships"]["weakness"] = {
            "data": {"type": "weakness", "id": weakness_id},
        }
    if structured_scope_id:
        payload["data"]["relationships"]["structured_scope"] = {
            "data": {"type": "structured_scope", "id": structured_scope_id},
        }

    resp = await client.post(
        "/hackers/reports",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    if resp.status_code in (201, 200):
        data = resp.json().get("data", {})
        return (
            f"Report submitted successfully!\n"
            f"  ID: #{data.get('id', '?')}\n"
            f"  Title: {data.get('attributes', {}).get('title', '?')}\n"
            f"  State: {data.get('attributes', {}).get('state', '?')}"
        )

    # Error handling
    try:
        errors = resp.json().get("errors", [])
        error_msgs = [e.get("detail", str(e)) for e in errors]
        return f"Error submitting report (HTTP {resp.status_code}):\n" + "\n".join(f"  - {m}" for m in error_msgs)
    except Exception:
        return f"Error: HTTP {resp.status_code} — {resp.text[:500]}"


@mcp.tool
async def hackerone_add_comment(
    report_id: Annotated[str, "HackerOne report ID"],
    message: Annotated[str, "Comment text (markdown supported)"],
    internal: Annotated[bool, "If true, only visible to you (not the program team)"] = False,
) -> str:
    """Add a comment to an existing HackerOne report."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    payload = {
        "data": {
            "type": "activity-comment",
            "attributes": {
                "message": message,
                "internal": internal,
            },
        },
    }

    resp = await client.post(
        f"/hackers/reports/{report_id}/activities",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    if resp.status_code in (200, 201):
        return f"Comment added to report #{report_id}."

    return f"Error adding comment: HTTP {resp.status_code} — {resp.text[:500]}"


# ---------------------------------------------------------------------------
# Hacktivity (public disclosures)
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_search_hacktivity(
    program: Annotated[str | None, "Filter by program handle"] = None,
    page_size: Annotated[int, "Results per page (max 100)"] = 25,
) -> str:
    """Search publicly disclosed reports on HackerOne (hacktivity).

    Useful for learning what vulnerability types have been found in
    a program before, and how they were exploited.
    """
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    params: dict[str, str] = {"page[size]": str(min(page_size, 100))}
    if program:
        params["filter[team_handle][]"] = program

    resp = await client.get("/hackers/hacktivity", params=params)
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    items = resp.json().get("data", [])
    if not items:
        return "No disclosed reports found."

    lines = ["Disclosed reports:\n"]
    for item in items:
        attrs = item.get("attributes", {})
        title = attrs.get("title", "?")
        sev = attrs.get("severity_rating", "?")
        disclosed = attrs.get("disclosed_at", "?")[:10]
        bounty = attrs.get("total_awarded_amount")
        bounty_str = f"${bounty}" if bounty else "-"

        lines.append(f"  {sev}\t{bounty_str}\t{disclosed}\t{title}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Earnings
# ---------------------------------------------------------------------------


@mcp.tool
async def hackerone_get_earnings(
    page_size: Annotated[int, "Results per page (max 100)"] = 25,
    page: Annotated[int, "Page number"] = 1,
) -> str:
    """Get your HackerOne bounty earnings history."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get(
        "/hackers/payments/earnings",
        params={"page[size]": str(min(page_size, 100)), "page[number]": str(page)},
    )
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    items = resp.json().get("data", [])
    if not items:
        return "No earnings found."

    lines = ["Earnings:\n"]
    for item in items:
        attrs = item.get("attributes", {})
        amount = attrs.get("amount", "?")
        currency = attrs.get("currency", "USD")
        awarded_by = attrs.get("awarded_by", "?")
        created = attrs.get("created_at", "?")[:10]
        lines.append(f"  {created}\t{amount} {currency}\t{awarded_by}")

    return "\n".join(lines)


@mcp.tool
async def hackerone_get_balance() -> str:
    """Get your current unpaid HackerOne bounty balance."""
    client, err = await _h1.safe_get()
    if err:
        return err
    assert client is not None

    resp = await client.get("/hackers/payments/balance")
    if resp.status_code != 200:
        return f"Error: HTTP {resp.status_code}"

    data = resp.json()
    balance = data.get("balance", data)
    return f"Current balance: {balance}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
