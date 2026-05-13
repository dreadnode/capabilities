"""Toolset: attack-path findings, types, trends, and risk acceptance.

Attack paths are BHE's central abstraction — each is a finding tied
to a domain, a principal, and a category (Kerberoastable, ADCS-ESC1,
DCSync, etc.). The tools here let an agent enumerate findings, drill
into a single one, watch trends across days, and mark findings as
accepted or unaccepted risk. Bulk acceptance is the top operator
workflow during AD remediation cycles.
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client


class AttackPathTools(Toolset):
    """Inspect, trend, and triage BHE attack-path findings."""

    @tool_method(name="list_attack_paths", catch=True)
    async def list_attack_paths(
        self,
        domain_sid: t.Annotated[
            str,
            "Filter to a specific domain SID (e.g. 'S-1-5-21-...'). " "Empty returns paths across every domain.",
        ] = "",
        finding: t.Annotated[
            str,
            "Filter by finding type (e.g. 'Kerberoastable'). Empty for all.",
        ] = "",
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 100,
        sort_by: t.Annotated[
            str,
            "Field to sort on. Common: 'finding', 'principal', 'severity'. " "Prefix with '-' for descending.",
        ] = "",
    ) -> str:
        """List active attack-path findings.

        Each row carries a finding type (e.g. ``Kerberoastable``), the
        principal it concerns, the domain SID, and a flag for whether
        risk has been accepted. The default page size (100) is BHE's
        own; raise ``limit`` if you need a wider view in one call.
        """
        params: dict[str, t.Any] = {"skip": skip, "limit": limit}
        if domain_sid:
            params["domain_sid"] = domain_sid
        if finding:
            params["finding"] = finding
        if sort_by:
            params["sort_by"] = sort_by
        client = get_client()
        try:
            data = await client.get_json("/api/v2/attack-paths", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="list_attack_path_types", catch=True)
    async def list_attack_path_types(self) -> str:
        """Catalogue every finding type the deployment recognises.

        Useful when filtering by finding name — the names are
        version-specific and there's no canonical list outside the
        deployment. Returns name + description + category per row.
        """
        client = get_client()
        try:
            data = await client.get_json("/api/v2/attack-paths/types")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="domain_attack_paths", catch=True)
    async def domain_attack_paths(
        self,
        domain_sid: t.Annotated[str, "SID of the target domain"],
    ) -> str:
        """List the attack-path types currently active in one domain.

        Faster than ``list_attack_paths`` when you only care which
        finding categories show up — counts per type, not the full
        finding list.
        """
        if not domain_sid:
            return "error: domain_sid is required"
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/attack-paths/{domain_sid}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="domain_attack_path_details", catch=True)
    async def domain_attack_path_details(
        self,
        domain_sid: t.Annotated[str, "SID of the target domain"],
        finding: t.Annotated[
            str,
            "Optional finding-type filter. Empty for all findings in the domain.",
        ] = "",
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 100,
    ) -> str:
        """Per-finding details for one domain.

        The richest view: each row carries the principal, the
        attack edge, severity, and risk-acceptance state. Use this
        to walk a domain end-to-end during a remediation cycle.
        """
        if not domain_sid:
            return "error: domain_sid is required"
        params: dict[str, t.Any] = {"skip": skip, "limit": limit}
        if finding:
            params["finding"] = finding
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/attack-paths/{domain_sid}/details", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="attack_path_sparklines", catch=True)
    async def attack_path_sparklines(
        self,
        domain_sid: t.Annotated[str, "SID of the target domain"],
        finding: t.Annotated[str, "Finding type to chart"],
        from_date: t.Annotated[
            str,
            "Inclusive start date in RFC3339 format (e.g. 2026-01-01T00:00:00Z).",
        ] = "",
        to_date: t.Annotated[str, "Exclusive end date in RFC3339 format"] = "",
    ) -> str:
        """Time-series datapoints for a (domain, finding) pair.

        Used by posture-trending workflows: feed in a 30-day window
        and watch how a specific attack-path category changed as
        you applied remediations.
        """
        if not domain_sid or not finding:
            return "error: domain_sid and finding are required"
        params: dict[str, t.Any] = {
            "domain_sid": domain_sid,
            "finding": finding,
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        client = get_client()
        try:
            data = await client.get_json("/api/v2/attack-paths/sparklines", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="attack_path_trends", catch=True)
    async def attack_path_trends(
        self,
        from_date: t.Annotated[str, "Inclusive RFC3339 start date"],
        to_date: t.Annotated[str, "Exclusive RFC3339 end date"],
        environments: t.Annotated[
            list[str],
            "Optional list of environment / domain SID filters",
        ] = [],  # noqa: B006
    ) -> str:
        """Cross-domain finding deltas between two dates.

        Returns the count change for every (environment, finding)
        pair in the window — the right tool when an agent is
        producing a "what got better / worse since last week"
        report.
        """
        params: dict[str, t.Any] = {"from": from_date, "to": to_date}
        for env in environments or []:
            params.setdefault("environments", []).append(env)
        client = get_client()
        try:
            data = await client.get_json("/api/v2/attack-paths/trends", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="export_attack_path_findings", catch=True)
    async def export_attack_path_findings(
        self,
        domain_sid: t.Annotated[str, "SID of the target domain"],
        finding: t.Annotated[str, "Finding type to export"],
        format: t.Annotated[str, "'csv' or 'json'"] = "json",
    ) -> str:
        """Export the finding-detail table for one (domain, finding) pair.

        The response is the raw export — passed through verbatim.
        Use this to hand a stakeholder a CSV they can open in
        Excel / paste into a ticket.
        """
        params = {
            "domain_sid": domain_sid,
            "finding": finding,
            "format": format,
        }
        client = get_client()
        try:
            response = await client.get("/api/v2/attack-paths/findings/export", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        if response.status_code >= 400:
            return f"error: HTTP {response.status_code} {response.text[:300]}"
        return response.text

    @tool_method(name="accept_finding_risk", catch=True)
    async def accept_finding_risk(
        self,
        finding_id: t.Annotated[
            str,
            "Id of the finding to mark as accepted (or unaccepted) risk.",
        ],
        accepted: t.Annotated[
            bool,
            "True to accept the risk; false to revoke a prior acceptance.",
        ] = True,
        accepted_until: t.Annotated[
            str,
            "Optional RFC3339 expiry. The acceptance reverts when reached.",
        ] = "",
    ) -> str:
        """Mark a finding as accepted (or unaccepted) risk.

        Acceptance keeps the finding visible but excludes it from
        unresolved counts and notification streams. Use the expiry
        to force a periodic re-review.
        """
        if not finding_id:
            return "error: finding_id is required"
        body: dict[str, t.Any] = {"risk_accepted": bool(accepted)}
        if accepted_until:
            body["accepted_until"] = accepted_until
        client = get_client()
        try:
            data = await client.put_json(f"/api/v2/attack-paths/{finding_id}/risk", json=body)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data or {"updated": finding_id}, indent=2, default=str)

    @tool_method(name="start_attack_path_analysis", catch=True)
    async def start_attack_path_analysis(self) -> str:
        """Trigger a server-side attack-path analysis pass.

        Normally BHE schedules this automatically; manual triggers
        are useful right after a fresh data ingest when you don't
        want to wait for the next cycle.
        """
        client = get_client()
        try:
            data = await client.post_json("/api/v2/attack-paths/start-analysis", json={})
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data or {"started": True}, indent=2, default=str)
