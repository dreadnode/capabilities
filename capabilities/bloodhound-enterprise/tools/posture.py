"""Toolset: posture / exposure trends and audit logs.

The posture endpoints surface domain-level rollups: tier-zero
counts, exposure index, critical-risk counts. The audit-log
endpoint surfaces who-did-what across the deployment. Together
they answer the questions a stakeholder asks at the end of a
remediation cycle:

- "What's our exposure today vs. last week?"
- "Who accepted these findings as risk?"
- "What changed in Tier Zero in the last 30 days?"
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client


class PostureTools(Toolset):
    """Domain exposure rollups + audit logs."""

    @tool_method(name="posture_snapshot", catch=True)
    async def posture_snapshot(
        self,
        domain_sid: t.Annotated[
            str,
            "Optional domain SID filter. Empty returns every domain.",
        ] = "",
    ) -> str:
        """Latest posture snapshot per domain.

        Wraps the ``/api/v2/posture-stats`` family — exposure index,
        tier-zero count, critical-risk count for the most recent
        analysis pass.
        """
        params: dict[str, t.Any] = {}
        if domain_sid:
            params["domain_sid"] = domain_sid
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/posture-stats", params=params
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="posture_history", catch=True)
    async def posture_history(
        self,
        domain_sid: t.Annotated[str, "Domain SID"],
        from_date: t.Annotated[str, "Inclusive RFC3339 start date"] = "",
        to_date: t.Annotated[str, "Exclusive RFC3339 end date"] = "",
    ) -> str:
        """Time-series posture for one domain.

        The agent's go-to for trend reports — pair with
        ``attack_path_trends`` to correlate "exposure went down"
        with "specific findings dropped".
        """
        if not domain_sid:
            return "error: domain_sid is required"
        params: dict[str, t.Any] = {"domain_sid": domain_sid}
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/posture-stats/history", params=params
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="audit_logs", catch=True)
    async def audit_logs(
        self,
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 100,
        action: t.Annotated[
            str,
            "Optional action filter (e.g. 'CreateUser', 'AcceptRisk', "
            "'CertifyMember'). Empty for all.",
        ] = "",
        actor_email: t.Annotated[
            str, "Filter by actor email address"
        ] = "",
        from_date: t.Annotated[
            str, "RFC3339 start of search window"
        ] = "",
        to_date: t.Annotated[
            str, "RFC3339 end of search window"
        ] = "",
    ) -> str:
        """Query the BHE audit log.

        Returns the recent N actions taken on the deployment with
        actor + timestamp + request id. Use the filters to narrow
        to a specific incident or actor.
        """
        params: dict[str, t.Any] = {"skip": skip, "limit": limit}
        if action:
            params["action"] = action
        if actor_email:
            params["actor_email"] = actor_email
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/audit/logs", params=params
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)
