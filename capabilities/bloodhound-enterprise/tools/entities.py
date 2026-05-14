"""Toolset: walk AD and Azure entities.

The BHE entity endpoints answer the most-frequent agent questions
about a single principal: who controls it, what it controls, where
it has admin rights, what sessions it has, who can assume its
identity. Each AD kind (User / Computer / Group / Domain / OU /
GPO) has its own endpoint family; we bundle them under one
toolset and dispatch by kind so the agent doesn't have to know the
URL shape.

Azure entities have a single info endpoint (the graph fans out
through Cypher rather than REST), so we expose one tool that
returns the entity's basic data and counts.
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client


_AD_KINDS = frozenset(
    {
        "user",
        "computer",
        "group",
        "domain",
        "ou",
        "gpo",
        "container",
        "cert-template",
        "aia-ca",
        "root-ca",
        "enterprise-ca",
        "issuance-policy",
    }
)


def _kind_path(kind: str) -> str:
    """Map a kind to its REST endpoint stem.

    The API uses plural slugs (``users``, ``computers``, ``groups``,
    ``domains``, ``ous``, ``gpos``, ``cert-templates``, ``aia-cas``,
    ``root-cas``, ``enterprise-cas``, ``containers``,
    ``issuance-policies``).
    """
    mapping = {
        "user": "users",
        "computer": "computers",
        "group": "groups",
        "domain": "domains",
        "ou": "ous",
        "gpo": "gpos",
        "container": "containers",
        "cert-template": "cert-templates",
        "aia-ca": "aia-cas",
        "root-ca": "root-cas",
        "enterprise-ca": "enterprise-cas",
        "issuance-policy": "issuance-policies",
    }
    return mapping.get(kind.lower().strip(), kind.lower().strip())


class EntityTools(Toolset):
    """Inspect AD and Azure entities by object id."""

    @tool_method(name="get_entity", catch=True)
    async def get_entity(
        self,
        object_id: t.Annotated[
            str,
            "Object id (SID for AD; AAD object id for Azure). Mandatory.",
        ],
    ) -> str:
        """Generic entity lookup — works for any node id.

        Returns the basic node info (kind, name, distinguished name,
        domain) plus relationship counts. Agents that already know
        the kind can call the more specific tools (``user_admins``,
        etc.) for richer data.
        """
        if not object_id:
            return "error: object_id is required"
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/entities/{object_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="entity_controllers", catch=True)
    async def entity_controllers(
        self,
        object_id: t.Annotated[str, "Object id of the controlled entity"],
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 200,
    ) -> str:
        """List principals that can control this entity.

        Combines every "X has rights over Y" relationship into one
        list — Owner, GenericAll, GenericWrite, WriteOwner, etc.
        """
        if not object_id:
            return "error: object_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/entities/{object_id}/controllers",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="entity_controllables", catch=True)
    async def entity_controllables(
        self,
        object_id: t.Annotated[str, "Object id of the controlling entity"],
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 200,
    ) -> str:
        """List entities this principal can control."""
        if not object_id:
            return "error: object_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/entities/{object_id}/controllables",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # User / computer specifics
    # ------------------------------------------------------------------

    @tool_method(name="user_admin_rights", catch=True)
    async def user_admin_rights(
        self,
        user_id: t.Annotated[str, "User SID"],
        kind: t.Annotated[
            str,
            "Right family: 'admin-rights' (default), 'rdp-rights', "
            "'powershell-remote-rights', 'dcom-rights', 'sql-admin-rights', "
            "'constrained-delegation-rights'.",
        ] = "admin-rights",
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 200,
    ) -> str:
        """List the systems a user has elevated access to.

        ``kind`` selects the family — default is local-admin rights
        on every reachable computer; pass ``rdp-rights`` for RDP
        targets, ``powershell-remote-rights`` for WinRM, etc.
        """
        family = kind.strip().lower() or "admin-rights"
        return await self._user_walk(user_id, family, skip=skip, limit=limit)

    @tool_method(name="user_admins", catch=True)
    async def user_admins(
        self,
        user_id: t.Annotated[str, "User SID"],
    ) -> str:
        """List principals that have admin rights *on* the user account."""
        return await self._user_walk(user_id, "admins")

    @tool_method(name="user_sessions", catch=True)
    async def user_sessions(
        self,
        user_id: t.Annotated[str, "User SID"],
    ) -> str:
        """List currently-recorded sessions for the user."""
        return await self._user_walk(user_id, "sessions")

    @tool_method(name="user_membership", catch=True)
    async def user_membership(
        self,
        user_id: t.Annotated[str, "User SID"],
    ) -> str:
        """List groups the user belongs to (direct + transitive)."""
        return await self._user_walk(user_id, "membership")

    @tool_method(name="computer_admins", catch=True)
    async def computer_admins(
        self,
        computer_id: t.Annotated[str, "Computer SID"],
    ) -> str:
        """List principals with admin rights on the computer."""
        return await self._computer_walk(computer_id, "admins")

    @tool_method(name="computer_sessions", catch=True)
    async def computer_sessions(
        self,
        computer_id: t.Annotated[str, "Computer SID"],
    ) -> str:
        """List recorded sessions on the computer (who's logged in / has been)."""
        return await self._computer_walk(computer_id, "sessions")

    @tool_method(name="computer_admin_rights", catch=True)
    async def computer_admin_rights(
        self,
        computer_id: t.Annotated[str, "Computer SID"],
        kind: t.Annotated[
            str,
            "Right family: 'admin-rights' (default), 'rdp-rights', "
            "'powershell-remote-rights', 'dcom-rights', 'sql-admin-rights', "
            "'constrained-delegation-rights'.",
        ] = "admin-rights",
    ) -> str:
        """List systems the *computer* has rights over (often via delegation)."""
        family = kind.strip().lower() or "admin-rights"
        return await self._computer_walk(computer_id, family)

    # ------------------------------------------------------------------
    # Cert template / PKI
    # ------------------------------------------------------------------

    @tool_method(name="cert_template_info", catch=True)
    async def cert_template_info(
        self,
        template_id: t.Annotated[str, "Cert template object id"],
    ) -> str:
        """Get cert template info + relationship counts."""
        if not template_id:
            return "error: template_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/cert-templates/{template_id}"
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="cert_template_cas", catch=True)
    async def cert_template_cas(
        self,
        template_id: t.Annotated[str, "Cert template object id"],
    ) -> str:
        """List enterprise CAs publishing this cert template."""
        if not template_id:
            return "error: template_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/cert-templates/{template_id}/cas"
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    @tool_method(name="azure_entity", catch=True)
    async def azure_entity(
        self,
        object_id: t.Annotated[str, "Azure AD / ARM object id"],
    ) -> str:
        """Return entity info + counts for an Azure node."""
        if not object_id:
            return "error: object_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/azure-entities/{object_id}"
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _user_walk(
        self,
        user_id: str,
        family: str,
        *,
        skip: int = 0,
        limit: int = 200,
    ) -> str:
        if not user_id:
            return "error: user_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/users/{user_id}/{family}",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    async def _computer_walk(
        self,
        computer_id: str,
        family: str,
        *,
        skip: int = 0,
        limit: int = 200,
    ) -> str:
        if not computer_id:
            return "error: computer_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/computers/{computer_id}/{family}",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)


# Re-export validation helper for tests.
__all__ = ["EntityTools", "_AD_KINDS", "_kind_path"]
