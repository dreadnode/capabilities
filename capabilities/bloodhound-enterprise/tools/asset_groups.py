"""Toolset: asset groups, tier tags, selectors, and certifications.

Asset groups carve the graph into logical zones — Tier Zero, owned
principals, custom partner-org slices. The tools here let an agent
list and search those zones, inspect their members, manage the
selectors that define membership, and certify (or revoke
certification of) individual nodes.

Tier Zero curation is the highest-leverage operator workflow in BHE:
adding a new asset to Tier Zero changes which findings the analysis
engine surfaces. The toolset is designed so an agent can do that
end-to-end (look up the tag, find the right selector, certify the
node) without dropping out into the UI.
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client


class AssetGroupTools(Toolset):
    """Manage tier tags, selectors, members, and certifications."""

    # ------------------------------------------------------------------
    # Asset groups (legacy — pre-tag system)
    # ------------------------------------------------------------------

    @tool_method(name="list_asset_groups", catch=True)
    async def list_asset_groups(self) -> str:
        """List the legacy asset-isolation groups.

        BHE keeps these around for back-compat with deployments that
        haven't migrated to the asset-group-tag system. Newer
        deployments should prefer ``list_asset_group_tags``.
        """
        client = get_client()
        try:
            data = await client.get_json("/api/v2/asset-groups")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Asset group tags (the modern API)
    # ------------------------------------------------------------------

    @tool_method(name="list_asset_group_tags", catch=True)
    async def list_asset_group_tags(self) -> str:
        """List every tier tag configured on the deployment.

        Tags are ordered (``position``) and carry a ``type``
        distinguishing tiers (Tier Zero, Tier One, ...) from
        labels (Owned, Crown Jewels, etc.). Names of high-tier
        tags are reused across BHE deployments — Tier Zero is
        always Tier Zero — but custom tags vary.
        """
        client = get_client()
        try:
            data = await client.get_json("/api/v2/asset-group-tags")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="get_asset_group_tag", catch=True)
    async def get_asset_group_tag(
        self,
        tag_id: t.Annotated[int, "Tag id (from list_asset_group_tags)"],
    ) -> str:
        """Retrieve a single tag with its description and metadata."""
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/asset-group-tags/{tag_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="list_tag_members", catch=True)
    async def list_tag_members(
        self,
        tag_id: t.Annotated[int, "Tag id (from list_asset_group_tags)"],
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 200,
    ) -> str:
        """List every node in a tag.

        Each row carries the node's object_id, kind, name, the
        selectors that brought it in, and whether it's currently
        certified.
        """
        params = {"skip": skip, "limit": limit}
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/asset-group-tags/{tag_id}/members", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="count_tag_members", catch=True)
    async def count_tag_members(
        self,
        tag_id: t.Annotated[int, "Tag id"],
    ) -> str:
        """Member count broken down by node kind (User / Computer / ...)."""
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/asset-group-tags/{tag_id}/members/count")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="search_asset_group_tags", catch=True)
    async def search_asset_group_tags(
        self,
        query: t.Annotated[
            str,
            "Free-text query — matches against tag names, member names, " "and member object_ids.",
        ],
    ) -> str:
        """Search tags and members by name or id.

        The fastest way to answer "is this user in any tier?" or
        "which tag is named 'Crown Jewels'?" without listing
        everything.
        """
        client = get_client()
        try:
            data = await client.get_json("/api/v2/asset-group-tags/search", params={"query": query})
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Selectors
    # ------------------------------------------------------------------

    @tool_method(name="list_tag_selectors", catch=True)
    async def list_tag_selectors(
        self,
        tag_id: t.Annotated[int, "Tag id"],
    ) -> str:
        """List the selectors that define membership for a tag.

        Each selector is named, optionally a default, and carries a
        Cypher query whose result becomes the selector's members.
        """
        client = get_client()
        try:
            data = await client.get_json(f"/api/v2/asset-group-tags/{tag_id}/selectors")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="create_tag_selector", catch=True)
    async def create_tag_selector(
        self,
        tag_id: t.Annotated[int, "Tag id this selector belongs to"],
        name: t.Annotated[str, "Display name for the selector"],
        cypher_query: t.Annotated[
            str,
            "OpenCypher query whose result populates the selector's members. "
            "The query must return nodes with object_id.",
        ],
        description: t.Annotated[str, "Optional description"] = "",
        is_default: t.Annotated[
            bool,
            "If true, marks the selector as the default for its tag.",
        ] = False,
    ) -> str:
        """Create a Cypher-driven selector for a tag.

        Example for "every Domain Admin":

            MATCH (g:Group)<-[:MemberOf*1..]-(p)
            WHERE g.objectid ENDS WITH '-512'
            RETURN p
        """
        if not cypher_query.strip():
            return "error: cypher_query is required"
        body = {
            "name": name,
            "cypher_query": cypher_query,
            "description": description,
            "is_default": is_default,
        }
        client = get_client()
        try:
            data = await client.post_json(f"/api/v2/asset-group-tags/{tag_id}/selectors", json=body)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="delete_tag_selector", catch=True)
    async def delete_tag_selector(
        self,
        tag_id: t.Annotated[int, "Tag id"],
        selector_id: t.Annotated[int, "Selector id"],
    ) -> str:
        """Remove a selector. Members it contributed are recomputed."""
        client = get_client()
        try:
            await client.delete_json(f"/api/v2/asset-group-tags/{tag_id}/selectors/{selector_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return f"deleted selector {selector_id} from tag {tag_id}"

    @tool_method(name="preview_selector", catch=True)
    async def preview_selector(
        self,
        cypher_query: t.Annotated[
            str,
            "Cypher query to evaluate. Returns the node set without "
            "persisting a selector — useful for verifying coverage "
            "before committing.",
        ],
    ) -> str:
        """Dry-run a selector's Cypher to see what it would match.

        Returns the same shape as the Cypher tools' graph
        responses. Use this before ``create_tag_selector`` to
        verify scope.
        """
        client = get_client()
        try:
            data = await client.post_json(
                "/api/v2/asset-groups/selectors/preview",
                json={"query": cypher_query},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Certifications
    # ------------------------------------------------------------------

    @tool_method(name="certify_member", catch=True)
    async def certify_member(
        self,
        object_id: t.Annotated[
            str,
            "Object_id of the node to certify (e.g. an SID or AAD object id).",
        ],
        certified: t.Annotated[
            bool,
            "True to certify; false to revoke a prior certification.",
        ] = True,
    ) -> str:
        """Manually certify (or revoke certification of) a member node.

        Certification is BHE's way of saying "yes, this node is
        intended to be in this tier" — it's the operator's signal
        that an inclusion is deliberate, not a configuration drift.
        """
        if not object_id:
            return "error: object_id is required"
        client = get_client()
        try:
            data = await client.put_json(
                "/api/v2/asset-group-tags/certify",
                json={"object_id": object_id, "certified": bool(certified)},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(
            data or {"object_id": object_id, "certified": certified},
            indent=2,
            default=str,
        )

    @tool_method(name="get_certifications", catch=True)
    async def get_certifications(
        self,
        tag_id: t.Annotated[
            int,
            "Tag id whose certified nodes to enumerate. Pass 0 to query " "across every tag.",
        ] = 0,
    ) -> str:
        """List certification status for the tag's nodes."""
        params: dict[str, t.Any] = {}
        if tag_id:
            params["tag_id"] = tag_id
        client = get_client()
        try:
            data = await client.get_json("/api/v2/asset-group-tags/certifications", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="tag_history", catch=True)
    async def tag_history(
        self,
        tag_id: t.Annotated[
            int,
            "Optional tag id filter. 0 returns every change across all tags.",
        ] = 0,
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 100,
    ) -> str:
        """Audit log of asset-group-tag mutations.

        Shows who added / removed selectors, certified or revoked
        nodes, and when. The right tool to answer "who changed
        Tier Zero last week?".
        """
        params: dict[str, t.Any] = {"skip": skip, "limit": limit}
        if tag_id:
            params["tag_id"] = tag_id
        client = get_client()
        try:
            data = await client.get_json("/api/v2/asset-group-tags/history", params=params)
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)
