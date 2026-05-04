"""Toolset: authentication, identity, and API-token management.

Six tools cover the three things an agent needs at the start of any
session: confirm credentials work (``connect`` / ``whoami``), enumerate
existing HMAC tokens, and create / revoke them. Tokens created here
are returned exactly once — the API key cannot be retrieved later.
"""

from __future__ import annotations

import json
import typing as t

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import (
    BHEAPIError,
    BHEAuthError,
    BHEConfig,
    get_client,
    reset_client,
)


class AuthTools(Toolset):
    """Manage BloodHound Enterprise authentication state."""

    @tool_method(name="connect", catch=True)
    async def connect(
        self,
        url: t.Annotated[
            str,
            "BHE base URL (e.g. https://bhe.example.com). If blank, "
            "BLOODHOUND_URL from the environment is used.",
        ] = "",
        token_id: t.Annotated[
            str,
            "HMAC token id. Pair with token_key for signed-request mode.",
        ] = "",
        token_key: t.Annotated[
            str,
            "HMAC token key. Pair with token_id for signed-request mode.",
        ] = "",
        username: t.Annotated[
            str,
            "BHE login email. Used with password for JWT mode.",
        ] = "",
        password: t.Annotated[
            str,
            "BHE login password. Used with username for JWT mode.",
        ] = "",
    ) -> str:
        """Configure credentials and confirm the API responds.

        Provide either an HMAC ``token_id`` + ``token_key`` (long-lived,
        recommended) or ``username`` + ``password`` (which is exchanged
        for a JWT). Empty args fall back to environment variables.
        """
        await reset_client()
        try:
            config = BHEConfig.from_env()
        except Exception:  # noqa: BLE001
            config = BHEConfig(base_url="")
        if url:
            config.base_url = url.strip().rstrip("/")
        if not config.base_url:
            return "error: no BHE URL configured (set BLOODHOUND_URL or pass url=)"
        if token_id and token_key:
            config.token_id = token_id
            config.token_key = token_key
            config.jwt = None
        client = get_client(config=config)

        if username and password and not (token_id and token_key):
            try:
                await client.login(username, password)
            except BHEAuthError as exc:
                return f"login failed: {exc}"

        # Round-trip through /api/v2/self to confirm.
        try:
            data = await client.get_json("/api/v2/self")
        except BHEAPIError as exc:
            return f"connection failed: {exc}"
        return json.dumps(
            {
                "auth_mode": client.auth_mode,
                "base_url": client.base_url,
                "self": _trim_self(data),
            },
            indent=2,
            default=str,
        )

    @tool_method(name="whoami", catch=True)
    async def whoami(self) -> str:
        """Return the requester's identity (user or collector)."""
        client = get_client()
        try:
            data = await client.get_json("/api/v2/self")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(_trim_self(data), indent=2, default=str)

    @tool_method(name="api_version", catch=True)
    async def api_version(self) -> str:
        """Return the supported BHE API version (cheap heartbeat)."""
        client = get_client()
        try:
            data = await client.get_json("/api/v2/api-version")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="list_api_tokens", catch=True)
    async def list_api_tokens(self) -> str:
        """List every HMAC API token configured on the server.

        Token *keys* are not returned by the API — only ids,
        descriptions, and ownership. Use ``create_api_token`` to
        provision a fresh credential when you need one.
        """
        client = get_client()
        try:
            data = await client.get_json("/api/v2/api-tokens")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="create_api_token", catch=True)
    async def create_api_token(
        self,
        name: t.Annotated[str, "Human-readable name for the new token"],
        user_id: t.Annotated[
            str,
            "User id the token authenticates as. If blank, defaults to "
            "the calling user's id (from /self).",
        ] = "",
    ) -> str:
        """Create a new HMAC API token.

        The response contains both ``token_id`` and ``token_key`` —
        capture the key immediately; the API will not return it again.
        """
        client = get_client()
        if not user_id:
            try:
                me = await client.get_json("/api/v2/self")
            except BHEAPIError as exc:
                return f"error: {exc}"
            user_id = (me.get("data") or {}).get("id") or me.get("id") or ""
            if not user_id:
                return "error: could not determine current user id; pass user_id="
        try:
            data = await client.post_json(
                "/api/v2/api-tokens",
                json={"user_id": user_id, "token_name": name},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="revoke_api_token", catch=True)
    async def revoke_api_token(
        self,
        token_id: t.Annotated[str, "Id of the token to revoke"],
    ) -> str:
        """Revoke an existing HMAC API token.

        Once revoked, requests signed with that token id stop
        authenticating immediately. Use ``list_api_tokens`` to
        find ids.
        """
        client = get_client()
        try:
            await client.delete_json(f"/api/v2/api-tokens/{token_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return f"revoked {token_id}"


def _trim_self(payload: t.Any) -> t.Any:
    """The /self response can be deeply nested; surface the useful fields."""
    if not isinstance(payload, dict):
        return payload
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    return {
        "id": data.get("id"),
        "email_address": data.get("email_address") or data.get("emailAddress"),
        "principal_name": data.get("principal_name") or data.get("principalName"),
        "first_name": data.get("first_name") or data.get("firstName"),
        "last_name": data.get("last_name") or data.get("lastName"),
        "roles": [
            r.get("name") if isinstance(r, dict) else r
            for r in (data.get("roles") or [])
        ],
        "is_disabled": data.get("is_disabled") or data.get("isDisabled"),
    }
