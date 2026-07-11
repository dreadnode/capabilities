"""AgentMail integration — real email inboxes for agents via the AgentMail API.

AgentMail (https://agentmail.to) gives agents programmatic email inboxes:
create inboxes, send and receive messages, and read threads over a REST API.

Authentication uses a single API key. Provide it either as the
``AGENTMAIL_API_KEY`` environment variable (exported in the shell or loaded
from a ``.env`` file) or pass ``api_key`` explicitly to any tool call. The
key is never persisted by this toolset.

API reference: https://docs.agentmail.to/api-reference
"""

from __future__ import annotations

import json
import os
from typing import Annotated, Any

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

_DEFAULT_BASE_URL = "https://api.agentmail.to/v0"
_ENV_API_KEY = "AGENTMAIL_API_KEY"
_ENV_BASE_URL = "AGENTMAIL_BASE_URL"


def _pretty(data: Any) -> str:
    """Serialize a JSON-compatible value for display."""
    return json.dumps(data, indent=2, ensure_ascii=False)


class AgentMail(Toolset):
    """Email inboxes for agents via the AgentMail API.

    Create inboxes, send and reply to messages, and read inbox contents.
    Requires an AgentMail API key, sourced from the ``AGENTMAIL_API_KEY``
    environment variable or passed per call.
    """

    _http: httpx.AsyncClient | None = PrivateAttr(default=None)

    def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            base_url = os.environ.get(_ENV_BASE_URL, _DEFAULT_BASE_URL)
            self._http = httpx.AsyncClient(
                base_url=base_url,
                timeout=30,
                follow_redirects=True,
            )
        return self._http

    @staticmethod
    def _resolve_key(api_key: str) -> str | None:
        return api_key or os.environ.get(_ENV_API_KEY)

    async def _request(
        self,
        method: str,
        path: str,
        api_key: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> str:
        key = self._resolve_key(api_key)
        if not key:
            return (
                f"Error: No API key. Set the {_ENV_API_KEY} environment variable "
                "or pass api_key."
            )

        clean_params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        try:
            resp = await self._client().request(
                method,
                path,
                params=clean_params or None,
                json=json_body,
                headers={"Authorization": f"Bearer {key}"},
            )
        except Exception as exc:  # noqa: BLE001 — surfaced to the model
            return f"Error: Request failed: {exc}"

        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text

        if resp.status_code >= 400:
            return f"Error: HTTP {resp.status_code}: {_pretty(payload)}"

        return _pretty(payload)

    # ── Inboxes ──────────────────────────────────────────────────────

    @tool_method(name="agentmail_list_inboxes", catch=True)
    async def list_inboxes(
        self,
        limit: Annotated[int, "Maximum number of inboxes to return."] = 20,
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """List the email inboxes available to the API key, newest first."""
        return await self._request("GET", "/inboxes", api_key, params={"limit": limit})

    @tool_method(name="agentmail_create_inbox", catch=True)
    async def create_inbox(
        self,
        username: Annotated[
            str, "Optional local part for the address. Empty for a random one."
        ] = "",
        domain: Annotated[
            str, "Optional domain. Empty uses the default AgentMail domain."
        ] = "",
        display_name: Annotated[str, "Optional display name for outgoing mail."] = "",
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """Create a new email inbox and return its id and address."""
        body = {
            k: v
            for k, v in {
                "username": username,
                "domain": domain,
                "display_name": display_name,
            }.items()
            if v
        }
        return await self._request("POST", "/inboxes", api_key, json_body=body)

    # ── Messages ─────────────────────────────────────────────────────

    @tool_method(name="agentmail_list_messages", catch=True)
    async def list_messages(
        self,
        inbox_id: Annotated[str, "Inbox id or address to read from."],
        limit: Annotated[int, "Maximum number of messages to return."] = 20,
        labels: Annotated[
            str, "Comma-separated labels to filter by. Empty for all."
        ] = "",
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """List messages in an inbox, most recent first."""
        params: dict[str, Any] = {"limit": limit}
        if labels:
            params["labels"] = [x.strip() for x in labels.split(",") if x.strip()]
        return await self._request(
            "GET", f"/inboxes/{inbox_id}/messages", api_key, params=params
        )

    @tool_method(name="agentmail_get_message", catch=True)
    async def get_message(
        self,
        inbox_id: Annotated[str, "Inbox id or address the message belongs to."],
        message_id: Annotated[str, "Id of the message to retrieve."],
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """Retrieve a single message, including its body and headers."""
        return await self._request(
            "GET", f"/inboxes/{inbox_id}/messages/{message_id}", api_key
        )

    @tool_method(name="agentmail_send_message", catch=True)
    async def send_message(
        self,
        inbox_id: Annotated[str, "Inbox id or address to send from."],
        to: Annotated[str, "Recipient address(es), comma-separated."],
        subject: Annotated[str, "Message subject."],
        text: Annotated[str, "Plain-text body."] = "",
        html: Annotated[str, "Optional HTML body."] = "",
        cc: Annotated[str, "Optional CC address(es), comma-separated."] = "",
        bcc: Annotated[str, "Optional BCC address(es), comma-separated."] = "",
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """Send an email from an inbox."""
        body: dict[str, Any] = {
            "to": [x.strip() for x in to.split(",") if x.strip()],
            "subject": subject,
        }
        if text:
            body["text"] = text
        if html:
            body["html"] = html
        if cc:
            body["cc"] = [x.strip() for x in cc.split(",") if x.strip()]
        if bcc:
            body["bcc"] = [x.strip() for x in bcc.split(",") if x.strip()]
        return await self._request(
            "POST", f"/inboxes/{inbox_id}/messages/send", api_key, json_body=body
        )

    @tool_method(name="agentmail_reply_message", catch=True)
    async def reply_message(
        self,
        inbox_id: Annotated[str, "Inbox id or address to reply from."],
        message_id: Annotated[str, "Id of the message to reply to."],
        text: Annotated[str, "Plain-text reply body."] = "",
        html: Annotated[str, "Optional HTML reply body."] = "",
        api_key: Annotated[
            str, "AgentMail API key. Falls back to AGENTMAIL_API_KEY env var."
        ] = "",
    ) -> str:
        """Reply to a message, keeping it in the same thread."""
        body: dict[str, Any] = {}
        if text:
            body["text"] = text
        if html:
            body["html"] = html
        return await self._request(
            "POST",
            f"/inboxes/{inbox_id}/messages/{message_id}/reply",
            api_key,
            json_body=body,
        )
