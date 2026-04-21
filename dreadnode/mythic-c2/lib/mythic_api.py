"""Shared helpers for the Mythic MCP tool layer.

Consumed by ``observation.py`` (observation tools) and ``apollo.py`` (tasking
tools, registered only when the ``apollo`` capability flag is on).

Nothing here is a tool — this module is pure plumbing: connection state,
GraphQL wrapper, output shapers, truncation. Tools live in the sibling files
and share one authenticated client through :func:`ensure_connected`.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, TypedDict

from mythic import mythic as mythic_sdk, mythic_utilities
from mythic.mythic_classes import Mythic


def _patch_mythic_for_gql4() -> None:
    """mythic==0.2.10 was written for gql 3.x, where ``gql(query)`` returned a
    ``graphql.DocumentNode``. In gql 4.0 it returns a ``GraphQLRequest`` wrapper
    around the DocumentNode, and the SDK's ``get_operation_name(query_data)``
    raises ``AttributeError: 'GraphQLRequest' object has no attribute 'definitions'``
    on any Mythic call.

    We can't pin the worker back to gql 3.5.3 without fighting dreadnode>=2.0's
    websockets>=14 requirement (see the ``fix(mythic-c2): drop redundant gql dep``
    commit). This shim is idempotent on both gql versions: if ``graphql_data`` is
    already a DocumentNode we use it directly; if it's a GraphQLRequest we unwrap
    to ``.document``.

    Remove once ``mythic`` ships a release that supports gql 4.0 natively.
    """

    async def _get_operation_name(graphql_data: Any) -> str:
        doc = getattr(graphql_data, "document", graphql_data)
        definitions = getattr(doc, "definitions", None) or []
        if definitions and getattr(definitions[0], "name", None):
            return definitions[0].name.value
        return ""

    mythic_utilities.get_operation_name = _get_operation_name


_patch_mythic_for_gql4()


MAX_OUTPUT_CHARS = 1_048_576
"""Cap on Apollo command output — head+tail trimmed past this."""


class MythicConfig(TypedDict):
    server_ip: str
    server_port: int
    username: str
    password: str
    api_token: str
    timeout: int


def _env(name: str, default: str) -> str:
    val = os.environ.get(name, "")
    return val if val else default


def default_config() -> MythicConfig:
    return MythicConfig(
        server_ip=_env("MYTHIC_SERVER_IP", "127.0.0.1"),
        server_port=int(_env("MYTHIC_SERVER_PORT", "7443")),
        username=_env("MYTHIC_USERNAME", "mythic_admin"),
        password=os.environ.get("MYTHIC_PASSWORD", ""),
        api_token=os.environ.get("MYTHIC_API_TOKEN", ""),
        timeout=int(_env("MYTHIC_TIMEOUT", "-1")),
    )


_client: Mythic | None = None
_config: MythicConfig | None = None


async def ensure_connected() -> Mythic:
    """Return the authenticated Mythic client, logging in on first call.

    Subsequent calls return the cached singleton. Raises ``RuntimeError`` if
    credentials are missing or authentication fails — FastMCP relays the
    exception to the caller as a tool-call error.
    """
    global _client, _config
    if _client is not None:
        return _client
    if _config is None:
        _config = default_config()
    if not _config["password"] and not _config["api_token"]:
        raise RuntimeError("Set MYTHIC_PASSWORD or MYTHIC_API_TOKEN env var.")

    try:
        if _config["api_token"]:
            client = await mythic_sdk.login(
                server_ip=_config["server_ip"],
                server_port=_config["server_port"],
                apitoken=_config["api_token"],
                timeout=_config["timeout"],
            )
        else:
            client = await mythic_sdk.login(
                server_ip=_config["server_ip"],
                server_port=_config["server_port"],
                username=_config["username"],
                password=_config["password"],
                timeout=_config["timeout"],
            )
    except Exception as exc:
        raise RuntimeError(f"Mythic authentication failed: {exc}") from exc

    try:
        await mythic_sdk.get_me(mythic=client)
    except Exception as exc:
        raise RuntimeError(f"Mythic authentication failed: {exc}") from exc

    _client = client
    return _client


def current_config() -> MythicConfig:
    """Return the active config, populating defaults if unset."""
    global _config
    if _config is None:
        _config = default_config()
    return _config


def reset_connection() -> None:
    """Drop the cached client — used by tests to force reconnect."""
    global _client, _config
    _client = None
    _config = None


async def gql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    """Post a GraphQL query against the authenticated Mythic client."""
    client = await ensure_connected()
    result = await mythic_utilities.graphql_post(
        mythic=client, query=query, variables=variables or {}
    )
    return result if isinstance(result, dict) else {}


class Filter(TypedDict):
    predicate: str
    value: bool | int | str | None


def build_where(
    filters: dict[str, Filter],
    always: list[str] | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Build a Hasura ``where:`` clause + variable declarations from optional filters.

    Returns ``(where_fragment, decls_fragment, variables)``. Filters whose
    value is ``None`` are skipped so callers can forward optional tool args
    without branching.
    """
    conditions: list[str] = list(always or [])
    variables: dict[str, Any] = {}
    decls: list[str] = []
    for var_name, flt in filters.items():
        value = flt["value"]
        if value is None:
            continue
        conditions.append(flt["predicate"])
        variables[var_name] = value
        if isinstance(value, bool):
            gql_type = "Boolean"
        elif isinstance(value, int):
            gql_type = "Int"
        else:
            gql_type = "String"
        decls.append(f"${var_name}: {gql_type}")
    where = f"where: {{{', '.join(conditions)}}}" if conditions else ""
    decls_fragment = ", " + ", ".join(decls) if decls else ""
    return where, decls_fragment, variables


def _is_empty(v: Any) -> bool:
    """True for None / ""/ [] / {}, keeping meaningful falsy values like 0 and False."""
    return v is None or v == "" or v == [] or v == {}


def clean(value: Any) -> Any:
    """Recursively drop None/""/[]/{} from dicts and lists.

    Preserves ``0`` and ``False`` — those are real values. The goal is to
    strip Hasura-null debris the SDK leaves in rows so tool returns are
    token-efficient and readable.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            cleaned = clean(v)
            if _is_empty(cleaned):
                continue
            out[k] = cleaned
        return out
    if isinstance(value, list):
        out_list: list[Any] = []
        for item in value:
            cleaned = clean(item)
            if _is_empty(cleaned):
                continue
            out_list.append(cleaned)
        return out_list
    return value


def first_ip(raw: Any) -> Any:
    """Mythic stores callback ``ip`` as a JSON-encoded list string; unwrap it."""
    if not isinstance(raw, str) or not raw.startswith("["):
        return raw
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(parsed, list) and parsed:
        return parsed[0]
    return raw


def parse_metadata(raw: Any) -> dict[str, Any]:
    """Decode a ``mythictree.metadata`` JSON-encoded-string field."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def decode_b64(text: str) -> str:
    """Best-effort base64 decode; return the original string if not valid b64."""
    if not text:
        return text
    try:
        return base64.b64decode(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return text


def parse_me_hook(raw: Any) -> dict[str, str]:
    """Extract ``current_operation`` + ``username`` from a ``get_me()`` response."""
    if not isinstance(raw, dict):
        return {}
    hook = raw.get("meHook")
    if not isinstance(hook, dict):
        return {}
    out: dict[str, str] = {}
    if isinstance(hook.get("current_operation"), str):
        out["current_operation"] = hook["current_operation"]
    if isinstance(hook.get("username"), str):
        out["username"] = hook["username"]
    return out


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Head+tail truncation for long Apollo command output."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


def normalize_callback(row: dict[str, Any]) -> dict[str, Any]:
    """Apply row-specific tweaks (unwrap IP) and drop empties."""
    if "ip" in row:
        row = {**row, "ip": first_ip(row["ip"])}
    return clean(row)


def normalize_tree_entry(row: dict[str, Any]) -> dict[str, Any]:
    """Decode the metadata blob on a ``mythictree`` row and drop empties."""
    if "metadata" in row:
        row = {**row, "metadata": parse_metadata(row["metadata"])}
    return clean(row)
