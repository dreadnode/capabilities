#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "pydantic>=2.0,<3.0",
# ]
# ///
"""Read-only Mythic C2 MCP server — query operation data without executing commands.

Credentials are read from the server's environment so they never appear in conversations.

Env vars:
    MYTHIC_SERVER_IP    (default: 127.0.0.1)
    MYTHIC_SERVER_PORT  (default: 7443)
    MYTHIC_USERNAME     (default: mythic_admin)
    MYTHIC_PASSWORD     (required unless MYTHIC_API_TOKEN set)
    MYTHIC_API_TOKEN    (alternative to username/password)
    MYTHIC_TIMEOUT      (default: -1)
"""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal, TypeAlias, TypedDict, TypeVar

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk, mythic_utilities
from mythic.mythic_classes import Mythic
from pydantic import BaseModel, Field, JsonValue, ValidationInfo, field_validator


# ── Type aliases ─────────────────────────────────────────────────────

# GraphQL variables: Hasura inputs we send are always int (IDs/limits/offsets) or str.
GqlVariables: TypeAlias = dict[str, int | str]

# Agent-populated free-form JSON (e.g. mythictree.metadata). Pydantic's JsonValue
# is a pre-defined recursive alias for valid JSON — str | int | float | bool |
# None | list[JsonValue] | dict[str, JsonValue] — and handles recursion safely.
JsonObject: TypeAlias = dict[str, JsonValue]


class MythicConfig(TypedDict):
    """Connection config loaded from environment variables."""

    server_ip: str
    server_port: int
    username: str
    password: str
    api_token: str
    timeout: int


class MeHook(TypedDict, total=False):
    """Subset of fields we consume from ``mythic_sdk.get_me()``'s meHook payload."""

    current_operation: str
    username: str


# ── Pydantic models ──────────────────────────────────────────────────


class _MythicBase(BaseModel):
    """Base model that coerces ``None`` -> a type-appropriate zero value.

    Mythic's Hasura API returns null for many optional columns regardless of
    the declared (non-null) SQL type. We swap nulls for ``""``/``0``/``False``
    on primitive string/int/bool fields so every row validates cleanly.
    """

    @field_validator("*", mode="before")
    @classmethod
    def _coerce_null(cls, v: JsonValue, info: ValidationInfo) -> JsonValue:
        if v is not None or info.field_name not in cls.model_fields:
            return v
        annotation = cls.model_fields[info.field_name].annotation
        if annotation is str:
            return ""
        if annotation is bool:
            return False
        if annotation is int:
            return 0
        return v


# ── Reference types (foreign key lookups in Hasura responses) ────────


class PayloadTypeRef(_MythicBase):
    name: str = ""


class PayloadRef(_MythicBase):
    os: str = ""
    uuid: str = ""
    description: str = ""
    payloadtype: PayloadTypeRef | None = None


class C2ProfileRef(_MythicBase):
    name: str = ""
    is_p2p: bool = False


class PayloadC2ProfileRef(_MythicBase):
    c2profile: C2ProfileRef | None = None


class PayloadDetail(_MythicBase):
    os: str = ""
    uuid: str = ""
    description: str = ""
    payloadtype: PayloadTypeRef | None = None
    payloadc2profiles: list[PayloadC2ProfileRef] = Field(default_factory=list)


class OperatorRef(_MythicBase):
    username: str = ""


class CallbackRef(_MythicBase):
    display_id: int = 0
    host: str = ""


class TaskRef(_MythicBase):
    id: int = 0
    display_id: int = 0
    command_name: str = ""
    callback: CallbackRef | None = None


# ── Entity types returned by tools ───────────────────────────────────


class _CallbackCommon(_MythicBase):
    """Fields shared between list and detail views of a callback."""

    display_id: int = 0
    host: str = ""
    user: str = ""
    ip: str = ""
    external_ip: str = ""
    os: str = ""
    architecture: str = ""
    pid: int = 0
    process_name: str = ""
    description: str = ""
    extra_info: str = ""
    sleep_info: str = ""
    active: bool = False
    last_checkin: str = ""
    init_callback: str = ""
    integrity_level: int = 0
    domain: str = ""

    @field_validator("ip", mode="before")
    @classmethod
    def _first_ip(cls, v: JsonValue) -> JsonValue:
        """Extract first IP from Mythic's JSON array string representation."""
        if not isinstance(v, str) or not v.startswith("["):
            return v
        try:
            parsed = json.loads(v)
        except json.JSONDecodeError:
            return v
        if isinstance(parsed, list) and parsed:
            return parsed[0]
        return v


class CallbackSummary(_CallbackCommon):
    payload: PayloadRef | None = None


class CallbackDetail(_CallbackCommon):
    id: int = 0
    agent_callback_id: str = ""
    operation_id: int = 0
    payload: PayloadDetail | None = None


class Task(_MythicBase):
    id: int = 0
    display_id: int = 0
    command_name: str = ""
    original_params: str = ""
    display_params: str = ""
    status: str = ""
    completed: bool = False
    timestamp: str = ""
    comment: str = ""
    operator: OperatorRef | None = None
    callback: CallbackRef | None = None


class TaskOutput(BaseModel):
    task_id: int
    total_lines: int
    offset: int
    returned_lines: int
    output: str


class Credential(_MythicBase):
    id: int = 0
    type: str = ""
    realm: str = ""
    account: str = ""
    credential_text: str = ""
    comment: str = ""
    timestamp: str = ""
    operator: OperatorRef | None = None
    task: TaskRef | None = None


class FileRow(_MythicBase):
    id: int = 0
    agent_file_id: str = ""
    filename_utf8: str = ""
    full_remote_path_utf8: str = ""
    host: str = ""
    complete: bool = False
    is_download_from_agent: bool = False
    md5: str = ""
    sha1: str = ""
    timestamp: str = ""
    comment: str = ""
    task: TaskRef | None = None


class FileContents(BaseModel):
    uuid: str
    path: str
    size_bytes: int
    type: Literal["text", "binary"]
    total_lines: int = 0
    preview: str = ""
    mime: str = ""


class Artifact(_MythicBase):
    id: int = 0
    artifact_text: str = ""
    base_artifact: str = ""
    host: str = ""
    timestamp: str = ""
    task: TaskRef | None = None


class Keylog(_MythicBase):
    id: int = 0
    keystrokes_text: str = ""
    window: str = ""
    user: str = ""
    timestamp: str = ""
    task: TaskRef | None = None


class Screenshot(_MythicBase):
    id: int = 0
    agent_file_id: str = ""
    host: str = ""
    timestamp: str = ""


class MythicTreeEntry(_MythicBase):
    """Row from the mythictree table — used for both process and file browser data.

    The ``metadata`` field is agent-defined JSON (process ID, size, permissions,
    etc.) and varies across agents. It is typed as ``JsonObject`` because its
    shape is genuinely unknown at query time.
    """

    id: int = 0
    task_id: int = 0
    timestamp: str = ""
    host: str = ""
    name_text: str = ""
    parent_path_text: str = ""
    full_path_text: str = ""
    metadata: JsonObject = Field(default_factory=dict)
    os: str = ""
    success: bool = False
    comment: str = ""
    deleted: bool = False
    can_have_children: bool = False

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: JsonValue) -> JsonValue:
        if v is None:
            return {}
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return v


class Token(_MythicBase):
    id: int = 0
    token_id: int = 0
    user: str = ""
    groups: str = ""
    privileges: str = ""
    thread_id: int = 0
    process_id: int = 0
    session_id: int = 0
    logon_sid: str = ""
    integrity_level_sid: str = ""
    restricted: bool = False
    default_dacl: str = ""
    handle: int = 0
    host: str = ""
    description: str = ""
    timestamp: str = ""
    task: TaskRef | None = None


class Status(BaseModel):
    server_ip: str
    server_port: int
    auth_method: Literal["API token", "username/password"]
    current_operation: str
    username: str


class SearchResult(BaseModel):
    tasks: list[Task] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    files: list[FileRow] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    keylogs: list[Keylog] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


# ── FastMCP setup ────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Connect to Mythic at startup; fail fast if credentials are bad."""
    await _ensure_connected()
    yield


mcp = FastMCP("mythic-readonly", lifespan=_lifespan)

TEMP_DIR = Path("/tmp/mythic-readonly")

# ── Connection state ────────────────────────────────────────────────

_client: Mythic | None = None
_config: MythicConfig | None = None

SearchType = Literal["tasks", "credentials", "files", "artifacts", "keylogs"]

_SEARCH_GQL_KEYS: dict[SearchType, str] = {
    "tasks": "task",
    "credentials": "credential",
    "files": "filemeta",
    "artifacts": "taskartifact",
    "keylogs": "keylog",
}


def _env(name: str, default: str) -> str:
    """Get env var, falling back to default if unset OR empty string."""
    val = os.environ.get(name, "")
    return val if val else default


def _default_config() -> MythicConfig:
    return MythicConfig(
        server_ip=_env("MYTHIC_SERVER_IP", "127.0.0.1"),
        server_port=int(_env("MYTHIC_SERVER_PORT", "7443")),
        username=_env("MYTHIC_USERNAME", "mythic_admin"),
        password=os.environ.get("MYTHIC_PASSWORD", ""),
        api_token=os.environ.get("MYTHIC_API_TOKEN", ""),
        timeout=int(_env("MYTHIC_TIMEOUT", "-1")),
    )


async def _ensure_connected() -> Mythic:
    global _client, _config
    if _client is not None:
        return _client
    if _config is None:
        _config = _default_config()
    if not _config["password"] and not _config["api_token"]:
        raise RuntimeError(
            "Set MYTHIC_PASSWORD or MYTHIC_API_TOKEN env var."
        )

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

    # Verify credentials actually work with a real query
    try:
        await mythic_sdk.get_me(mythic=client)
    except Exception as exc:
        raise RuntimeError(f"Mythic authentication failed: {exc}") from exc

    _client = client
    return _client


async def _gql(query: str, variables: GqlVariables | None = None) -> JsonObject:
    client = await _ensure_connected()
    result = await mythic_utilities.graphql_post(
        mythic=client, query=query, variables=variables or {}
    )
    return result if isinstance(result, dict) else {}


T = TypeVar("T", bound=_MythicBase)


def _parse_rows(model: type[T], result: JsonObject, key: str) -> list[T]:
    """Parse a GraphQL result's row list into a list of Pydantic models."""
    value = result.get(key)
    if not isinstance(value, list):
        return []
    return [model.model_validate(row) for row in value if isinstance(row, dict)]


class _Filter(TypedDict):
    """A single optional Hasura filter: predicate fragment and variable value."""

    predicate: str
    value: int | str | None


def _build_where(
    filters: dict[str, _Filter],
    always: list[str] | None = None,
) -> tuple[str, str, GqlVariables]:
    """Build dynamic Hasura where-clause fragments.

    ``filters`` maps each variable name to a ``_Filter`` — the predicate is
    included and the variable declared only when its value is not None.
    ``always`` holds predicates that have no variable (always included).

    Returns ``(where_clause, decls_fragment, variables)`` where the
    ``where_clause`` is an empty string if there are no conditions, otherwise
    ``"where: {...}"``; ``decls_fragment`` is ``""`` or starts with ``", "``.
    """
    conditions: list[str] = list(always or [])
    variables: GqlVariables = {}
    decls: list[str] = []
    for var_name, flt in filters.items():
        value = flt["value"]
        if value is None:
            continue
        conditions.append(flt["predicate"])
        variables[var_name] = value
        gql_type = "Int" if isinstance(value, int) else "String"
        decls.append(f"${var_name}: {gql_type}")
    where = f"where: {{{', '.join(conditions)}}}" if conditions else ""
    decls_fragment = ", " + ", ".join(decls) if decls else ""
    return where, decls_fragment, variables


def _decode_b64(text: str) -> str:
    """Attempt base64 decode (Poseidon encodes output as base64)."""
    if not text:
        return text
    try:
        return base64.b64decode(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return text


def _as_me_hook(raw: JsonValue) -> MeHook:
    """Narrow the untyped ``get_me()`` response into our MeHook shape."""
    if not isinstance(raw, dict):
        return {}
    hook_obj = raw.get("meHook")
    if not isinstance(hook_obj, dict):
        return {}
    hook: MeHook = {}
    op = hook_obj.get("current_operation")
    if isinstance(op, str):
        hook["current_operation"] = op
    user = hook_obj.get("username")
    if isinstance(user, str):
        hook["username"] = user
    return hook


# ── Tools ───────────────────────────────────────────────────────────


@mcp.tool
async def get_status() -> Status:
    """Check connection and return current Mythic operation info."""
    client = await _ensure_connected()
    assert _config is not None  # set by _ensure_connected
    me = await mythic_sdk.get_me(mythic=client)
    hook = _as_me_hook(me)
    return Status(
        server_ip=_config["server_ip"],
        server_port=_config["server_port"],
        auth_method="API token" if _config["api_token"] else "username/password",
        current_operation=hook.get("current_operation", "unknown"),
        username=hook.get("username", _config["username"]),
    )


# ── Callbacks ───────────────────────────────────────────────────────


@mcp.tool
async def list_callbacks(
    active_only: Annotated[bool, "Only return active callbacks"] = False,
) -> list[CallbackSummary]:
    """List Mythic callbacks (agents)."""
    client = await _ensure_connected()
    attrs = (
        "display_id,host,user,ip,external_ip,os,architecture,pid,process_name,"
        "description,extra_info,sleep_info,active,last_checkin,init_callback,integrity_level,"
        "domain,payload{os,uuid,description,payloadtype{name}}"
    )
    if active_only:
        rows = await mythic_sdk.get_all_active_callbacks(client, custom_return_attributes=attrs)
    else:
        rows = await mythic_sdk.get_all_callbacks(client, custom_return_attributes=attrs)
    callbacks = [CallbackSummary.model_validate(row) for row in rows]
    callbacks.sort(key=lambda c: c.last_checkin, reverse=True)
    return callbacks


@mcp.tool
async def get_callback(
    display_id: Annotated[int, "Callback display ID"],
) -> CallbackDetail | None:
    """Get full details for a single callback including payload and C2 profiles."""
    result = await _gql(
        """
        query CallbackDetails($display_id: Int!) {
            callback(where: {display_id: {_eq: $display_id}}) {
                id, display_id, host, user, domain, integrity_level, ip, external_ip,
                os, architecture, pid, process_name, description, extra_info, sleep_info,
                active, last_checkin, init_callback, agent_callback_id, operation_id,
                payload {
                    os, uuid, description,
                    payloadtype { name },
                    payloadc2profiles { c2profile { name, is_p2p } }
                }
            }
        }
        """,
        {"display_id": display_id},
    )
    callbacks = _parse_rows(CallbackDetail, result, "callback")
    return callbacks[0] if callbacks else None


# ── Tasks ───────────────────────────────────────────────────────────


@mcp.tool
async def list_tasks(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 20,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[Task]:
    """List executed commands (tasks), most recent first."""
    client = await _ensure_connected()
    attrs = (
        "id,display_id,command_name,original_params,display_params,"
        "status,completed,timestamp,comment,"
        "operator{username},callback{display_id,host}"
    )
    # Mythic SDK types callback_display_id as int (not Optional), so we can't
    # unify the two calls via kwargs without fighting the type checker.
    if callback_id is not None:
        rows = await mythic_sdk.get_all_tasks(
            client, custom_return_attributes=attrs, callback_display_id=callback_id
        )
    else:
        rows = await mythic_sdk.get_all_tasks(client, custom_return_attributes=attrs)
    tasks = [Task.model_validate(row) for row in rows]
    tasks.sort(key=lambda t: t.id, reverse=True)
    return tasks[offset: offset + limit]


@mcp.tool
async def get_task_output(
    display_id: Annotated[int, "Task display ID"],
    max_lines: Annotated[int | None, "Limit output to N lines"] = None,
    offset: Annotated[int, "Skip N lines before returning"] = 0,
) -> TaskOutput | None:
    """Get decoded task output with optional line paging. Returns None if the task has no output."""
    client = await _ensure_connected()
    responses = await mythic_sdk.get_all_task_and_subtask_output_by_id(
        mythic=client, task_display_id=display_id
    )
    if not responses:
        return None

    parts = [
        _decode_b64(str(text))
        for r in responses
        if (text := r.get("response_text") or r.get("response"))
    ]
    lines = "\n".join(parts).split("\n")
    stop = offset + max_lines if max_lines is not None else None
    sliced = lines[offset:stop]

    return TaskOutput(
        task_id=display_id,
        total_lines=len(lines),
        offset=offset,
        returned_lines=len(sliced),
        output="\n".join(sliced),
    )


# ── Credentials / Files / Artifacts ─────────────────────────────────


@mcp.tool
async def list_credentials(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[Credential]:
    """List discovered credentials."""
    result = await _gql(
        """
        query AllCredentials($limit: Int!, $offset: Int!) {
            credential(order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, type, realm, account, credential_text, comment, timestamp,
                operator { username },
                task { id, display_id, command_name,
                       callback { display_id, host } }
            }
        }
        """,
        {"limit": limit, "offset": offset},
    )
    return _parse_rows(Credential, result, "credential")


@mcp.tool
async def list_files(
    include_uploaded: Annotated[bool, "Include uploaded files (default: downloads only)"] = False,
    uploaded_only: Annotated[bool, "Only uploaded files"] = False,
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[FileRow]:
    """List downloaded/uploaded files."""
    client = await _ensure_connected()
    attrs = (
        "id,agent_file_id,filename_utf8,full_remote_path_utf8,host,complete,"
        "is_download_from_agent,md5,sha1,timestamp,comment,"
        "task{id,display_id,command_name,callback{display_id,host}}"
    )
    files: list[FileRow] = []
    if not uploaded_only:
        async for batch in mythic_sdk.get_all_downloaded_files(client, custom_return_attributes=attrs):
            files.extend(FileRow.model_validate(row) for row in batch)
            if len(files) >= limit:
                break
    if include_uploaded or uploaded_only:
        async for batch in mythic_sdk.get_all_uploaded_files(client, custom_return_attributes=attrs):
            files.extend(FileRow.model_validate(row) for row in batch)
            if len(files) >= limit:
                break
    return files[:limit]


@mcp.tool
async def get_file_contents(
    uuid: Annotated[str, "File UUID (agent_file_id)"],
) -> FileContents | None:
    """Download a file to /tmp/mythic-readonly/ and return a preview plus the saved path.

    Returns None if the file is empty or could not be downloaded.
    """
    client = await _ensure_connected()
    data = await mythic_sdk.download_file(mythic=client, file_uuid=uuid)
    if not data:
        return None

    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / uuid
    path.write_bytes(data)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        mime, _ = mimetypes.guess_type(str(path))
        return FileContents(
            uuid=uuid,
            path=str(path),
            size_bytes=len(data),
            type="binary",
            mime=mime or "application/octet-stream",
        )

    lines = text.split("\n")
    return FileContents(
        uuid=uuid,
        path=str(path),
        size_bytes=len(data),
        type="text",
        total_lines=len(lines),
        preview="\n".join(lines[:50]),
    )


@mcp.tool
async def list_artifacts(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[Artifact]:
    """List IOCs/artifacts generated by tasks."""
    result = await _gql(
        """
        query AllArtifacts($limit: Int!, $offset: Int!) {
            taskartifact(order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, artifact_text, base_artifact, host, timestamp,
                task { id, display_id, command_name,
                       callback { display_id, host } }
            }
        }
        """,
        {"limit": limit, "offset": offset},
    )
    return _parse_rows(Artifact, result, "taskartifact")


# ── Keylogs / Screenshots ───────────────────────────────────────────


@mcp.tool
async def list_keylogs(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[Keylog]:
    """List keylog captures."""
    where, decls, variables = _build_where({
        "callback_display_id": {
            "predicate": "task: {callback: {display_id: {_eq: $callback_display_id}}}",
            "value": callback_id,
        },
    })
    variables.update({"limit": limit, "offset": offset})
    where_clause = f"{where}, " if where else ""
    result = await _gql(
        f"""
        query ListKeylogs($limit: Int!, $offset: Int!{decls}) {{
            keylog({where_clause}order_by: {{id: desc}}, limit: $limit, offset: $offset) {{
                id, keystrokes_text, window, user, timestamp,
                task {{ id, display_id, command_name,
                       callback {{ display_id, host }} }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Keylog, result, "keylog")


@mcp.tool
async def list_screenshots(
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[Screenshot]:
    """List screenshot metadata (use get_file_contents with agent_file_id to fetch image bytes)."""
    client = await _ensure_connected()
    attrs = "id,agent_file_id,host,timestamp"
    screenshots: list[Screenshot] = []
    async for batch in mythic_sdk.get_all_screenshots(client, custom_return_attributes=attrs):
        screenshots.extend(Screenshot.model_validate(row) for row in batch)
        if len(screenshots) >= limit:
            break
    return screenshots[:limit]


# ── Processes / File Browser / Tokens ───────────────────────────────


async def _list_mythictree(
    tree_type: Literal["process", "file"],
    host: str | None,
    path: str | None,
    limit: int,
    columns: str,
) -> list[MythicTreeEntry]:
    """Shared query for the mythictree table (processes + file browser)."""
    where, decls, variables = _build_where(
        {
            "host": {"predicate": "host: {_ilike: $host}", "value": f"%{host}%" if host else None},
            "path": {
                "predicate": "full_path_text: {_ilike: $path}",
                "value": f"%{path}%" if path else None,
            },
        },
        always=[f'tree_type: {{_eq: "{tree_type}"}}'],
    )
    variables["limit"] = limit
    result = await _gql(
        f"""
        query ListMythicTree($limit: Int!{decls}) {{
            mythictree({where}, order_by: {{id: desc}}, limit: $limit) {{
                {columns}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(MythicTreeEntry, result, "mythictree")


@mcp.tool
async def list_processes(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[MythicTreeEntry]:
    """List captured process listings."""
    return await _list_mythictree(
        tree_type="process",
        host=host,
        path=None,
        limit=limit,
        columns=(
            "id, task_id, timestamp, host, name_text, parent_path_text, "
            "full_path_text, metadata, os, success"
        ),
    )


@mcp.tool
async def list_file_browser(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    path: Annotated[str | None, "Filter by path prefix (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[MythicTreeEntry]:
    """Browse captured file system data from agents."""
    return await _list_mythictree(
        tree_type="file",
        host=host,
        path=path,
        limit=limit,
        columns=(
            "id, task_id, timestamp, host, comment, success, deleted, os, "
            "can_have_children, name_text, parent_path_text, full_path_text, metadata"
        ),
    )


@mcp.tool
async def list_tokens(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[Token]:
    """List Windows token captures."""
    where, decls, variables = _build_where({
        "callback_display_id": {
            "predicate": "task: {callback: {display_id: {_eq: $callback_display_id}}}",
            "value": callback_id,
        },
    })
    variables["limit"] = limit
    where_clause = f"{where}, " if where else ""
    result = await _gql(
        f"""
        query ListTokens($limit: Int!{decls}) {{
            token({where_clause}order_by: {{id: desc}}, limit: $limit) {{
                id, token_id, user, groups, privileges, thread_id, process_id,
                session_id, logon_sid, integrity_level_sid, restricted,
                default_dacl, handle, host, description, timestamp,
                task {{ id, display_id, command_name,
                       callback {{ display_id, host }} }}
            }}
        }}
        """,
        variables,
    )
    return _parse_rows(Token, result, "token")


# ── Search ──────────────────────────────────────────────────────────

# Search dispatch: each entry has the GraphQL query, the response key, and the
# Pydantic model to parse rows into. Using separate queries (instead of one
# union) lets us gather them concurrently with asyncio.gather.
_SEARCH_QUERIES: dict[SearchType, tuple[str, type[_MythicBase]]] = {
    "tasks": (
        """
        query SearchTasks($s: String!, $l: Int!) {
            task(where: {_or: [{display_params: {_ilike: $s}}, {command_name: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                 order_by: {id: desc}, limit: $l) {
                id, display_id, command_name, display_params, status, timestamp,
                callback { display_id, host }
            }
        }
        """,
        Task,
    ),
    "credentials": (
        """
        query SearchCreds($s: String!, $l: Int!) {
            credential(where: {_or: [{account: {_ilike: $s}}, {realm: {_ilike: $s}}, {credential_text: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                       order_by: {id: desc}, limit: $l) {
                id, type, realm, account, credential_text, comment
            }
        }
        """,
        Credential,
    ),
    "files": (
        """
        query SearchFiles($s: String!, $l: Int!) {
            filemeta(where: {_or: [{filename_utf8: {_ilike: $s}}, {full_remote_path_utf8: {_ilike: $s}}]},
                     order_by: {id: desc}, limit: $l) {
                id, agent_file_id, filename_utf8, full_remote_path_utf8, host, is_download_from_agent
            }
        }
        """,
        FileRow,
    ),
    "artifacts": (
        """
        query SearchArtifacts($s: String!, $l: Int!) {
            taskartifact(where: {_or: [{artifact_text: {_ilike: $s}}, {base_artifact: {_ilike: $s}}]},
                         order_by: {id: desc}, limit: $l) {
                id, artifact_text, base_artifact, host
            }
        }
        """,
        Artifact,
    ),
    "keylogs": (
        """
        query SearchKeylogs($s: String!, $l: Int!) {
            keylog(where: {_or: [{keystrokes_text: {_ilike: $s}}, {window: {_ilike: $s}}]},
                   order_by: {id: desc}, limit: $l) {
                id, keystrokes_text, window
            }
        }
        """,
        Keylog,
    ),
}


def _valid_search_types(raw: str | None) -> set[SearchType]:
    """Parse and validate the user-supplied comma-separated type filter."""
    all_types: set[SearchType] = set(_SEARCH_GQL_KEYS)
    if raw is None:
        return all_types
    requested = {name.strip() for name in raw.split(",")}
    return {t for t in all_types if t in requested}


@mcp.tool
async def search(
    query: Annotated[str, "Search term"],
    types: Annotated[str | None, "Comma-separated types to search (tasks,credentials,files,artifacts,keylogs). Default: all"] = None,
    limit: Annotated[int, "Maximum results per type"] = 10,
) -> SearchResult:
    """Search across tasks, credentials, files, artifacts, and keylogs concurrently."""
    await _ensure_connected()
    term = f"%{query}%"
    variables: GqlVariables = {"s": term, "l": limit}

    selected = sorted(_valid_search_types(types))
    raw = await asyncio.gather(
        *(_gql(_SEARCH_QUERIES[key][0], variables) for key in selected),
        return_exceptions=True,
    )

    out = SearchResult()
    for key, r in zip(selected, raw):
        if isinstance(r, BaseException):
            out.errors[key] = str(r)
            continue
        if not isinstance(r, dict):
            continue
        _, model = _SEARCH_QUERIES[key]
        rows = _parse_rows(model, r, _SEARCH_GQL_KEYS[key])
        # Each field on SearchResult is typed for its specific model,
        # so assign via setattr with the model's known identity.
        setattr(out, key, rows)
    return out


if __name__ == "__main__":
    mcp.run(transport="stdio")
