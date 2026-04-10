#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
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
from typing import Annotated, Any

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk, mythic_utilities


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Connect to Mythic at startup; fail fast if credentials are bad."""
    await _ensure_connected()
    yield


mcp = FastMCP("mythic-readonly", lifespan=_lifespan)

TEMP_DIR = Path("/tmp/mythic-readonly")

# ── Connection state ────────────────────────────────────────────────

_client: Any | None = None
_config: dict[str, Any] = {}

_SEARCH_GQL_KEYS = {
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


def _default_config() -> dict[str, Any]:
    return {
        "server_ip": _env("MYTHIC_SERVER_IP", "127.0.0.1"),
        "server_port": int(_env("MYTHIC_SERVER_PORT", "7443")),
        "username": _env("MYTHIC_USERNAME", "mythic_admin"),
        "password": os.environ.get("MYTHIC_PASSWORD", ""),
        "api_token": os.environ.get("MYTHIC_API_TOKEN", ""),
        "timeout": int(_env("MYTHIC_TIMEOUT", "-1")),
    }


async def _ensure_connected() -> None:
    global _client, _config
    if _client is not None:
        return
    if not _config:
        _config = _default_config()
    if not _config["password"] and not _config["api_token"]:
        raise RuntimeError(
            "Set MYTHIC_PASSWORD or MYTHIC_API_TOKEN env var."
        )

    kwargs: dict[str, Any] = {
        "server_ip": _config["server_ip"],
        "server_port": _config["server_port"],
        "timeout": _config["timeout"],
    }
    if _config["api_token"]:
        kwargs["apitoken"] = _config["api_token"]
    else:
        kwargs["username"] = _config["username"]
        kwargs["password"] = _config["password"]

    try:
        _client = await mythic_sdk.login(**kwargs)
    except Exception as exc:
        _client = None
        raise RuntimeError(f"Mythic authentication failed: {exc}") from exc

    # Verify credentials actually work with a real query
    try:
        await mythic_sdk.get_me(mythic=_client)
    except Exception as exc:
        _client = None
        raise RuntimeError(f"Mythic authentication failed: {exc}") from exc


async def _gql(query: str, variables: dict | None = None) -> dict:
    await _ensure_connected()
    return await mythic_utilities.graphql_post(
        mythic=_client, query=query, variables=variables
    )


def _decode_b64(text: str) -> str:
    """Attempt base64 decode (Poseidon encodes output as base64)."""
    if not text:
        return text
    try:
        return base64.b64decode(text).decode("utf-8")
    except Exception:
        return text


def _first_ip(ip_field: str) -> str:
    """Extract first IP from Mythic's JSON array string."""
    if not ip_field:
        return ""
    if ip_field.startswith("["):
        try:
            ips = json.loads(ip_field)
            return ips[0] if ips else ip_field
        except Exception:
            pass
    return ip_field


# ── Tools ───────────────────────────────────────────────────────────


@mcp.tool
async def get_status() -> dict:
    """Check connection and return current Mythic operation info."""
    await _ensure_connected()
    me = await mythic_sdk.get_me(mythic=_client)
    hook = me.get("meHook", {}) if isinstance(me, dict) else {}
    return {
        "server_ip": _config.get("server_ip", ""),
        "server_port": _config.get("server_port", ""),
        "auth_method": "API token" if _config.get("api_token") else "username/password",
        "current_operation": hook.get("current_operation", "unknown"),
        "username": hook.get("username", _config.get("username", "")),
    }


# ── Callbacks ───────────────────────────────────────────────────────


@mcp.tool
async def list_callbacks(
    active_only: Annotated[bool, "Only return active callbacks"] = False,
) -> list[dict]:
    """List Mythic callbacks (agents)."""
    await _ensure_connected()
    attrs = (
        "display_id,host,user,ip,external_ip,os,architecture,pid,process_name,"
        "description,extra_info,sleep_info,active,last_checkin,init_callback,integrity_level,"
        "domain,payload{os,payloadtype{name},description}"
    )
    if active_only:
        cbs = await mythic_sdk.get_all_active_callbacks(_client, custom_return_attributes=attrs)
    else:
        cbs = await mythic_sdk.get_all_callbacks(_client, custom_return_attributes=attrs)
    # Normalize IP field
    for cb in cbs:
        if "ip" in cb:
            cb["ip"] = _first_ip(cb.get("ip", ""))
    return sorted(cbs, key=lambda x: x.get("last_checkin", ""), reverse=True)


@mcp.tool
async def get_callback(
    display_id: Annotated[int, "Callback display ID"],
) -> dict:
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
    callbacks = result.get("callback", []) if isinstance(result, dict) else []
    if not callbacks:
        return {"error": f"No callback found with display_id={display_id}"}
    return callbacks[0]


# ── Tasks ───────────────────────────────────────────────────────────


@mcp.tool
async def list_tasks(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 20,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List executed commands (tasks), most recent first."""
    await _ensure_connected()
    attrs = (
        "id,display_id,command_name,original_params,display_params,"
        "status,completed,timestamp,comment,"
        "operator{username},callback{display_id,host}"
    )
    tasks = await mythic_sdk.get_all_tasks(
        _client,
        custom_return_attributes=attrs,
        callback_display_id=callback_id,
    )
    tasks.sort(key=lambda x: x.get("id", 0), reverse=True)
    return tasks[offset: offset + limit]


@mcp.tool
async def get_task_output(
    display_id: Annotated[int, "Task display ID"],
    max_lines: Annotated[int | None, "Limit output to N lines"] = None,
    offset: Annotated[int, "Skip N lines before returning"] = 0,
) -> dict:
    """Get decoded task output with optional line paging."""
    await _ensure_connected()
    responses = await mythic_sdk.get_all_task_and_subtask_output_by_id(
        mythic=_client, task_display_id=display_id
    )
    if not responses:
        return {"error": f"No output for task {display_id}", "output": "", "total_lines": 0}

    parts = []
    for r in responses:
        text = r.get("response_text", r.get("response", ""))
        if text:
            parts.append(_decode_b64(str(text)))
    full = "\n".join(parts)
    lines = full.split("\n")
    total = len(lines)

    sliced = lines[offset:]
    if max_lines is not None:
        sliced = sliced[:max_lines]

    return {
        "task_id": display_id,
        "total_lines": total,
        "offset": offset,
        "returned_lines": len(sliced),
        "output": "\n".join(sliced),
    }


# ── Credentials / Files / Artifacts ─────────────────────────────────


@mcp.tool
async def list_credentials(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
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
    return result.get("credential", []) if isinstance(result, dict) else []


@mcp.tool
async def list_files(
    include_uploaded: Annotated[bool, "Include uploaded files (default: downloads only)"] = False,
    uploaded_only: Annotated[bool, "Only uploaded files"] = False,
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[dict]:
    """List downloaded/uploaded files."""
    await _ensure_connected()
    attrs = (
        "id,agent_file_id,filename_utf8,full_remote_path_utf8,host,complete,"
        "is_download_from_agent,md5,sha1,timestamp,comment,"
        "task{display_id,command_name,callback{display_id,host}}"
    )
    results: list[dict] = []
    if not uploaded_only:
        async for batch in mythic_sdk.get_all_downloaded_files(_client, custom_return_attributes=attrs):
            results.extend(batch)
            if len(results) >= limit:
                break
    if include_uploaded or uploaded_only:
        async for batch in mythic_sdk.get_all_uploaded_files(_client, custom_return_attributes=attrs):
            results.extend(batch)
            if len(results) >= limit:
                break
    return results[:limit]


@mcp.tool
async def get_file_contents(
    uuid: Annotated[str, "File UUID (agent_file_id)"],
) -> dict:
    """Download a file to /tmp/mythic-readonly/ and return a preview plus the saved path."""
    await _ensure_connected()
    data = await mythic_sdk.download_file(mythic=_client, file_uuid=uuid)
    if not data:
        return {"error": "File is empty or could not be downloaded.", "uuid": uuid}

    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / uuid
    path.write_bytes(data)

    try:
        text = data.decode("utf-8")
        lines = text.split("\n")
        return {
            "uuid": uuid,
            "path": str(path),
            "size_bytes": len(data),
            "total_lines": len(lines),
            "type": "text",
            "preview": "\n".join(lines[:50]),
        }
    except UnicodeDecodeError:
        mime, _ = mimetypes.guess_type(str(path))
        return {
            "uuid": uuid,
            "path": str(path),
            "size_bytes": len(data),
            "type": "binary",
            "mime": mime or "application/octet-stream",
        }


@mcp.tool
async def list_artifacts(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List IOCs/artifacts generated by tasks."""
    result = await _gql(
        """
        query AllArtifacts($limit: Int!, $offset: Int!) {
            taskartifact(order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, artifact_text, base_artifact, host, timestamp,
                task { display_id, command_name,
                       callback { display_id, host } }
            }
        }
        """,
        {"limit": limit, "offset": offset},
    )
    return result.get("taskartifact", []) if isinstance(result, dict) else []


# ── Keylogs / Screenshots ───────────────────────────────────────────


@mcp.tool
async def list_keylogs(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Offset for pagination"] = 0,
) -> list[dict]:
    """List keylog captures."""
    if callback_id is not None:
        query = """
        query KeylogsByCallback($callback_display_id: Int!, $limit: Int!, $offset: Int!) {
            keylog(where: {task: {callback: {display_id: {_eq: $callback_display_id}}}},
                   order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, keystrokes_text, window, user, timestamp,
                task { display_id, callback { display_id, host } }
            }
        }
        """
        variables: dict[str, Any] = {
            "callback_display_id": callback_id,
            "limit": limit,
            "offset": offset,
        }
    else:
        query = """
        query AllKeylogs($limit: Int!, $offset: Int!) {
            keylog(order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, keystrokes_text, window, user, timestamp,
                task { display_id, callback { display_id, host } }
            }
        }
        """
        variables = {"limit": limit, "offset": offset}
    result = await _gql(query, variables)
    return result.get("keylog", []) if isinstance(result, dict) else []


@mcp.tool
async def list_screenshots(
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[dict]:
    """List screenshot metadata (use get_file_contents with agent_file_id to fetch image bytes)."""
    await _ensure_connected()
    attrs = "id,agent_file_id,host,timestamp"
    results: list[dict] = []
    async for batch in mythic_sdk.get_all_screenshots(_client, custom_return_attributes=attrs):
        results.extend(batch)
        if len(results) >= limit:
            break
    return results[:limit]


# ── Processes / File Browser / Tokens ───────────────────────────────


@mcp.tool
async def list_processes(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[dict]:
    """List captured process listings."""
    if host:
        query = """
        query ProcessesByHost($host: String!, $limit: Int!) {
            mythictree(where: {host: {_ilike: $host}, tree_type: {_eq: "process"}},
                       order_by: {id: desc}, limit: $limit) {
                id, task_id, timestamp, host, name_text, parent_path_text,
                full_path_text, metadata, os, success
            }
        }
        """
        result = await _gql(query, {"host": f"%{host}%", "limit": limit})
    else:
        query = """
        query AllProcesses($limit: Int!) {
            mythictree(where: {tree_type: {_eq: "process"}},
                       order_by: {id: desc}, limit: $limit) {
                id, task_id, timestamp, host, name_text, parent_path_text,
                full_path_text, metadata, os, success
            }
        }
        """
        result = await _gql(query, {"limit": limit})
    return result.get("mythictree", []) if isinstance(result, dict) else []


@mcp.tool
async def list_file_browser(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    path: Annotated[str | None, "Filter by path prefix (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[dict]:
    """Browse captured file system data from agents."""
    conditions = ['tree_type: {_eq: "file"}']
    variables: dict[str, Any] = {"limit": limit}
    decls = ""
    if host:
        conditions.append("host: {_ilike: $host}")
        variables["host"] = f"%{host}%"
        decls += ", $host: String"
    if path:
        conditions.append("full_path_text: {_ilike: $path}")
        variables["path"] = f"%{path}%"
        decls += ", $path: String"

    where = ", ".join(conditions)
    query = f"""
    query FileBrowser($limit: Int!{decls}) {{
        mythictree(where: {{{where}}}, order_by: {{id: desc}}, limit: $limit) {{
            id, task_id, timestamp, host, comment, success, deleted,
            os, can_have_children, name_text, parent_path_text, full_path_text, metadata
        }}
    }}
    """
    result = await _gql(query, variables)
    return result.get("mythictree", []) if isinstance(result, dict) else []


@mcp.tool
async def list_tokens(
    callback_id: Annotated[int | None, "Filter by callback display ID"] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict]:
    """List Windows token captures."""
    if callback_id is not None:
        query = """
        query TokensByCallback($callback_display_id: Int!, $limit: Int!) {
            token(where: {task: {callback: {display_id: {_eq: $callback_display_id}}}},
                  order_by: {id: desc}, limit: $limit) {
                id, token_id, user, groups, privileges, thread_id, process_id,
                session_id, logon_sid, integrity_level_sid, restricted,
                default_dacl, handle, host, description, timestamp,
                task { callback { display_id, host } }
            }
        }
        """
        variables: dict[str, Any] = {"callback_display_id": callback_id, "limit": limit}
    else:
        query = """
        query AllTokens($limit: Int!) {
            token(order_by: {id: desc}, limit: $limit) {
                id, token_id, user, groups, privileges, thread_id, process_id,
                session_id, logon_sid, integrity_level_sid, restricted,
                default_dacl, handle, host, description, timestamp,
                task { callback { display_id, host } }
            }
        }
        """
        variables = {"limit": limit}
    result = await _gql(query, variables)
    return result.get("token", []) if isinstance(result, dict) else []


# ── Search ──────────────────────────────────────────────────────────


@mcp.tool
async def search(
    query: Annotated[str, "Search term"],
    types: Annotated[str | None, "Comma-separated types to search (tasks,credentials,files,artifacts,keylogs). Default: all"] = None,
    limit: Annotated[int, "Maximum results per type"] = 10,
) -> dict:
    """Search across tasks, credentials, files, artifacts, and keylogs concurrently."""
    await _ensure_connected()
    term = f"%{query}%"
    search_types = set(types.split(",")) if types else set(_SEARCH_GQL_KEYS)

    queries: dict[str, Any] = {}
    if "tasks" in search_types:
        queries["tasks"] = _gql(
            """
            query SearchTasks($s: String!, $l: Int!) {
                task(where: {_or: [{display_params: {_ilike: $s}}, {command_name: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                     order_by: {id: desc}, limit: $l) {
                    display_id, command_name, display_params, status, timestamp,
                    callback { display_id, host }
                }
            }
            """,
            {"s": term, "l": limit},
        )
    if "credentials" in search_types:
        queries["credentials"] = _gql(
            """
            query SearchCreds($s: String!, $l: Int!) {
                credential(where: {_or: [{account: {_ilike: $s}}, {realm: {_ilike: $s}}, {credential_text: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                           order_by: {id: desc}, limit: $l) {
                    id, type, realm, account, credential_text, comment
                }
            }
            """,
            {"s": term, "l": limit},
        )
    if "files" in search_types:
        queries["files"] = _gql(
            """
            query SearchFiles($s: String!, $l: Int!) {
                filemeta(where: {_or: [{filename_utf8: {_ilike: $s}}, {full_remote_path_utf8: {_ilike: $s}}]},
                         order_by: {id: desc}, limit: $l) {
                    agent_file_id, filename_utf8, full_remote_path_utf8, host, is_download_from_agent
                }
            }
            """,
            {"s": term, "l": limit},
        )
    if "artifacts" in search_types:
        queries["artifacts"] = _gql(
            """
            query SearchArtifacts($s: String!, $l: Int!) {
                taskartifact(where: {_or: [{artifact_text: {_ilike: $s}}, {base_artifact: {_ilike: $s}}]},
                             order_by: {id: desc}, limit: $l) {
                    id, artifact_text, base_artifact, host
                }
            }
            """,
            {"s": term, "l": limit},
        )
    if "keylogs" in search_types:
        queries["keylogs"] = _gql(
            """
            query SearchKeylogs($s: String!, $l: Int!) {
                keylog(where: {_or: [{keystrokes_text: {_ilike: $s}}, {window: {_ilike: $s}}]},
                       order_by: {id: desc}, limit: $l) {
                    id, keystrokes_text, window
                }
            }
            """,
            {"s": term, "l": limit},
        )

    keys = list(queries.keys())
    raw = await asyncio.gather(*queries.values(), return_exceptions=True)
    results: dict[str, Any] = {}
    for key, r in zip(keys, raw):
        if isinstance(r, BaseException):
            results[key] = [{"error": str(r)}]
        elif isinstance(r, dict):
            results[key] = r.get(_SEARCH_GQL_KEYS.get(key, key), [])
        else:
            results[key] = []
    return results


if __name__ == "__main__":
    mcp.run(transport="stdio")
