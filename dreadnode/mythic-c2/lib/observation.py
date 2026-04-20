"""Always-on read-only observation tools for the Mythic MCP server.

Tools are plain async functions; ``register(mcp)`` attaches them to a
FastMCP instance (``mcp_server.py``'s). Apollo tasking lives in
``apollo.py`` and registers onto the same instance only when the
``apollo`` capability flag is on.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk

from .mythic_api import (
    build_where,
    clean,
    current_config,
    decode_b64,
    ensure_connected,
    gql,
    normalize_callback,
    normalize_tree_entry,
    parse_me_hook,
)


# ── Connection status ───────────────────────────────────────────────


async def get_status() -> dict[str, Any]:
    """Verify the Mythic connection and report orientation facts.

    Forces the auth handshake so any credential problem surfaces before the
    agent spends work on real queries, then returns the operation + operator
    context the agent needs to orient itself.

    Returns:
        Dict with ``current_operation``, ``username``, ``apollo`` (True when
        Apollo tasking tools are registered alongside the observation surface).
    """
    client = await ensure_connected()
    cfg = current_config()
    me = await mythic_sdk.get_me(mythic=client)
    hook = parse_me_hook(me)
    return {
        "current_operation": hook.get("current_operation", "unknown"),
        "username": hook.get("username", cfg["username"]),
        "apollo": os.environ.get("CAPABILITY_FLAG__MYTHIC_C2__APOLLO", "0") == "1",
    }


# ── Callbacks ───────────────────────────────────────────────────────


async def list_callbacks(
    active_only: Annotated[
        bool, "Drop callbacks Mythic has marked inactive (default True)"
    ] = True,
    host: Annotated[
        str | None, "Substring filter on hostname (case-insensitive)"
    ] = None,
    user: Annotated[str | None, "Substring filter on user (case-insensitive)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[dict[str, Any]]:
    """List Mythic callbacks (agents), newest check-in first.

    Args:
        active_only: Drop callbacks Mythic has marked inactive. Pass False
            to include dead callbacks in the result.
        host: Substring filter on the callback's hostname.
        user: Substring filter on the callback's user.
        limit: Max results.

    Returns:
        List of callback dicts with ``display_id``, ``host``, ``user``,
        ``ip``, ``os``, ``integrity_level``, ``active``, ``last_checkin``,
        and nested ``payload`` where set. Empty fields are omitted.
    """
    always = ["active: {_eq: true}"] if active_only else []
    where, decls, variables = build_where(
        {
            "host": {
                "predicate": "host: {_ilike: $host}",
                "value": f"%{host}%" if host else None,
            },
            "user": {
                "predicate": "user: {_ilike: $user}",
                "value": f"%{user}%" if user else None,
            },
        },
        always=always,
    )
    variables["limit"] = limit
    where_clause = f"{where}, " if where else ""
    result = await gql(
        f"""
        query ListCallbacks($limit: Int!{decls}) {{
            callback({where_clause}order_by: {{last_checkin: desc}}, limit: $limit) {{
                display_id, host, user, domain, integrity_level, ip, external_ip,
                os, architecture, pid, process_name, description, extra_info, sleep_info,
                active, last_checkin, init_callback,
                payload {{ os, uuid, description, payloadtype {{ name }} }}
            }}
        }}
        """,
        variables,
    )
    rows = result.get("callback") or []
    return [normalize_callback(row) for row in rows]


async def get_callback(
    callback_display_id: Annotated[int, "Callback display ID"],
) -> dict[str, Any] | None:
    """Get full details for a single callback including payload and C2 profiles.

    Args:
        callback_display_id: The number shown in Mythic's UI for this callback.

    Returns:
        Callback dict with nested ``payload`` (including ``payloadtype`` and
        the list of ``payloadc2profiles``). ``None`` if the callback does not
        exist. Empty fields are omitted.
    """
    result = await gql(
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
        {"display_id": callback_display_id},
    )
    rows = result.get("callback") or []
    if not rows:
        return None
    return normalize_callback(rows[0])


# ── Tasks ───────────────────────────────────────────────────────────


_TASK_ATTRS = (
    "id,display_id,command_name,original_params,display_params,"
    "status,completed,timestamp,comment,"
    "operator{username},callback{display_id,host}"
)


async def list_tasks(
    callback_display_id: Annotated[
        int | None, "Filter to one callback by its display ID"
    ] = None,
    limit: Annotated[int, "Maximum results to return"] = 20,
    offset: Annotated[int, "Skip N results before returning (for pagination)"] = 0,
) -> list[dict[str, Any]]:
    """List executed commands (tasks), most recent first.

    Args:
        callback_display_id: Scope to one callback's tasks.
        limit: Max results after offset.
        offset: Skip before slicing — pair with ``limit`` to page.

    Returns:
        List of task dicts with ``display_id``, ``command_name``, ``status``,
        ``completed``, ``timestamp``, ``comment``, nested ``operator`` and
        ``callback`` where set. Empty fields omitted.
    """
    client = await ensure_connected()
    if callback_display_id is not None:
        rows = await mythic_sdk.get_all_tasks(
            client,
            custom_return_attributes=_TASK_ATTRS,
            callback_display_id=callback_display_id,
        )
    else:
        rows = await mythic_sdk.get_all_tasks(
            client, custom_return_attributes=_TASK_ATTRS
        )
    tasks = [clean(row) for row in rows]
    tasks.sort(key=lambda t: t.get("id", 0), reverse=True)
    return tasks[offset : offset + limit]


async def get_task(
    task_display_id: Annotated[int, "Task display ID"],
) -> dict[str, Any] | None:
    """Look up a single task by display ID without pulling its output.

    Cheap metadata lookup — use when you need to know which command a task
    ran or which callback it belongs to, before deciding whether to pull
    the full output via ``get_task_output``.

    Args:
        task_display_id: The number shown in Mythic's UI for this task.

    Returns:
        Task dict, or ``None`` if the task does not exist.
    """
    result = await gql(
        """
        query TaskDetail($display_id: Int!) {
            task(where: {display_id: {_eq: $display_id}}) {
                id, display_id, command_name, original_params, display_params,
                status, completed, timestamp, comment,
                operator { username },
                callback { display_id, host }
            }
        }
        """,
        {"display_id": task_display_id},
    )
    rows = result.get("task") or []
    if not rows:
        return None
    return clean(rows[0])


async def get_task_output(
    task_display_id: Annotated[int, "Task display ID"],
    max_lines: Annotated[int | None, "Return at most N lines"] = None,
    offset: Annotated[int, "Skip N lines before returning"] = 0,
) -> dict[str, Any] | None:
    """Get decoded task output with optional line paging.

    Output chunks are base64-decoded and concatenated in the order Mythic
    stored them, then split into lines so you can page through very large
    outputs without pulling it all.

    Args:
        task_display_id: The task whose output you want.
        max_lines: Cap on returned lines.
        offset: Skip N lines before ``max_lines`` applies.

    Returns:
        Dict with ``task_id``, ``total_lines``, ``offset``, ``returned_lines``,
        ``output``. ``None`` if the task has no output.
    """
    client = await ensure_connected()
    responses = await mythic_sdk.get_all_task_and_subtask_output_by_id(
        mythic=client, task_display_id=task_display_id
    )
    if not responses:
        return None

    parts = [
        decode_b64(str(text))
        for r in responses
        if (text := r.get("response_text") or r.get("response"))
    ]
    lines = "\n".join(parts).split("\n")
    stop = offset + max_lines if max_lines is not None else None
    sliced = lines[offset:stop]

    return {
        "task_id": task_display_id,
        "total_lines": len(lines),
        "offset": offset,
        "returned_lines": len(sliced),
        "output": "\n".join(sliced),
    }


async def get_recent_callback_activity(
    callback_display_id: Annotated[int, "Callback display ID"],
    limit: Annotated[int, "Maximum recent tasks to return"] = 10,
    preview_chars: Annotated[int, "Max characters of output preview per task"] = 2_000,
) -> dict[str, Any]:
    """Return the most recent tasks for a callback with truncated output previews.

    The primary situational-awareness tool: one call is usually enough to
    describe what an operator has been doing on a callback. Previews are
    head+tail-truncated; call ``get_task_output`` for a full body when you
    need it.

    Args:
        callback_display_id: The callback to summarize.
        limit: Max recent tasks.
        preview_chars: Cap on each task's output preview.

    Returns:
        Dict with ``callback_id``, ``count``, and ``activity`` — a list of
        ``{task, output_length, output_preview}`` entries.
    """
    tasks = await list_tasks(callback_display_id=callback_display_id, limit=limit)
    activity: list[dict[str, Any]] = []
    for task in tasks:
        display_id = task.get("display_id")
        if not isinstance(display_id, int):
            continue
        output = await get_task_output(task_display_id=display_id)
        body = output["output"] if output else ""
        if len(body) <= preview_chars:
            preview = body
        else:
            half = preview_chars // 2
            preview = (
                body[:half]
                + f"\n...[truncated {len(body) - preview_chars} chars]...\n"
                + body[-half:]
            )
        activity.append(
            {
                "task": task,
                "output_length": len(body),
                "output_preview": preview,
            }
        )
    return {
        "callback_id": callback_display_id,
        "count": len(activity),
        "activity": activity,
    }


async def get_operation_summary() -> dict[str, Any]:
    """Operation-wide rollup: callback counts, top commands, operators, hosts.

    Useful as the opening move on broad "what's happening right now" questions.

    Returns:
        Dict with ``callbacks`` (total/active/inactive/hosts), ``tasks``
        (total + top 10 commands by count), ``operators`` (sorted usernames).
    """
    callbacks = await list_callbacks(active_only=False)
    active = [cb for cb in callbacks if cb.get("active")]
    tasks = await list_tasks(limit=500)
    command_counts: dict[str, int] = {}
    operators: set[str] = set()
    for t in tasks:
        command = t.get("command_name")
        if isinstance(command, str) and command:
            command_counts[command] = command_counts.get(command, 0) + 1
        operator = t.get("operator")
        if isinstance(operator, dict):
            username = operator.get("username")
            if isinstance(username, str) and username:
                operators.add(username)
    top = sorted(command_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    hosts = sorted({cb.get("host", "") for cb in callbacks if cb.get("host")})
    return {
        "callbacks": {
            "total": len(callbacks),
            "active": len(active),
            "inactive": len(callbacks) - len(active),
            "hosts": hosts,
        },
        "tasks": {
            "total": len(tasks),
            "top_commands": [{"command": name, "count": count} for name, count in top],
        },
        "operators": sorted(operators),
    }


# ── Credentials / Files / Artifacts ─────────────────────────────────


async def list_credentials(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Skip N results before returning"] = 0,
) -> list[dict[str, Any]]:
    """List discovered credentials, newest first.

    Args:
        limit: Max results after offset.
        offset: Skip before slicing — pair with ``limit`` to page.

    Returns:
        List of credential dicts with ``id``, ``type``, ``realm``,
        ``account``, ``credential_text``, ``comment``, ``timestamp``, and
        nested ``operator`` / ``task`` where set.
    """
    result = await gql(
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
    rows = result.get("credential") or []
    return [clean(row) for row in rows]


_FILE_ATTRS = (
    "id,agent_file_id,filename_utf8,full_remote_path_utf8,host,complete,"
    "is_download_from_agent,md5,sha1,timestamp,comment,"
    "task{id,display_id,command_name,callback{display_id,host}}"
)


FileScope = Literal["downloads", "uploads", "both"]


async def list_files(
    scope: Annotated[
        FileScope,
        "Which side to list: 'downloads' (agent → Mythic), 'uploads' (operator → Mythic), or 'both'",
    ] = "downloads",
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[dict[str, Any]]:
    """List files downloaded from agents or uploaded to Mythic, newest first.

    Args:
        scope: ``downloads`` for agent-exfiltrated files (the default),
            ``uploads`` for operator uploads staged on Mythic, ``both`` to
            merge the two.
        limit: Max results combined across sources.

    Returns:
        List of file dicts with ``agent_file_id``, ``filename_utf8``, ``host``,
        ``complete``, ``is_download_from_agent``, ``md5``, ``sha1``,
        ``timestamp``, nested ``task`` where set.
    """
    client = await ensure_connected()
    files: list[dict[str, Any]] = []
    if scope in ("downloads", "both"):
        async for batch in mythic_sdk.get_all_downloaded_files(
            client, custom_return_attributes=_FILE_ATTRS
        ):
            files.extend(clean(row) for row in batch)
            if len(files) >= limit:
                break
    if scope in ("uploads", "both"):
        async for batch in mythic_sdk.get_all_uploaded_files(
            client, custom_return_attributes=_FILE_ATTRS
        ):
            files.extend(clean(row) for row in batch)
            if len(files) >= limit:
                break
    return files[:limit]


async def list_payloads(
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict[str, Any]]:
    """List payload artifacts Mythic has built, newest first.

    Returns:
        List of file dicts with ``agent_file_id``, ``filename_utf8``, ``md5``,
        ``sha1``, ``timestamp``, and ``is_payload=True``.
    """
    result = await gql(
        """
        query Payloads($limit: Int!) {
            filemeta(where: {is_payload: {_eq: true}}, order_by: {id: desc}, limit: $limit) {
                id, agent_file_id, filename_utf8, full_remote_path_utf8, host, complete,
                is_download_from_agent, md5, sha1, timestamp, comment,
                task { id, display_id, command_name,
                       callback { display_id, host } }
            }
        }
        """,
        {"limit": limit},
    )
    rows = result.get("filemeta") or []
    return [{**clean(row), "is_payload": True} for row in rows]


_BLOODHOUND_HINTS = ("bloodhound", "sharphound", "azurehound", "bh_data", "bh-data")


async def find_bloodhound_data(
    callback_display_id: Annotated[
        int | None, "Optional callback display ID to scope to"
    ] = None,
    limit: Annotated[int, "Maximum matches to return"] = 25,
) -> dict[str, Any]:
    """Scan agent-downloaded files for likely BloodHound / SharpHound / AzureHound output.

    Matches by substring in filename and comment (bloodhound, sharphound,
    azurehound, bh_data, bh-data — case-insensitive). Call
    ``get_file_contents`` on a match to pull the archive.

    Args:
        callback_display_id: Only match files downloaded by this callback.
        limit: Max matches.

    Returns:
        ``{count, matches}`` — matches are file dicts in the same shape as
        ``list_files``.
    """
    scoped = await list_files(limit=500)
    matches: list[dict[str, Any]] = []
    for f in scoped:
        if not f.get("is_download_from_agent"):
            continue
        if callback_display_id is not None:
            task = f.get("task") or {}
            cb = task.get("callback") if isinstance(task, dict) else None
            if not isinstance(cb, dict) or cb.get("display_id") != callback_display_id:
                continue
        name = (f.get("filename_utf8") or "").lower()
        comment = (f.get("comment") or "").lower()
        if any(hint in name or hint in comment for hint in _BLOODHOUND_HINTS):
            matches.append(f)
        if len(matches) >= limit:
            break
    return {"count": len(matches), "matches": matches}


async def get_file_contents(
    agent_file_id: Annotated[str, "File UUID from list_files / find_bloodhound_data"],
    as_text: Annotated[
        bool, "When True, decode as UTF-8; otherwise return base64-encoded bytes"
    ] = True,
    max_bytes: Annotated[
        int | None,
        "Cap on bytes returned in ``content`` (size/hashes reflect the full file)",
    ] = None,
) -> dict[str, Any] | None:
    """Download a file by its Mythic ``agent_file_id`` and return the contents.

    When ``as_text`` is True and the bytes decode as UTF-8, returns text with
    ``encoding="utf-8"``. On decode failure, or when ``as_text`` is False,
    returns base64-encoded bytes with ``encoding="base64"`` so an agent can
    still hash or forward it. ``size_bytes``, ``md5``, and ``sha256`` always
    reflect the full file even when ``content`` is truncated.

    Args:
        agent_file_id: The opaque UUID returned by ``list_files`` and friends.
        as_text: Try UTF-8 decoding first.
        max_bytes: Truncate ``content`` to this many bytes.

    Returns:
        Dict with ``agent_file_id``, ``size_bytes``, ``returned_bytes``,
        ``truncated``, ``md5``, ``sha256``, ``encoding``, ``content``.
        ``None`` if the file is missing or empty on the server.
    """
    client = await ensure_connected()
    data = await mythic_sdk.download_file(mythic=client, file_uuid=agent_file_id)
    if not data:
        return None

    size = len(data)
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    body = data if max_bytes is None else data[:max_bytes]
    truncated = max_bytes is not None and size > max_bytes

    if as_text:
        try:
            content = body.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(body).decode("ascii")
            encoding = "base64"
    else:
        content = base64.b64encode(body).decode("ascii")
        encoding = "base64"

    return {
        "agent_file_id": agent_file_id,
        "size_bytes": size,
        "returned_bytes": len(body),
        "truncated": truncated,
        "md5": md5,
        "sha256": sha256,
        "encoding": encoding,
        "content": content,
    }


async def list_artifacts(
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Skip N results before returning"] = 0,
) -> list[dict[str, Any]]:
    """List IOCs/artifacts generated by tasks, newest first.

    Returns:
        List of artifact dicts with ``id``, ``artifact_text``,
        ``base_artifact``, ``host``, ``timestamp``, nested ``task``.
    """
    result = await gql(
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
    rows = result.get("taskartifact") or []
    return [clean(row) for row in rows]


# ── Keylogs / Screenshots ───────────────────────────────────────────


async def list_keylogs(
    callback_display_id: Annotated[
        int | None, "Filter to one callback by its display ID"
    ] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
    offset: Annotated[int, "Skip N results before returning"] = 0,
) -> list[dict[str, Any]]:
    """List keylog captures, newest first.

    Returns:
        List of keylog dicts with ``id``, ``keystrokes_text``, ``window``,
        ``user``, ``timestamp``, nested ``task``.
    """
    where, decls, variables = build_where(
        {
            "callback_display_id": {
                "predicate": "task: {callback: {display_id: {_eq: $callback_display_id}}}",
                "value": callback_display_id,
            },
        }
    )
    variables.update({"limit": limit, "offset": offset})
    where_clause = f"{where}, " if where else ""
    result = await gql(
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
    rows = result.get("keylog") or []
    return [clean(row) for row in rows]


async def list_screenshots(
    limit: Annotated[int, "Maximum results to return"] = 20,
) -> list[dict[str, Any]]:
    """List screenshot metadata, newest first.

    Call ``get_file_contents(agent_file_id, as_text=False)`` to fetch the
    actual image bytes.

    Returns:
        List of dicts with ``id``, ``agent_file_id``, ``host``, ``timestamp``.
    """
    client = await ensure_connected()
    attrs = "id,agent_file_id,host,timestamp"
    screenshots: list[dict[str, Any]] = []
    async for batch in mythic_sdk.get_all_screenshots(
        client, custom_return_attributes=attrs
    ):
        screenshots.extend(clean(row) for row in batch)
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
) -> list[dict[str, Any]]:
    where, decls, variables = build_where(
        {
            "host": {
                "predicate": "host: {_ilike: $host}",
                "value": f"%{host}%" if host else None,
            },
            "path": {
                "predicate": "full_path_text: {_ilike: $path}",
                "value": f"%{path}%" if path else None,
            },
        },
        always=[f'tree_type: {{_eq: "{tree_type}"}}'],
    )
    variables["limit"] = limit
    result = await gql(
        f"""
        query ListMythicTree($limit: Int!{decls}) {{
            mythictree({where}, order_by: {{id: desc}}, limit: $limit) {{
                {columns}
            }}
        }}
        """,
        variables,
    )
    rows = result.get("mythictree") or []
    return [normalize_tree_entry(row) for row in rows]


async def list_processes(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[dict[str, Any]]:
    """List captured process listings across hosts, newest first.

    Returns:
        List of dicts with ``host``, ``name_text``, ``full_path_text``,
        ``parent_path_text``, ``metadata``, ``os``, ``timestamp``.
    """
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


async def list_file_browser(
    host: Annotated[str | None, "Filter by hostname (partial match)"] = None,
    path: Annotated[str | None, "Filter by path substring (partial match)"] = None,
    limit: Annotated[int, "Maximum results to return"] = 100,
) -> list[dict[str, Any]]:
    """Browse captured file system entries from agents, newest first.

    Returns:
        List of dicts with ``host``, ``name_text``, ``full_path_text``,
        ``parent_path_text``, ``metadata``, ``can_have_children``, ``os``,
        ``deleted``, ``timestamp``.
    """
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


async def list_tokens(
    callback_display_id: Annotated[
        int | None, "Filter to one callback by its display ID"
    ] = None,
    limit: Annotated[int, "Maximum results to return"] = 50,
) -> list[dict[str, Any]]:
    """List Windows token captures, newest first.

    Returns:
        List of token dicts with ``token_id``, ``user``, ``groups``,
        ``privileges``, ``process_id``, ``integrity_level_sid``, ``host``,
        ``timestamp``, nested ``task``.
    """
    where, decls, variables = build_where(
        {
            "callback_display_id": {
                "predicate": "task: {callback: {display_id: {_eq: $callback_display_id}}}",
                "value": callback_display_id,
            },
        }
    )
    variables["limit"] = limit
    where_clause = f"{where}, " if where else ""
    result = await gql(
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
    rows = result.get("token") or []
    return [clean(row) for row in rows]


# ── Search ──────────────────────────────────────────────────────────


SearchType = Literal["tasks", "credentials", "files", "artifacts", "keylogs"]

_SEARCH_GQL_KEYS: dict[SearchType, str] = {
    "tasks": "task",
    "credentials": "credential",
    "files": "filemeta",
    "artifacts": "taskartifact",
    "keylogs": "keylog",
}

_SEARCH_QUERIES: dict[SearchType, str] = {
    "tasks": """
        query SearchTasks($s: String!, $l: Int!) {
            task(where: {_or: [{display_params: {_ilike: $s}}, {command_name: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                 order_by: {id: desc}, limit: $l) {
                id, display_id, command_name, display_params, status, timestamp,
                callback { display_id, host }
            }
        }
    """,
    "credentials": """
        query SearchCreds($s: String!, $l: Int!) {
            credential(where: {_or: [{account: {_ilike: $s}}, {realm: {_ilike: $s}}, {credential_text: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                       order_by: {id: desc}, limit: $l) {
                id, type, realm, account, credential_text, comment
            }
        }
    """,
    "files": """
        query SearchFiles($s: String!, $l: Int!) {
            filemeta(where: {_or: [{filename_utf8: {_ilike: $s}}, {full_remote_path_utf8: {_ilike: $s}}]},
                     order_by: {id: desc}, limit: $l) {
                id, agent_file_id, filename_utf8, full_remote_path_utf8, host, is_download_from_agent
            }
        }
    """,
    "artifacts": """
        query SearchArtifacts($s: String!, $l: Int!) {
            taskartifact(where: {_or: [{artifact_text: {_ilike: $s}}, {base_artifact: {_ilike: $s}}]},
                         order_by: {id: desc}, limit: $l) {
                id, artifact_text, base_artifact, host
            }
        }
    """,
    "keylogs": """
        query SearchKeylogs($s: String!, $l: Int!) {
            keylog(where: {_or: [{keystrokes_text: {_ilike: $s}}, {window: {_ilike: $s}}]},
                   order_by: {id: desc}, limit: $l) {
                id, keystrokes_text, window
            }
        }
    """,
}


def _parse_search_types(raw: str | None) -> list[SearchType]:
    all_types: list[SearchType] = list(_SEARCH_GQL_KEYS)
    if raw is None:
        return all_types
    requested = {name.strip() for name in raw.split(",")}
    return [t for t in all_types if t in requested]


async def search(
    query: Annotated[str, "Search term (wrapped in ``%...%`` for ILIKE)"],
    types: Annotated[
        str | None,
        "Comma-separated types to search (tasks,credentials,files,artifacts,keylogs). Default: all",
    ] = None,
    limit: Annotated[int, "Maximum results per type"] = 10,
) -> dict[str, Any]:
    """Search tasks, credentials, files, artifacts, and keylogs concurrently.

    Case-insensitive substring search (Hasura ``_ilike``) across the text
    fields of each type. Errors in one type do not fail the whole call —
    they appear under an ``errors`` key.

    Args:
        query: The substring to search for.
        types: Restrict to a subset of types.
        limit: Max matches per type.

    Returns:
        Dict keyed by type with lists of matching rows, plus an ``errors``
        dict keyed by type for any that failed.
    """
    await ensure_connected()
    term = f"%{query}%"
    variables: dict[str, Any] = {"s": term, "l": limit}

    selected = _parse_search_types(types)
    raw = await asyncio.gather(
        *(gql(_SEARCH_QUERIES[key], variables) for key in selected),
        return_exceptions=True,
    )

    out: dict[str, Any] = {key: [] for key in selected}
    errors: dict[str, str] = {}
    for key, r in zip(selected, raw):
        if isinstance(r, BaseException):
            errors[key] = str(r)
            continue
        if not isinstance(r, dict):
            continue
        rows = r.get(_SEARCH_GQL_KEYS[key]) or []
        out[key] = [clean(row) for row in rows]
    if errors:
        out["errors"] = errors
    return out


# ── Registration ────────────────────────────────────────────────────


_TOOLS = (
    get_status,
    list_callbacks,
    get_callback,
    list_tasks,
    get_task,
    get_task_output,
    get_recent_callback_activity,
    get_operation_summary,
    list_credentials,
    list_files,
    list_payloads,
    find_bloodhound_data,
    get_file_contents,
    list_artifacts,
    list_keylogs,
    list_screenshots,
    list_processes,
    list_file_browser,
    list_tokens,
    search,
)


def register(mcp: FastMCP) -> None:
    """Attach every observation tool onto the provided FastMCP instance."""
    for fn in _TOOLS:
        mcp.tool(fn)
