#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "pydantic>=2.0,<3.0",
# ]
# ///
"""Read-only Mythic C2 query tool — no commands executed, no state modified.

Usage:
    uv run mythic_read.py <command> [options]

Commands:
    status, callbacks, callback, tasks, task-output, credentials,
    files, file-contents, artifacts, keylogs, screenshots,
    processes, file-browser, tokens, search

Env vars:
    MYTHIC_SERVER_IP    (default: 127.0.0.1)
    MYTHIC_SERVER_PORT  (default: 7443)
    MYTHIC_USERNAME     (default: mythic_admin)
    MYTHIC_PASSWORD     (required unless MYTHIC_API_TOKEN set)
    MYTHIC_API_TOKEN    (alternative to username/password)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import mimetypes
import os
import sys
from pathlib import Path
from typing import Any, TypeVar

from mythic import mythic as mythic_sdk, mythic_utilities
from pydantic import BaseModel, Field, ValidationInfo, field_validator

_T = TypeVar("_T", bound=BaseModel)
TEMP_DIR = Path("/tmp/mythic-readonly")

# Maps search type names to their GraphQL root query keys.
_SEARCH_GQL_KEYS = {
    "tasks": "task",
    "credentials": "credential",
    "files": "filemeta",
    "artifacts": "taskartifact",
    "keylogs": "keylog",
}


# ── Models ───────────────────────────────────────────────────────────


class _MythicBase(BaseModel):
    """Base model: coerces ``None`` to ``""`` for string fields.

    Mythic's Hasura API returns null for many optional text columns.
    """

    @field_validator("*", mode="before")
    @classmethod
    def _none_to_empty_str(cls, v: object, info: ValidationInfo) -> object:
        if v is None and info.field_name in cls.model_fields:
            field = cls.model_fields[info.field_name]
            if field.annotation is str:
                return ""
        return v


class PayloadTypeRef(_MythicBase):
    name: str = ""


class PayloadRef(_MythicBase):
    os: str = ""
    payloadtype: PayloadTypeRef = Field(default_factory=PayloadTypeRef)
    description: str = ""


class CallbackRef(_MythicBase):
    display_id: int = 0
    host: str = ""


class TaskRef(_MythicBase):
    display_id: int = 0
    command_name: str = ""
    callback: CallbackRef | None = None


class CallbackInList(_MythicBase):
    display_id: int = 0
    host: str = ""
    user: str = ""
    ip: str = ""
    os: str = ""
    active: bool = False
    last_checkin: str = ""
    payload: PayloadRef = Field(default_factory=PayloadRef)


class TaskInList(_MythicBase):
    id: int = 0
    display_id: int = 0
    command_name: str = ""
    original_params: str = ""
    display_params: str = ""
    status: str = ""
    timestamp: str = ""
    callback: CallbackRef | None = None


class CredentialInList(_MythicBase):
    id: int = 0
    type: str = ""
    realm: str = ""
    account: str = ""
    credential_text: str = ""
    comment: str = ""


class FileInList(_MythicBase):
    agent_file_id: str = ""
    filename_utf8: str = ""
    full_remote_path_utf8: str = ""
    host: str = ""
    is_download_from_agent: bool = False
    md5: str = ""


class ArtifactInList(_MythicBase):
    id: int = 0
    artifact_text: str = ""
    base_artifact: str = ""
    host: str = ""
    task: TaskRef | None = None


class KeylogInList(_MythicBase):
    id: int = 0
    keystrokes_text: str = ""
    window: str = ""
    user: str = ""
    task: TaskRef = Field(default_factory=TaskRef)


class ScreenshotInList(_MythicBase):
    agent_file_id: str = ""
    host: str = ""
    timestamp: str = ""


class ProcessMeta(_MythicBase):
    process_id: int = 0
    name: str = ""
    user: str = ""
    bin_path: str = ""


def _coerce_json_metadata(v: object, default: object) -> object:
    """Parse metadata that may be a JSON string, dict, or None."""
    if v is None:
        return default
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (json.JSONDecodeError, ValueError):
            return default
    return v


class ProcessEntry(_MythicBase):
    host: str = ""
    name_text: str = ""
    full_path_text: str = ""
    metadata: ProcessMeta = Field(default_factory=ProcessMeta)

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: object) -> object:
        return _coerce_json_metadata(v, ProcessMeta())


class FileBrowserEntry(_MythicBase):
    name_text: str = ""
    full_path_text: str = ""
    host: str = ""
    can_have_children: bool = False
    metadata: dict = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: object) -> object:
        result = _coerce_json_metadata(v, {})
        return result if isinstance(result, dict) else {}


class TokenInList(_MythicBase):
    id: int = 0
    user: str = ""
    host: str = ""
    groups: str = ""
    privileges: str = ""
    description: str = ""


# ── Connection ───────────────────────────────────────────────────────


async def connect() -> Any:
    ip = os.environ.get("MYTHIC_SERVER_IP", "127.0.0.1")
    port = int(os.environ.get("MYTHIC_SERVER_PORT", "7443"))
    username = os.environ.get("MYTHIC_USERNAME", "mythic_admin")
    password = os.environ.get("MYTHIC_PASSWORD", "")
    api_token = os.environ.get("MYTHIC_API_TOKEN", "")
    timeout = int(os.environ.get("MYTHIC_TIMEOUT", "-1"))

    if not password and not api_token:
        print("Error: Set MYTHIC_PASSWORD or MYTHIC_API_TOKEN env var.", file=sys.stderr)
        sys.exit(1)

    kwargs: dict[str, Any] = {"server_ip": ip, "server_port": port, "timeout": timeout}
    if api_token:
        kwargs["apitoken"] = api_token
    else:
        kwargs["username"] = username
        kwargs["password"] = password

    return await mythic_sdk.login(**kwargs)


async def gql(client: Any, query: str, variables: dict | None = None) -> dict:
    return await mythic_utilities.graphql_post(mythic=client, query=query, variables=variables)


# ── Helpers ──────────────────────────────────────────────────────────


def decode_b64(text: str) -> str:
    """Attempt base64 decode (Poseidon encodes output as base64)."""
    if not text:
        return text
    try:
        return base64.b64decode(text).decode("utf-8")
    except Exception:
        return text


def first_ip(ip_field: str) -> str:
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


def _parse_list(model: type[_T], data: object) -> list[_T]:
    """Validate a list of raw dicts into Pydantic models."""
    if not isinstance(data, list):
        return []
    return [model.model_validate(d) for d in data]


def print_table(headers: list[str], rows: list[list[str]], max_widths: dict[int, int] | None = None) -> None:
    """Print a simple aligned table."""
    if not rows:
        print("(no results)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    if max_widths:
        for i, mw in max_widths.items():
            if i < len(widths):
                widths[i] = min(widths[i], mw)
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)
            if max_widths and i in max_widths and len(s) > max_widths[i]:
                s = s[: max_widths[i] - 3] + "..."
            cells.append(s)
        print(fmt.format(*cells))


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


# ── Commands ─────────────────────────────────────────────────────────


async def cmd_status(client: Any, args: argparse.Namespace) -> None:
    me = await mythic_sdk.get_me(mythic=client)
    hook = me.get("meHook", {})
    op = hook.get("current_operation", "unknown")
    ip = os.environ.get("MYTHIC_SERVER_IP", "127.0.0.1")
    port = os.environ.get("MYTHIC_SERVER_PORT", "7443")
    print(f"Connected to {ip}:{port} — operation: {op}")


async def cmd_callbacks(client: Any, args: argparse.Namespace) -> None:
    attrs = (
        "display_id,host,user,ip,external_ip,os,architecture,pid,process_name,"
        "description,extra_info,sleep_info,active,last_checkin,init_callback,integrity_level,"
        "domain,payload{os,payloadtype{name},description}"
    )
    if args.active:
        cbs_raw = await mythic_sdk.get_all_active_callbacks(client, custom_return_attributes=attrs)
    else:
        cbs_raw = await mythic_sdk.get_all_callbacks(client, custom_return_attributes=attrs)
    cbs_raw = sorted(cbs_raw, key=lambda x: x.get("last_checkin", ""), reverse=True)

    if args.json or args.detail:
        print_json(cbs_raw)
        return

    callbacks = _parse_list(CallbackInList, cbs_raw)
    headers = ["ID", "HOST", "USER", "IP", "OS", "AGENT", "ACTIVE", "LAST_CHECKIN"]
    rows = [
        [
            str(cb.display_id),
            cb.host,
            cb.user,
            first_ip(cb.ip),
            cb.os.split("\n")[0],
            cb.payload.payloadtype.name or "?",
            "yes" if cb.active else "no",
            cb.last_checkin[:16],
        ]
        for cb in callbacks
    ]
    print_table(headers, rows)


async def cmd_callback(client: Any, args: argparse.Namespace) -> None:
    query = """
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
    """
    result = await gql(client, query, {"display_id": args.id})
    callbacks = result.get("callback", [])
    if not callbacks:
        print(f"No callback found with id={args.id}")
        return
    print_json(callbacks[0])


async def cmd_tasks(client: Any, args: argparse.Namespace) -> None:
    attrs = (
        "id,display_id,command_name,original_params,display_params,"
        "status,completed,timestamp,comment,"
        "operator{username},callback{display_id,host}"
    )
    tasks_raw = await mythic_sdk.get_all_tasks(
        client, custom_return_attributes=attrs,
        callback_display_id=args.callback,
    )
    tasks_raw.sort(key=lambda x: x.get("id", 0), reverse=True)
    page_raw = tasks_raw[args.offset: args.offset + args.limit]

    if args.json or args.detail:
        print_json(page_raw)
        return

    tasks = _parse_list(TaskInList, page_raw)
    headers = ["ID", "COMMAND", "PARAMS", "STATUS", "HOST", "TIMESTAMP"]
    rows = [
        [
            str(t.display_id),
            t.command_name,
            t.display_params or t.original_params,
            t.status,
            t.callback.host if t.callback else "",
            t.timestamp[:16],
        ]
        for t in tasks
    ]
    print_table(headers, rows, max_widths={2: 60})
    if len(tasks_raw) > args.offset + args.limit:
        print(f"\n({len(tasks_raw)} total tasks — showing {args.offset + 1}-{args.offset + len(tasks)}, use --offset to page)")


async def cmd_task_output(client: Any, args: argparse.Namespace) -> None:
    responses = await mythic_sdk.get_all_task_and_subtask_output_by_id(
        mythic=client, task_display_id=args.id
    )
    if not responses:
        print(f"No output for task {args.id}")
        return
    parts = []
    for r in responses:
        text = r.get("response_text", r.get("response", ""))
        if text:
            parts.append(decode_b64(str(text)))
    full = "\n".join(parts)
    lines = full.split("\n")
    total = len(lines)

    if args.offset > 0 or args.max_lines is not None:
        sliced = lines[args.offset:]
        if args.max_lines is not None:
            sliced = sliced[:args.max_lines]
        print("\n".join(sliced))
        shown_end = min(args.offset + len(sliced), total)
        if shown_end < total:
            print(f"\n... (lines {args.offset + 1}-{shown_end} of {total} — use --offset/--max-lines to page)")
    else:
        print(full)


async def cmd_credentials(client: Any, args: argparse.Namespace) -> None:
    query = """
    query AllCredentials($limit: Int!, $offset: Int!) {
        credential(order_by: {id: desc}, limit: $limit, offset: $offset) {
            id, type, realm, account, credential_text, comment, timestamp,
            operator { username },
            task { id, display_id, command_name,
                   callback { display_id, host } }
        }
    }
    """
    result = await gql(client, query, {"limit": args.limit, "offset": args.offset})
    creds_raw = result.get("credential", [])

    if args.json or args.detail:
        print_json(creds_raw)
        return

    creds = _parse_list(CredentialInList, creds_raw)
    headers = ["ID", "TYPE", "REALM", "ACCOUNT", "CREDENTIAL", "COMMENT"]
    rows = [
        [str(c.id), c.type, c.realm, c.account, c.credential_text, c.comment]
        for c in creds
    ]
    print_table(headers, rows, max_widths={4: 50, 5: 40})


async def cmd_files(client: Any, args: argparse.Namespace) -> None:
    attrs = (
        "id,agent_file_id,filename_utf8,full_remote_path_utf8,host,complete,"
        "is_download_from_agent,md5,sha1,timestamp,comment,"
        "task{display_id,command_name,callback{display_id,host}}"
    )
    results = []
    if not args.uploaded_only:
        async for batch in mythic_sdk.get_all_downloaded_files(client, custom_return_attributes=attrs):
            results.extend(batch)
            if len(results) >= args.limit:
                break
    if args.uploaded or args.uploaded_only:
        async for batch in mythic_sdk.get_all_uploaded_files(client, custom_return_attributes=attrs):
            results.extend(batch)
            if len(results) >= args.limit:
                break
    page_raw = results[:args.limit]

    if args.json or args.detail:
        print_json(page_raw)
        return

    files = _parse_list(FileInList, page_raw)
    headers = ["FILE_ID", "FILENAME", "PATH", "HOST", "MD5", "DOWNLOADED"]
    rows = [
        [
            f.agent_file_id[:12] + "...",
            f.filename_utf8,
            f.full_remote_path_utf8,
            f.host,
            f.md5[:12],
            "yes" if f.is_download_from_agent else "no",
        ]
        for f in files
    ]
    print_table(headers, rows, max_widths={2: 50})


async def cmd_file_contents(client: Any, args: argparse.Namespace) -> None:
    data = await mythic_sdk.download_file(mythic=client, file_uuid=args.uuid)
    if not data:
        print("File is empty or could not be downloaded.")
        return

    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / args.uuid
    path.write_bytes(data)

    try:
        text = data.decode("utf-8")
        lines = text.split("\n")
        print(f"Saved to: {path}")
        print(f"Size: {len(data)} bytes, {len(lines)} lines")
        print(f"--- Preview (first 50 lines) ---")
        print("\n".join(lines[:50]))
        if len(lines) > 50:
            print(f"\n... ({len(lines)} lines total — use Read tool on {path} with offset/limit for more)")
    except UnicodeDecodeError:
        mime, _ = mimetypes.guess_type(str(path))
        print(f"Saved to: {path}")
        print(f"Size: {len(data)} bytes")
        print(f"Type: binary ({mime or 'application/octet-stream'})")
        print("Use Read tool or external tools to inspect.")


async def cmd_artifacts(client: Any, args: argparse.Namespace) -> None:
    query = """
    query AllArtifacts($limit: Int!, $offset: Int!) {
        taskartifact(order_by: {id: desc}, limit: $limit, offset: $offset) {
            id, artifact_text, base_artifact, host, timestamp,
            task { display_id, command_name,
                   callback { display_id, host } }
        }
    }
    """
    result = await gql(client, query, {"limit": args.limit, "offset": args.offset})
    artifacts_raw = result.get("taskartifact", [])

    if args.json or args.detail:
        print_json(artifacts_raw)
        return

    artifacts = _parse_list(ArtifactInList, artifacts_raw)
    headers = ["ID", "TYPE", "ARTIFACT", "HOST", "TASK_ID"]
    rows = [
        [
            str(a.id),
            a.base_artifact,
            a.artifact_text,
            a.host or (a.task.callback.host if a.task and a.task.callback else ""),
            str(a.task.display_id) if a.task else "",
        ]
        for a in artifacts
    ]
    print_table(headers, rows, max_widths={2: 80})


async def cmd_keylogs(client: Any, args: argparse.Namespace) -> None:
    if args.callback is not None:
        query = """
        query KeylogsByCallback($callback_display_id: Int!, $limit: Int!, $offset: Int!) {
            keylog(where: {task: {callback: {display_id: {_eq: $callback_display_id}}}},
                   order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, keystrokes_text, window, user, timestamp,
                task { display_id, callback { display_id, host } }
            }
        }
        """
        variables: dict[str, Any] = {"callback_display_id": args.callback, "limit": args.limit, "offset": args.offset}
    else:
        query = """
        query AllKeylogs($limit: Int!, $offset: Int!) {
            keylog(order_by: {id: desc}, limit: $limit, offset: $offset) {
                id, keystrokes_text, window, user, timestamp,
                task { display_id, callback { display_id, host } }
            }
        }
        """
        variables = {"limit": args.limit, "offset": args.offset}

    result = await gql(client, query, variables)
    keylogs_raw = result.get("keylog", [])

    if args.json or args.detail:
        print_json(keylogs_raw)
        return

    keylogs = _parse_list(KeylogInList, keylogs_raw)
    headers = ["ID", "KEYSTROKES", "WINDOW", "USER", "HOST"]
    rows = [
        [
            str(k.id),
            k.keystrokes_text,
            k.window,
            k.user,
            k.task.callback.host if k.task.callback else "",
        ]
        for k in keylogs
    ]
    print_table(headers, rows, max_widths={1: 60, 2: 30})


async def cmd_screenshots(client: Any, args: argparse.Namespace) -> None:
    attrs = "id,agent_file_id,host,timestamp"
    results = []
    async for batch in mythic_sdk.get_all_screenshots(client, custom_return_attributes=attrs):
        results.extend(batch)
        if len(results) >= args.limit:
            break
    page_raw = results[:args.limit]

    if args.json or args.detail:
        print_json(page_raw)
        return

    screenshots = _parse_list(ScreenshotInList, page_raw)
    headers = ["FILE_ID", "HOST", "TIMESTAMP"]
    rows = [
        [s.agent_file_id, s.host, s.timestamp[:16]]
        for s in screenshots
    ]
    print_table(headers, rows)


async def cmd_processes(client: Any, args: argparse.Namespace) -> None:
    if args.host:
        query = """
        query ProcessesByHost($host: String!, $limit: Int!) {
            mythictree(where: {host: {_ilike: $host}, tree_type: {_eq: "process"}},
                       order_by: {id: desc}, limit: $limit) {
                id, task_id, timestamp, host, name_text, parent_path_text,
                full_path_text, metadata, os, success
            }
        }
        """
        result = await gql(client, query, {"host": f"%{args.host}%", "limit": args.limit})
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
        result = await gql(client, query, {"limit": args.limit})
    procs_raw = result.get("mythictree", [])

    if args.json or args.detail:
        print_json(procs_raw)
        return

    procs = _parse_list(ProcessEntry, procs_raw)
    headers = ["PID", "NAME", "USER", "BIN_PATH", "HOST"]
    rows = [
        [
            str(p.metadata.process_id or p.full_path_text),
            p.metadata.name or p.name_text,
            p.metadata.user,
            p.metadata.bin_path,
            p.host,
        ]
        for p in procs
    ]
    print_table(headers, rows, max_widths={3: 60})


async def cmd_file_browser(client: Any, args: argparse.Namespace) -> None:
    conditions = ['tree_type: {_eq: "file"}']
    variables: dict[str, Any] = {"limit": args.limit}
    decls = ""
    if args.host:
        conditions.append("host: {_ilike: $host}")
        variables["host"] = f"%{args.host}%"
        decls += ", $host: String"
    if args.path:
        conditions.append("full_path_text: {_ilike: $path}")
        variables["path"] = f"%{args.path}%"
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
    result = await gql(client, query, variables)
    entries_raw = result.get("mythictree", [])

    if args.json or args.detail:
        print_json(entries_raw)
        return

    entries = _parse_list(FileBrowserEntry, entries_raw)
    headers = ["NAME", "PATH", "HOST", "TYPE", "SIZE", "PERMS"]
    rows = []
    for e in entries:
        perms = e.metadata.get("permissions", {})
        rows.append([
            e.name_text,
            e.full_path_text,
            e.host,
            "dir" if e.can_have_children else "file",
            str(e.metadata.get("size", "")),
            perms.get("permissions", "") if isinstance(perms, dict) else "",
        ])
    print_table(headers, rows, max_widths={1: 50})


async def cmd_tokens(client: Any, args: argparse.Namespace) -> None:
    if args.callback is not None:
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
        variables: dict[str, Any] = {"callback_display_id": args.callback, "limit": args.limit}
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
        variables = {"limit": args.limit}

    result = await gql(client, query, variables)
    tokens_raw = result.get("token", [])

    if args.json or args.detail:
        print_json(tokens_raw)
        return

    tokens = _parse_list(TokenInList, tokens_raw)
    headers = ["ID", "USER", "HOST", "GROUPS", "PRIVILEGES", "DESCRIPTION"]
    rows = [
        [str(t.id), t.user, t.host, str(t.groups), str(t.privileges), t.description]
        for t in tokens
    ]
    print_table(headers, rows, max_widths={3: 40, 4: 40})


async def cmd_search(client: Any, args: argparse.Namespace) -> None:
    term = f"%{args.query}%"
    types = set(args.types.split(",")) if args.types else set(_SEARCH_GQL_KEYS)

    queries = {}
    if "tasks" in types:
        queries["tasks"] = gql(client, """
            query SearchTasks($s: String!, $l: Int!) {
                task(where: {_or: [{display_params: {_ilike: $s}}, {command_name: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                     order_by: {id: desc}, limit: $l) {
                    display_id, command_name, display_params, status, timestamp,
                    callback { display_id, host }
                }
            }""", {"s": term, "l": args.limit})
    if "credentials" in types:
        queries["credentials"] = gql(client, """
            query SearchCreds($s: String!, $l: Int!) {
                credential(where: {_or: [{account: {_ilike: $s}}, {realm: {_ilike: $s}}, {credential_text: {_ilike: $s}}, {comment: {_ilike: $s}}]},
                           order_by: {id: desc}, limit: $l) {
                    id, type, realm, account, credential_text, comment
                }
            }""", {"s": term, "l": args.limit})
    if "files" in types:
        queries["files"] = gql(client, """
            query SearchFiles($s: String!, $l: Int!) {
                filemeta(where: {_or: [{filename_utf8: {_ilike: $s}}, {full_remote_path_utf8: {_ilike: $s}}]},
                         order_by: {id: desc}, limit: $l) {
                    agent_file_id, filename_utf8, full_remote_path_utf8, host, is_download_from_agent
                }
            }""", {"s": term, "l": args.limit})
    if "artifacts" in types:
        queries["artifacts"] = gql(client, """
            query SearchArtifacts($s: String!, $l: Int!) {
                taskartifact(where: {_or: [{artifact_text: {_ilike: $s}}, {base_artifact: {_ilike: $s}}]},
                             order_by: {id: desc}, limit: $l) {
                    id, artifact_text, base_artifact, host
                }
            }""", {"s": term, "l": args.limit})
    if "keylogs" in types:
        queries["keylogs"] = gql(client, """
            query SearchKeylogs($s: String!, $l: Int!) {
                keylog(where: {_or: [{keystrokes_text: {_ilike: $s}}, {window: {_ilike: $s}}]},
                       order_by: {id: desc}, limit: $l) {
                    id, keystrokes_text, window
                }
            }""", {"s": term, "l": args.limit})

    keys = list(queries.keys())
    raw = await asyncio.gather(*queries.values(), return_exceptions=True)
    gql_keys = _SEARCH_GQL_KEYS

    if args.json or args.detail:
        results = {}
        for key, r in zip(keys, raw):
            if isinstance(r, BaseException):
                results[key] = [{"error": str(r)}]
            elif isinstance(r, dict):
                results[key] = r.get(gql_keys.get(key, key), [])
            else:
                results[key] = []
        print_json(results)
        return

    for key, r in zip(keys, raw):
        items: list = []
        if isinstance(r, dict):
            items = r.get(gql_keys.get(key, key), [])
        elif isinstance(r, BaseException):
            print(f"\n=== {key.upper()} === (error: {r})")
            continue
        print(f"\n=== {key.upper()} ({len(items)} results) ===")
        if not items:
            continue
        if key == "tasks":
            for t in _parse_list(TaskInList, items):
                host = t.callback.host if t.callback else ""
                print(f"  #{t.display_id} {t.command_name} {t.display_params[:60]} [{t.status}] on {host}")
        elif key == "credentials":
            for c in _parse_list(CredentialInList, items):
                print(f"  [{c.type}] {c.realm}\\{c.account}: {c.credential_text[:50]}  ({c.comment})")
        elif key == "files":
            for f in _parse_list(FileInList, items):
                dl = "download" if f.is_download_from_agent else "upload"
                print(f"  {f.filename_utf8} — {f.full_remote_path_utf8} on {f.host} [{dl}]")
        elif key == "artifacts":
            for a in _parse_list(ArtifactInList, items):
                print(f"  [{a.base_artifact}] {a.artifact_text[:80]} on {a.host}")
        elif key == "keylogs":
            for k in _parse_list(KeylogInList, items):
                print(f"  {k.keystrokes_text[:80]} (window: {k.window})")


# ── CLI ──────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only Mythic C2 query tool")
    sub = p.add_subparsers(dest="command", required=True)

    # Shared flags available on every subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-d", "--detail", action="store_true", help="Print full raw JSON")
    common.add_argument("--json", action="store_true", help="Output raw JSON")

    sub.add_parser("status", parents=[common], help="Show connection and operation info")

    cb_list = sub.add_parser("callbacks", parents=[common], help="List callbacks")
    cb_list.add_argument("--active", action="store_true", help="Active only")

    cb_detail = sub.add_parser("callback", parents=[common], help="Full details for one callback")
    cb_detail.add_argument("id", type=int, help="Callback display ID")

    tasks = sub.add_parser("tasks", parents=[common], help="List tasks")
    tasks.add_argument("--callback", type=int, default=None, help="Filter by callback ID")
    tasks.add_argument("--limit", type=int, default=20)
    tasks.add_argument("--offset", type=int, default=0)

    to = sub.add_parser("task-output", parents=[common], help="Get decoded task output")
    to.add_argument("id", type=int, help="Task display ID")
    to.add_argument("--max-lines", type=int, default=None, help="Limit output lines")
    to.add_argument("--offset", type=int, default=0, help="Skip N lines")

    creds = sub.add_parser("credentials", parents=[common], help="List credentials")
    creds.add_argument("--limit", type=int, default=50)
    creds.add_argument("--offset", type=int, default=0)

    files = sub.add_parser("files", parents=[common], help="List files")
    files.add_argument("--uploaded", action="store_true", help="Include uploaded files")
    files.add_argument("--uploaded-only", action="store_true", help="Only uploaded files")
    files.add_argument("--limit", type=int, default=20)

    fc = sub.add_parser("file-contents", parents=[common], help="Download and preview a file")
    fc.add_argument("uuid", help="File UUID (agent_file_id)")

    arts = sub.add_parser("artifacts", parents=[common], help="List artifacts/IOCs")
    arts.add_argument("--limit", type=int, default=50)
    arts.add_argument("--offset", type=int, default=0)

    kl = sub.add_parser("keylogs", parents=[common], help="List keylogs")
    kl.add_argument("--callback", type=int, default=None)
    kl.add_argument("--limit", type=int, default=50)
    kl.add_argument("--offset", type=int, default=0)

    ss = sub.add_parser("screenshots", parents=[common], help="List screenshots")
    ss.add_argument("--limit", type=int, default=20)

    ps = sub.add_parser("processes", parents=[common], help="List processes")
    ps.add_argument("--host", default=None, help="Filter by hostname")
    ps.add_argument("--limit", type=int, default=100)

    fb = sub.add_parser("file-browser", parents=[common], help="Browse file system data")
    fb.add_argument("--host", default=None)
    fb.add_argument("--path", default=None)
    fb.add_argument("--limit", type=int, default=100)

    tk = sub.add_parser("tokens", parents=[common], help="List tokens")
    tk.add_argument("--callback", type=int, default=None)
    tk.add_argument("--limit", type=int, default=50)

    sr = sub.add_parser("search", parents=[common], help="Search across operation data")
    sr.add_argument("query", help="Search term")
    sr.add_argument("--types", default=None, help="Comma-separated: tasks,credentials,files,artifacts,keylogs")
    sr.add_argument("--limit", type=int, default=10)

    return p


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    client = await connect()

    commands = {
        "status": cmd_status, "callbacks": cmd_callbacks, "callback": cmd_callback,
        "tasks": cmd_tasks, "task-output": cmd_task_output, "credentials": cmd_credentials,
        "files": cmd_files, "file-contents": cmd_file_contents, "artifacts": cmd_artifacts,
        "keylogs": cmd_keylogs, "screenshots": cmd_screenshots, "processes": cmd_processes,
        "file-browser": cmd_file_browser, "tokens": cmd_tokens, "search": cmd_search,
    }
    await commands[args.command](client, args)


if __name__ == "__main__":
    asyncio.run(main())
