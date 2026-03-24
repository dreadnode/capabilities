# C2/Network Stateful Tools → MCP Servers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert mythic-c2, sliver-c2, and bloodhound from Python Toolset classes to standalone FastMCP servers with isolated dependencies.

**Architecture:** Each server is a standalone `uv run` script with PEP 723 inline deps, following the web-security caido/jxscout pattern. Servers use lazy connection with env var defaults and an explicit `connect` tool for runtime override. Old Toolset files are deleted after the MCP replacement is validated.

**Tech Stack:** FastMCP >=2.0, PEP 723 inline metadata, `uv run` for dep isolation

**Reference pattern:** `dreadnode/web-security/mcp/server.py` + `mcp/tools/caido.py`

---

## File Structure

```
dreadnode/mythic-c2/
├── capability.yaml              (modify: add mcp.servers.mythic)
├── mcp/
│   └── server.py                (create: FastMCP server, ~250 lines)
└── tools/
    ├── mythic.py                (delete: replaced by MCP)
    └── mythic_apollo.py         (delete: replaced by MCP)

dreadnode/sliver-c2/
├── capability.yaml              (modify: add mcp.servers.sliver)
├── mcp/
│   └── server.py                (create: FastMCP server, ~300 lines)
└── tools/
    ├── sliver.py                (delete: replaced by MCP)
    └── sliver_session.py        (delete: replaced by MCP)

dreadnode/network-ops/
├── capability.yaml              (modify: add mcp.servers.bloodhound)
├── mcp/
│   └── bloodhound.py            (create: FastMCP server, ~250 lines)
└── tools/
    ├── bloodhound.py            (delete: replaced by MCP)
    ├── impacket.py              (keep: stateless subprocess wrapper)
    ├── netexec.py               (keep)
    ├── nmap.py                  (keep)
    ├── ... other tools ...      (keep)
```

---

### Task 1: Mythic C2 MCP Server

**Files:**
- Create: `dreadnode/mythic-c2/mcp/server.py`
- Modify: `dreadnode/mythic-c2/capability.yaml`
- Delete: `dreadnode/mythic-c2/tools/mythic.py`
- Delete: `dreadnode/mythic-c2/tools/mythic_apollo.py`

- [ ] **Step 1: Create the MCP server**

Create `dreadnode/mythic-c2/mcp/server.py`:

```python
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
```

- [ ] **Step 2: Update capability.yaml**

Add to `dreadnode/mythic-c2/capability.yaml`:

```yaml
mcp:
  servers:
    mythic:
      command: "uv"
      args: ["run", "${CAPABILITY_ROOT}/mcp/server.py"]
      init_timeout: 30
```

- [ ] **Step 3: Verify the MCP server starts**

```bash
cd dreadnode/mythic-c2 && uv run mcp/server.py &
# Should start without import errors (mythic lib will fail at connect time, not import time)
# Kill the background process
```

- [ ] **Step 4: Run SDK validation**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/mythic-c2/
```

Expected: OK or WARN (MCP server may not connect without a running Mythic instance, but should not FAIL).

- [ ] **Step 5: Delete old Toolset files**

```bash
rm dreadnode/mythic-c2/tools/mythic.py dreadnode/mythic-c2/tools/mythic_apollo.py
rmdir dreadnode/mythic-c2/tools/ 2>/dev/null || true
```

- [ ] **Step 6: Re-validate after deletion**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/mythic-c2/
```

- [ ] **Step 7: Commit**

```bash
git add dreadnode/mythic-c2/
git commit -m "refactor(mythic-c2): replace Toolset with FastMCP server

Convert Mythic and Apollo Toolset classes to a standalone FastMCP server
with PEP 723 deps (mythic SDK isolated from platform env).

- Lazy connection with MYTHIC_* env vars + runtime connect() tool
- Consolidate ~30 Apollo command wrappers into one generic execute() tool
- Delete old tools/ directory"
```

---

### Task 2: Sliver C2 MCP Server

**Files:**
- Create: `dreadnode/sliver-c2/mcp/server.py`
- Modify: `dreadnode/sliver-c2/capability.yaml`
- Delete: `dreadnode/sliver-c2/tools/sliver.py`
- Delete: `dreadnode/sliver-c2/tools/sliver_session.py`

- [ ] **Step 1: Create the MCP server**

Create `dreadnode/sliver-c2/mcp/server.py`:

```python
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
            "id": s.ID, "name": s.Name, "remote_address": s.RemoteAddress,
            "hostname": s.Hostname, "username": s.Username, "os": s.OS,
            "arch": s.Arch, "transport": s.Transport, "pid": s.PID,
        }
        for s in await client.sessions()
    ]


@mcp.tool
async def get_beacons() -> list[dict]:
    """List all active Sliver beacons (async callback implants)."""
    client = await _get_client()
    return [
        {
            "id": b.ID, "name": b.Name, "hostname": b.Hostname,
            "username": b.Username, "os": b.OS, "arch": b.Arch,
            "transport": b.Transport, "interval": b.Interval, "jitter": b.Jitter,
        }
        for b in await client.beacons()
    ]


@mcp.tool
async def get_jobs() -> list[dict]:
    """List all active jobs (listeners) on the Sliver server."""
    client = await _get_client()
    return [
        {"id": j.ID, "name": j.Name, "protocol": j.Protocol, "port": j.Port}
        for j in await client.jobs()
    ]


@mcp.tool
async def start_listener(
    listener_type: Annotated[str, "Listener type: mtls, https, http, or dns"],
    host: Annotated[str, "Interface to bind on"] = "0.0.0.0",
    port: Annotated[int, "Port for the listener"] = 8888,
    domains: Annotated[list[str] | None, "DNS domains (required for dns type)"] = None,
) -> str:
    """Start a C2 listener on the Sliver server."""
    client = await _get_client()
    if listener_type == "mtls":
        r = await client.start_mtls_listener(host=host, port=port)
    elif listener_type == "https":
        r = await client.start_https_listener(host=host, port=port)
    elif listener_type == "http":
        r = await client.start_http_listener(host=host, port=port)
    elif listener_type == "dns":
        if not domains:
            return "Error: domains required for DNS listener."
        r = await client.start_dns_listener(domains=domains, host=host, port=port)
    else:
        return f"Error: unknown listener type '{listener_type}'. Use mtls, https, http, or dns."
    return f"Started {listener_type} listener — Job ID: {r.JobID}"


@mcp.tool
async def kill_job(
    job_id: Annotated[int, "Job ID to kill"],
) -> str:
    """Kill an active listener job."""
    client = await _get_client()
    r = await client.kill_job(job_id)
    return f"Killed job {r.ID}"


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
async def ps() -> str:
    """List running processes on the target."""
    impl = await _get_interact()
    procs = await _resolve(await impl.ps())
    lines = [f"{'PID':>7}  {'PPID':>7}  {'Owner':20}  Executable"]
    lines.extend(f"{p.Pid:7d}  {p.Ppid:7d}  {p.Owner:20s}  {p.Executable}" for p in procs)
    return _truncate("\n".join(lines))


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
    tcp: Annotated[bool, "Show TCP"] = True,
    udp: Annotated[bool, "Show UDP"] = True,
    listening: Annotated[bool, "Only listening ports"] = True,
) -> str:
    """Show active network connections on the target."""
    impl = await _get_interact()
    result = await _resolve(await impl.netstat(tcp=tcp, udp=udp, ipv4=True, ipv6=False, listening=listening))
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
        await impl.execute_assembly(data, arguments=arguments, process="",
                                     is_dll=is_dll, arch=arch, class_name="",
                                     method="", app_domain="")
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


if __name__ == "__main__":
    mcp.run(transport="stdio")
```

- [ ] **Step 2: Update capability.yaml**

Add to `dreadnode/sliver-c2/capability.yaml`:

```yaml
mcp:
  servers:
    sliver:
      command: "uv"
      args: ["run", "${CAPABILITY_ROOT}/mcp/server.py"]
      init_timeout: 30
```

- [ ] **Step 3: Validate**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/sliver-c2/
```

- [ ] **Step 4: Delete old Toolset files**

```bash
rm dreadnode/sliver-c2/tools/sliver.py dreadnode/sliver-c2/tools/sliver_session.py
rmdir dreadnode/sliver-c2/tools/ 2>/dev/null || true
```

- [ ] **Step 5: Re-validate and commit**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/sliver-c2/
git add dreadnode/sliver-c2/
git commit -m "refactor(sliver-c2): replace Toolset with FastMCP server

Convert Sliver and SliverImplant Toolset classes to a standalone FastMCP
server with PEP 723 deps (sliver-py isolated from platform env).

- Lazy connection with SLIVER_CONFIG_FILE env var + runtime connect() tool
- interact() tool sets active implant for subsequent commands
- Consolidate 4 listener types into one start_listener() tool
- Drop server lifecycle management (require pre-existing server)
- Delete old tools/ directory"
```

---

### Task 3: BloodHound MCP Server

**Files:**
- Create: `dreadnode/network-ops/mcp/bloodhound.py`
- Modify: `dreadnode/network-ops/capability.yaml`
- Delete: `dreadnode/network-ops/tools/bloodhound.py`

- [ ] **Step 1: Create the MCP server**

Create `dreadnode/network-ops/mcp/bloodhound.py`:

```python
#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "fastmcp>=2.0",
#   "neo4j>=5.0",
#   "aiohttp>=3.0",
# ]
# ///
"""BloodHound CE MCP server — graph queries and API interaction.

Env vars:
  BLOODHOUND_URL          (default: http://localhost:8080)
  BLOODHOUND_USERNAME     (default: admin)
  BLOODHOUND_PASSWORD     (required unless provided via connect tool)
  NEO4J_URL               (default: bolt://localhost:7687)
  NEO4J_USERNAME          (default: neo4j)
  NEO4J_PASSWORD          (default: bloodhoundcommunityedition)
"""

from __future__ import annotations

import os
from typing import Annotated, Any

import aiohttp
from fastmcp import FastMCP
from neo4j import AsyncGraphDatabase

mcp = FastMCP("bloodhound")

# ── Standard query catalog ───────────────────────────────────────────

STANDARD_QUERIES: dict[str, dict[str, str]] = {
    # Domain Admins & Trusts
    "find_all_domain_admins": {
        "description": "Find all users and computers that are members of the Domain Admins group",
        "category": "domain-admins",
        "cypher": "MATCH p = (t:Group)<-[:MemberOf*1..]-(a) WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512' RETURN p LIMIT 1000",
    },
    "map_domain_trusts": {
        "description": "Map all domain trust relationships",
        "category": "domain-admins",
        "cypher": "MATCH p = (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p",
    },
    # Tier Zero
    "find_tier_zero_locations": {
        "description": "Find where tier zero principals are logged in",
        "category": "tier-zero",
        "cypher": "MATCH p = (c:Computer)-[:HasSession]->(s) WHERE s.highvalue = true RETURN p",
    },
    "find_shortest_paths_to_tier_zero": {
        "description": "Find shortest attack paths from any principal to tier zero assets",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((s)-[r*1..]->(t)) WHERE t.highvalue = true AND s<>t RETURN p LIMIT 1000",
    },
    "find_paths_from_domain_users_to_tier_zero": {
        "description": "Find paths from Domain Users group to tier zero",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((g:Group)-[r*1..]->(t)) WHERE g.objectid ENDS WITH '-513' AND t.highvalue = true RETURN p LIMIT 1000",
    },
    "find_paths_from_owned_objects": {
        "description": "Find attack paths from owned principals",
        "category": "tier-zero",
        "cypher": "MATCH p=shortestPath((s)-[r*1..]->(t)) WHERE s.owned = true AND t.highvalue = true AND s<>t RETURN p LIMIT 1000",
    },
    # Kerberos
    "find_kerberoastable_tier_zero": {
        "description": "Find tier zero users vulnerable to Kerberoasting",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true AND NOT u.objectid ENDS WITH '-502' AND NOT u.gmsa=true AND NOT u.msa=true AND u.highvalue=true RETURN u LIMIT 100",
    },
    "find_all_kerberoastable_users": {
        "description": "Find all Kerberoastable users",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true AND NOT u.objectid ENDS WITH '-502' AND NOT u.gmsa=true AND NOT u.msa=true RETURN u LIMIT 500",
    },
    "find_asreproast_users": {
        "description": "Find users vulnerable to AS-REP roasting (no pre-auth required)",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true RETURN u LIMIT 500",
    },
    "find_paths_from_kerberoastable_to_da": {
        "description": "Find paths from Kerberoastable users to Domain Admins",
        "category": "kerberos",
        "cypher": "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p=shortestPath((u)-[r*1..]->(g)) RETURN p LIMIT 1000",
    },
    # Delegation
    "find_shortest_paths_unconstrained_delegation": {
        "description": "Find paths to computers with unconstrained delegation",
        "category": "delegation",
        "cypher": "MATCH (c:Computer) WHERE c.unconstraineddelegation=true MATCH p=shortestPath((s)-[r*1..]->(c)) WHERE s<>c RETURN p LIMIT 1000",
    },
    # DCSync & Privileges
    "find_dcsync_privileges": {
        "description": "Find principals with DCSync privileges",
        "category": "privileges",
        "cypher": "MATCH p = (n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p",
    },
    "find_domain_users_local_admins": {
        "description": "Find domain users with local admin rights",
        "category": "privileges",
        "cypher": "MATCH p = (g:Group)-[:AdminTo]->(c:Computer) WHERE g.objectid ENDS WITH '-513' RETURN p",
    },
    # PKI / ADCS
    "find_pki_hierarchy": {
        "description": "Map the PKI certificate authority hierarchy",
        "category": "pki",
        "cypher": "MATCH p = ()-[:IssuedSignedBy|EnterpriseCAFor|RootCAFor|TrustedForNTAuth*1..]->(d:Domain) RETURN p",
    },
    "find_esc1_vulnerable_templates": {
        "description": "Find certificate templates vulnerable to ESC1",
        "category": "pki",
        "cypher": "MATCH (t:CertTemplate) WHERE t.enrolleesuppliessubject=true AND t.authenticationenabled=true AND t.requiresmanagerapproval=false AND t.enabled=true MATCH p = ()-[:Enroll|GenericAll|AllExtendedRights]->(t) RETURN p LIMIT 1000",
    },
    "find_esc8_vulnerable_cas": {
        "description": "Find CAs vulnerable to ESC8 (NTLM relay to HTTP enrollment)",
        "category": "pki",
        "cypher": "MATCH (ca:EnterpriseCA) WHERE ca.isuserspecifiessanenabled=true RETURN ca",
    },
    # NTLM & Network
    "find_ntlm_relay_edges": {
        "description": "Find NTLM relay attack opportunities",
        "category": "network",
        "cypher": "MATCH p = ()-[:CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToHTTP*1..]->(t) RETURN p LIMIT 1000",
    },
    "find_computers_no_smb_signing": {
        "description": "Find computers without SMB signing enabled",
        "category": "network",
        "cypher": "MATCH (c:Computer) WHERE c.signingrequired=false RETURN c LIMIT 500",
    },
    "find_computers_webclient_running": {
        "description": "Find computers running the WebClient service",
        "category": "network",
        "cypher": "MATCH (c:Computer) WHERE c.webclientrunning=true RETURN c LIMIT 500",
    },
    # Hygiene
    "find_unsupported_operating_systems": {
        "description": "Find computers running unsupported operating systems",
        "category": "hygiene",
        "cypher": "MATCH (c:Computer) WHERE c.operatingsystem =~ '.*(2000|2003|2008|XP|Vista|7 |ME|98).*' RETURN c LIMIT 500",
    },
    "find_users_password_not_rotated": {
        "description": "Find enabled users whose password hasn't been changed in over a year",
        "category": "hygiene",
        "cypher": "MATCH (u:User) WHERE u.enabled=true AND u.pwdlastset < (datetime().epochSeconds - 31536000) RETURN u LIMIT 500",
    },
    # Azure / Entra
    "find_global_administrators": {
        "description": "Find Azure/Entra Global Administrator role members",
        "category": "azure",
        "cypher": "MATCH p = (n)-[:AZHasRole|AZMemberOf*1..]->(r:AZRole) WHERE r.displayname = 'Global Administrator' RETURN p",
    },
    "find_paths_from_entra_to_tier_zero": {
        "description": "Find paths from Entra principals to on-prem tier zero",
        "category": "azure",
        "cypher": "MATCH p=shortestPath((s:AZUser)-[r*1..]->(t)) WHERE t.highvalue=true RETURN p LIMIT 1000",
    },
}

# ── Connection state ─────────────────────────────────────────────────

_graph_driver: Any | None = None
_api_token: dict | None = None
_config: dict[str, str] = {}


def _default_config() -> dict[str, str]:
    return {
        "bloodhound_url": os.environ.get("BLOODHOUND_URL", "http://localhost:8080"),
        "username": os.environ.get("BLOODHOUND_USERNAME", "admin"),
        "password": os.environ.get("BLOODHOUND_PASSWORD", ""),
        "neo4j_url": os.environ.get("NEO4J_URL", "bolt://localhost:7687"),
        "neo4j_username": os.environ.get("NEO4J_USERNAME", "neo4j"),
        "neo4j_password": os.environ.get("NEO4J_PASSWORD", "bloodhoundcommunityedition"),
        "neo4j_database": os.environ.get("NEO4J_DATABASE", "neo4j"),
    }


async def _ensure_connected() -> None:
    global _graph_driver, _api_token, _config
    if _graph_driver is not None:
        return
    if not _config:
        _config = _default_config()
    if not _config["password"]:
        raise RuntimeError(
            "Not connected. Call connect(password=...) or set BLOODHOUND_PASSWORD env var."
        )
    _graph_driver = AsyncGraphDatabase.driver(
        _config["neo4j_url"],
        auth=(_config["neo4j_username"], _config["neo4j_password"]),
    )
    # Verify Neo4j
    async with _graph_driver.session(database=_config["neo4j_database"]) as session:
        await session.run("RETURN 1")
    # Authenticate to BloodHound API
    async with aiohttp.ClientSession() as http:
        async with http.post(
            f"{_config['bloodhound_url']}/api/v2/login",
            json={"login_method": "secret", "username": _config["username"], "secret": _config["password"]},
        ) as resp:
            result = await resp.json()
    if not result or not isinstance(result.get("data"), dict):
        raise RuntimeError(f"BloodHound API auth failed: {result}")
    _api_token = result["data"]


async def _run_cypher(cypher: str, params: dict | None = None) -> list[dict]:
    await _ensure_connected()
    assert _graph_driver is not None
    records = []
    async with _graph_driver.session(database=_config["neo4j_database"]) as session:
        result = await session.run(cypher, params or {})
        async for record in result:
            records.append(dict(record))
    return records


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool
async def connect(
    bloodhound_url: Annotated[str | None, "BloodHound CE URL (e.g. http://localhost:8080)"] = None,
    username: Annotated[str | None, "BloodHound username"] = None,
    password: Annotated[str | None, "BloodHound password"] = None,
    neo4j_url: Annotated[str | None, "Neo4j bolt URL"] = None,
    neo4j_username: Annotated[str | None, "Neo4j username"] = None,
    neo4j_password: Annotated[str | None, "Neo4j password"] = None,
) -> str:
    """Connect to BloodHound CE and Neo4j. Overrides env var defaults for this session."""
    global _graph_driver, _api_token, _config
    if _graph_driver is not None:
        await _graph_driver.close()
    _graph_driver = None
    _api_token = None
    _config = _default_config()
    if bloodhound_url:
        _config["bloodhound_url"] = bloodhound_url
    if username:
        _config["username"] = username
    if password:
        _config["password"] = password
    if neo4j_url:
        _config["neo4j_url"] = neo4j_url
    if neo4j_username:
        _config["neo4j_username"] = neo4j_username
    if neo4j_password:
        _config["neo4j_password"] = neo4j_password
    await _ensure_connected()
    return f"Connected to BloodHound at {_config['bloodhound_url']} + Neo4j at {_config['neo4j_url']}"


@mcp.tool
async def query(
    cypher: Annotated[str, "Cypher query to execute against the BloodHound graph"],
    params: Annotated[dict | None, "Query parameters"] = None,
) -> list[dict]:
    """Execute an arbitrary Cypher query against the BloodHound Neo4j database."""
    return await _run_cypher(cypher, params)


@mcp.tool
async def standard_query(
    name: Annotated[str, "Name of the standard query (e.g. find_all_domain_admins)"],
) -> list[dict]:
    """Run a named standard query from the built-in catalog."""
    entry = STANDARD_QUERIES.get(name)
    if entry is None:
        available = ", ".join(sorted(STANDARD_QUERIES.keys()))
        raise ValueError(f"Unknown query '{name}'. Available: {available}")
    return await _run_cypher(entry["cypher"])


@mcp.tool
async def list_queries(
    category: Annotated[str | None, "Filter by category (e.g. kerberos, pki, tier-zero, azure)"] = None,
) -> list[dict]:
    """List available standard queries with descriptions. Optionally filter by category."""
    results = []
    for name, entry in sorted(STANDARD_QUERIES.items()):
        if category and entry["category"] != category:
            continue
        results.append({
            "name": name,
            "description": entry["description"],
            "category": entry["category"],
        })
    if not results and category:
        categories = sorted({e["category"] for e in STANDARD_QUERIES.values()})
        return [{"error": f"No queries in category '{category}'", "available_categories": categories}]
    return results


if __name__ == "__main__":
    mcp.run(transport="stdio")
```

**Note:** The standard query catalog above includes ~25 of the most useful queries from the original 76. The remaining queries follow identical patterns and can be added incrementally. The `query()` tool provides full Cypher access for anything not in the catalog.

- [ ] **Step 2: Update capability.yaml**

Add to `dreadnode/network-ops/capability.yaml`:

```yaml
mcp:
  servers:
    bloodhound:
      command: "uv"
      args: ["run", "${CAPABILITY_ROOT}/mcp/bloodhound.py"]
      init_timeout: 30
```

- [ ] **Step 3: Validate**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/network-ops/
```

- [ ] **Step 4: Delete old bloodhound Toolset**

```bash
rm dreadnode/network-ops/tools/bloodhound.py
```

Do NOT delete other tools in `network-ops/tools/` — impacket, nmap, netexec, etc. remain.

- [ ] **Step 5: Re-validate and commit**

```bash
uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate dreadnode/network-ops/
git add dreadnode/network-ops/
git commit -m "refactor(network-ops): replace BloodHound Toolset with FastMCP server

Convert 58+ BloodHound query methods to 4 MCP tools with a progressive
disclosure query catalog. Neo4j and aiohttp deps isolated via PEP 723.

- connect() tool with env var defaults for BloodHound CE + Neo4j auth
- query() for arbitrary Cypher, standard_query() for named catalog queries
- list_queries() with category filtering for progressive discovery
- Other network-ops tools (impacket, nmap, etc.) unchanged"
```

---

### Task 4: Tests for MCP Servers

Each server gets a lightweight test script using the same PEP 723 inline deps trick — no global project needed. Tests cover connection state machine, query catalog logic, truncation, and tool registration. External services are mocked.

**Files:**
- Create: `dreadnode/mythic-c2/mcp/test_server.py`
- Create: `dreadnode/sliver-c2/mcp/test_server.py`
- Create: `dreadnode/network-ops/mcp/test_bloodhound.py`

- [ ] **Step 1: Create mythic-c2 tests**

Create `dreadnode/mythic-c2/mcp/test_server.py`:

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
# ]
# ///
"""Tests for mythic MCP server — no Mythic instance required."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Import server module from adjacent file
sys.path.insert(0, str(Path(__file__).parent))
import server


class TestConnectionState:
    """Test the connect/disconnect state machine."""

    def setup_method(self):
        server._client = None
        server._config = {}

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("MYTHIC_SERVER_IP", "10.0.0.5")
        monkeypatch.setenv("MYTHIC_PASSWORD", "secret")
        cfg = server._default_config()
        assert cfg["server_ip"] == "10.0.0.5"
        assert cfg["password"] == "secret"
        assert cfg["username"] == "mythic_admin"

    def test_default_config_defaults(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_SERVER_IP", raising=False)
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        cfg = server._default_config()
        assert cfg["server_ip"] == "127.0.0.1"
        assert cfg["password"] == ""

    @pytest.mark.asyncio
    async def test_get_client_errors_without_password(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        server._config = {}
        with pytest.raises(RuntimeError, match="Not connected"):
            await server._get_client()

    @pytest.mark.asyncio
    async def test_connect_sets_config(self, monkeypatch):
        monkeypatch.delenv("MYTHIC_PASSWORD", raising=False)
        mock_login = AsyncMock(return_value="fake_client")
        with patch.object(server.mythic_sdk, "login", mock_login):
            result = await server.connect(
                server_ip="192.168.1.1", password="test123"
            )
        assert "192.168.1.1" in result
        assert server._client == "fake_client"

    @pytest.mark.asyncio
    async def test_connect_resets_previous_client(self, monkeypatch):
        server._client = "old_client"
        mock_login = AsyncMock(return_value="new_client")
        with patch.object(server.mythic_sdk, "login", mock_login):
            await server.connect(password="pw")
        assert server._client == "new_client"


class TestTruncation:
    def test_short_text_unchanged(self):
        assert server._truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (server.MAX_OUTPUT_CHARS + 100)
        result = server._truncate(text)
        assert len(result) < len(text)
        assert "truncated" in result.lower()

    def test_truncation_preserves_head_and_tail(self):
        head = "HEAD" * 100
        tail = "TAIL" * 100
        middle = "M" * (server.MAX_OUTPUT_CHARS + 1000)
        text = head + middle + tail
        result = server._truncate(text)
        assert result.startswith("HEAD")
        assert result.endswith("TAIL")


class TestToolRegistration:
    def test_expected_tools_registered(self):
        tool_names = {t.name for t in server.mcp._tool_manager.tools.values()}
        expected = {"connect", "get_callbacks", "upload_file", "check_file",
                    "download_file", "execute", "download_to_local"}
        assert expected.issubset(tool_names), f"Missing: {expected - tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

- [ ] **Step 2: Create sliver-c2 tests**

Create `dreadnode/sliver-c2/mcp/test_server.py`:

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
# ]
# ///
"""Tests for sliver MCP server — no Sliver instance required."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import server


class TestConnectionState:
    def setup_method(self):
        server._client = None
        server._interact = None
        server._interact_id = None
        server._interact_type = None

    def test_discover_config_missing_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path / "nonexistent"))
        assert server._discover_config() is None

    def test_discover_config_finds_newest(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path))
        (tmp_path / "old.cfg").write_text("old")
        (tmp_path / "new.cfg").write_text("new")
        result = server._discover_config()
        assert result is not None
        assert "new.cfg" in result

    @pytest.mark.asyncio
    async def test_get_client_errors_without_config(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SLIVER_CONFIG_FILE", raising=False)
        monkeypatch.setattr(server, "DEFAULT_CONFIG_DIR", str(tmp_path / "empty"))
        server._client = None
        with pytest.raises(RuntimeError, match="No Sliver config"):
            await server._get_client()

    @pytest.mark.asyncio
    async def test_interact_errors_without_connection(self):
        server._interact = None
        with pytest.raises(RuntimeError, match="No active implant"):
            await server._get_interact()


class TestImplantStateGating:
    """Implant tools must fail cleanly when no interact() has been called."""

    def setup_method(self):
        server._interact = None

    @pytest.mark.asyncio
    async def test_ls_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.ls()

    @pytest.mark.asyncio
    async def test_execute_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.execute(exe="/bin/ls")

    @pytest.mark.asyncio
    async def test_ps_requires_interact(self):
        with pytest.raises(RuntimeError, match="No active implant"):
            await server.ps()


class TestListenerValidation:
    @pytest.mark.asyncio
    async def test_unknown_listener_type(self):
        server._client = MagicMock()  # fake connected state
        result = await server.start_listener(listener_type="invalid")
        assert "unknown listener type" in result.lower()

    @pytest.mark.asyncio
    async def test_dns_requires_domains(self):
        server._client = MagicMock()
        result = await server.start_listener(listener_type="dns")
        assert "domains required" in result.lower()


class TestTruncation:
    def test_short_text_unchanged(self):
        assert server._truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (server.MAX_OUTPUT_CHARS + 100)
        result = server._truncate(text)
        assert "truncated" in result.lower()


class TestToolRegistration:
    def test_expected_tools_registered(self):
        tool_names = {t.name for t in server.mcp._tool_manager.tools.values()}
        expected = {"connect", "interact", "get_sessions", "get_beacons",
                    "get_jobs", "start_listener", "execute", "ls", "cd",
                    "pwd", "upload", "download", "ps", "screenshot"}
        assert expected.issubset(tool_names), f"Missing: {expected - tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

- [ ] **Step 3: Create bloodhound tests**

Create `dreadnode/network-ops/mcp/test_bloodhound.py`:

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "fastmcp>=2.0",
# ]
# ///
"""Tests for bloodhound MCP server — no Neo4j/BloodHound required."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import bloodhound as server


class TestQueryCatalog:
    """Test the standard query catalog and progressive disclosure."""

    def test_all_queries_have_required_fields(self):
        for name, entry in server.STANDARD_QUERIES.items():
            assert "description" in entry, f"{name} missing description"
            assert "category" in entry, f"{name} missing category"
            assert "cypher" in entry, f"{name} missing cypher"

    def test_all_queries_have_nonempty_cypher(self):
        for name, entry in server.STANDARD_QUERIES.items():
            assert entry["cypher"].strip(), f"{name} has empty cypher"
            assert "MATCH" in entry["cypher"] or "RETURN" in entry["cypher"], \
                f"{name} cypher doesn't look like Cypher: {entry['cypher'][:50]}"

    @pytest.mark.asyncio
    async def test_list_queries_returns_all(self):
        results = await server.list_queries()
        assert len(results) == len(server.STANDARD_QUERIES)

    @pytest.mark.asyncio
    async def test_list_queries_filter_by_category(self):
        results = await server.list_queries(category="kerberos")
        assert all(r["category"] == "kerberos" for r in results)
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_list_queries_invalid_category(self):
        results = await server.list_queries(category="nonexistent")
        assert len(results) == 1
        assert "error" in results[0]
        assert "available_categories" in results[0]

    @pytest.mark.asyncio
    async def test_standard_query_unknown_name(self):
        with pytest.raises(ValueError, match="Unknown query"):
            await server.standard_query(name="not_a_real_query")

    def test_categories_cover_expected_domains(self):
        categories = {e["category"] for e in server.STANDARD_QUERIES.values()}
        # At minimum we should have these broad categories
        assert "kerberos" in categories
        assert "tier-zero" in categories
        assert "pki" in categories


class TestConnectionState:
    def setup_method(self):
        server._graph_driver = None
        server._api_token = None
        server._config = {}

    def test_default_config_from_env(self, monkeypatch):
        monkeypatch.setenv("BLOODHOUND_URL", "http://bh:8080")
        monkeypatch.setenv("BLOODHOUND_PASSWORD", "secret")
        monkeypatch.setenv("NEO4J_URL", "bolt://neo:7687")
        cfg = server._default_config()
        assert cfg["bloodhound_url"] == "http://bh:8080"
        assert cfg["password"] == "secret"
        assert cfg["neo4j_url"] == "bolt://neo:7687"

    @pytest.mark.asyncio
    async def test_ensure_connected_errors_without_password(self, monkeypatch):
        monkeypatch.delenv("BLOODHOUND_PASSWORD", raising=False)
        with pytest.raises(RuntimeError, match="Not connected"):
            await server._ensure_connected()

    @pytest.mark.asyncio
    async def test_query_requires_connection(self, monkeypatch):
        monkeypatch.delenv("BLOODHOUND_PASSWORD", raising=False)
        server._config = {}
        with pytest.raises(RuntimeError, match="Not connected"):
            await server.query(cypher="RETURN 1")


class TestToolRegistration:
    def test_expected_tools_registered(self):
        tool_names = {t.name for t in server.mcp._tool_manager.tools.values()}
        expected = {"connect", "query", "standard_query", "list_queries"}
        assert expected == tool_names, f"Unexpected tools: {tool_names - expected}, Missing: {expected - tool_names}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

- [ ] **Step 4: Run all tests**

```bash
uv run dreadnode/mythic-c2/mcp/test_server.py
uv run dreadnode/sliver-c2/mcp/test_server.py
uv run dreadnode/network-ops/mcp/test_bloodhound.py
```

All three should pass. Fix any failures before proceeding.

- [ ] **Step 5: Commit**

```bash
git add dreadnode/mythic-c2/mcp/test_server.py dreadnode/sliver-c2/mcp/test_server.py dreadnode/network-ops/mcp/test_bloodhound.py
git commit -m "test: add unit tests for C2/BloodHound MCP servers

Per-server test scripts using PEP 723 inline deps (no global project).
Tests cover connection state machine, tool registration, query catalog
validation, input validation, and truncation edge cases."
```

---

### Task 5: Final Validation & PR

**Note:** Renumbered from Task 4 — tests are now Task 4.

- [ ] **Step 1: Full validation sweep**

```bash
for dir in dreadnode/mythic-c2/ dreadnode/sliver-c2/ dreadnode/network-ops/; do
  echo "=== $dir ===" && uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate "$dir" 2>&1
  echo
done
```

Expected: All three OK or WARN (external dep warnings acceptable — the MCP servers manage their own deps via uv).

- [ ] **Step 2: Push and create PR**

```bash
git push -u origin fix/c2-mcp-servers
gh pr create --title "refactor: convert stateful C2/network tools to MCP servers" --body "..."
```
