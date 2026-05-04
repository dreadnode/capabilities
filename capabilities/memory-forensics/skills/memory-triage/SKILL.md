---
name: memory-triage
description: Structured first-pass triage of an unknown memory image. Use when handed a .mem/.raw/.vmem/.dmp/.lime/.bin/.aff4 and asked "what happened on this box?" — establishes ground truth before any targeted hunt.
---

# Memory Triage

Implements the SANS 6-step memory triage workflow (rogue processes → DLLs/handles → network → injection → rootkit → dump). For methodology anchors and MITRE ATT&CK / D3FEND mappings, see `references/methodology.md`.

## When to Use
- First contact with an unfamiliar memory image
- Incident scoping before deep-diving (injection / credential / persistence hunts)
- Quick check for obvious compromise indicators

## Goal
Answer these in order: what OS/build, what processes, what network, what looks wrong.

## Procedure

### 1. Identify the image
Run `volatility_info` with no `os_hint` — it tries Windows / Linux / Mac in order and returns the resolved `os_kind` along with the banner. Record:
- Kernel build / Windows version
- Image acquisition timestamp (NtHeader TimeDateStamp, or system time)
- CPU architecture

All subsequent tools take `os_kind` — set it once based on this.

### 2. Process census (the single most valuable step)
Run both in succession:
- `volatility_processes` — live EPROCESS walk
- `volatility_process_scan` — pool-tag carve

**Diff them.** Entries in `process_scan` but not `processes` = hidden via DKOM or recently exited. Entries present in both but with odd parents = suspicious.

Then `volatility_process_tree` to see lineage. Red flags:
- `svchost.exe` not parented by `services.exe`
- `powershell.exe` / `cmd.exe` parented by an Office app, `wmic`, or `mshta`
- Unusual parents for `rundll32`, `regsvr32`, `mshta`
- Processes with no parent (PPID resolves to nothing)
- Double-extension or system-lookalike names (`scvhost`, `lsass ` with trailing space, `svchost32`)
- Multiple `lsass.exe` / `csrss.exe` / `winlogon.exe` instances

### 3. Command lines
`volatility_cmdlines` — read every line. Look for:
- Base64 / FromBase64String / `-enc` / `-EncodedCommand`
- `powershell.exe -nop -w hidden -exec bypass`
- IEX / DownloadString / Invoke-Expression
- LOLBins with network args (certutil -urlcache, bitsadmin /transfer, mshta http...)
- Writes to `%TEMP%`, `%APPDATA%`, `ProgramData`, `Public`

### 4. Network artifacts
`volatility_network`. Score every foreign endpoint:
- RFC1918 / loopback / multicast → usually benign
- Public IPv4 with process = `svchost`, `lsass`, `explorer` → suspicious, investigate
- Listening ports on non-standard processes → possible backdoor
- Cross-reference PIDs against the process tree anomalies above

### 5. Injection sweep
`volatility_malfind` (no `pid` filter = all processes). Any hit is high-signal:
- RWX VAD, no backing file, `MZ` header → classic injected PE
- RWX VAD, no backing file, shellcode-looking bytes → reflective loader / beacon

For each hit: note the PID, then `volatility_dll_list --pid N` to see what else is loaded, and `volatility_handles --pid N` for IPC / named-pipe clues.

### 6. Persistence glance
Quick pass before committing to a deeper persistence hunt:
- `volatility_services` — look for `Start=Auto` services with paths in user-writable dirs, random service names, or ImagePath pointing at `cmd /c`, `powershell`, `rundll32`
- `volatility_registry_hives` + `volatility_registry_key --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'`

### 7. Record findings
Summarize in a triage table: PID, process, parent, cmdline highlights, network, malfind hits, verdict (benign / suspicious / confirmed malicious). This drives the next step (a focused hunt skill).

## Heuristic Priorities
If you only have time for three things: (a) pstree + cmdlines, (b) malfind, (c) netscan cross-referenced against pstree. Those catch ~80% of commodity intrusions.

## Common Pitfalls
- Trusting `pslist` alone — always corroborate with `psscan`
- Assuming a process is benign because the name matches — check the parent and path
- Running `volatility_timeline` first — it's huge and unstructured; reach for it after you have a suspect window
