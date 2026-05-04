---
name: anti-debug-bypass
description: Defeat stock Windows anti-debug checks (IsDebuggerPresent, PEB.BeingDebugged, NtGlobalFlag, CheckRemoteDebuggerPresent, NtQueryInformationProcess, timing) using Qiling emulation so you never need to attach a debugger in the first place.
---

# Anti-Debug Bypass via Emulation

Maps to **MITRE ATT&CK [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622/)** and **MBC [B0001 Anti-Static Analysis](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/debugger-detection.md)** (Debugger Detection). For the canonical taxonomy of every check below, cite [Check Point's anti-debug encyclopedia](https://anti-debug.checkpoint.com/).

## When to Use
- `pe_info` shows imports like `IsDebuggerPresent`,
  `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`,
  `NtSetInformationThread` (ThreadHideFromDebugger), or
  `RtlAddVectoredExceptionHandler`.
- `pe_capa` tags include "check for debugger" or
  "obfuscated with trap exceptions" (capa rules emit ATT&CK T1622 and
  MBC `B0001` IDs — pass them through to the report).
- The binary prints "debugger detected" / crashes quickly under a real
  debugger.
- The challenge description says "hard to debug" — assume anti-debug
  is the point.

## Why Emulation, Not a Debugger
Two complementary lanes:

- **Live-debug lane** — [ScyllaHide](https://github.com/x64dbg/ScyllaHide) (x64dbg/IDA plugin) is the 2025 SOTA; hooks the same Nt* APIs and rewrites PEB. Use when you need to drive the program interactively.
- **Headless-emulation lane (this skill)** — Qiling emulates the Windows user-mode API itself. There is no debugger to detect, so most checks pass automatically; the few that read PEB.BeingDebugged or NtGlobalFlag get cleared before run. Use when you want scripted, repeatable, instrumentable runs (e.g., flag-hunting, unpacking loops).

Neither defeats VMProtect or Themida user-mode VMs reliably — those usually warrant a side-channel solve.

## Procedure

### 1. Identify the checks
```
pe_info                         # look at flagged_anti_debug_imports
pe_capa --summary_only          # look for ATT&CK T1622 / MBC tags
ghidra_strings --pattern="debug" # scan for strings around the checks
```
Common patterns and what bypasses each:

| Check                               | Qiling bypass                                   |
|-------------------------------------|-------------------------------------------------|
| `IsDebuggerPresent`                 | API returns 0                                   |
| `CheckRemoteDebuggerPresent`        | API sets *pbDebuggerPresent=0, returns success |
| `NtQueryInformationProcess`         | API returns STATUS_SUCCESS with cleared out     |
| `PEB.BeingDebugged` read            | Zero the byte in the emulated PEB               |
| `NtGlobalFlag` (0x70 in PEB)        | Zero four bytes in the emulated PEB             |
| `NtSetInformationThread` (HideFromDebugger) | Ignore — emulation has no debugger     |
| Int 2d / SEH-based trick            | Qiling dispatches the exception normally        |

`qiling_emulate(bypass_antidebug=True)` installs every row of the common
table in one call.

### 2. First attempt — just run it
```
qiling_emulate path=<pe> bypass_antidebug=true
```
Read `# stdout`. For simple crackmes the flag prints directly.

### 3. If it exits early — trace the APIs
```
qiling_api_trace path=<pe> bypass_antidebug=true
```
Look at `# api_log`. If you see the program calling the same anti-
debug API repeatedly and exiting, the bypass didn't cover it — pass
an explicit `apis=["<that api>", ...]` and report which one so it can
be added to the built-in bypass.

### 4. Timing checks need a different approach
`GetTickCount` / `QueryPerformanceCounter` / `rdtsc` checks work by
measuring wall-clock time across a region and bailing if it's too
long. Emulation is slow, so these trip falsely. Two options:

- **Patch the API** to return a monotonically incrementing tiny delta
  (write a custom hook for GetTickCount that returns a counter
  incrementing by 1 each call).
- **Decompile and patch the branch** — use `ghidra_decompile` on the
  function containing the `ja/jb` after the `sub`, note the target,
  then write a Qiling code hook that skips the branch.

### 5. Capture the answer
Once the binary runs to completion, the flag is usually inside a
string comparison. Follow up with the flag-hunting skill.

## Tip
If Qiling's rootfs is missing a DLL the binary needs (e.g. a late-load
crypto library), the emulation error message names it. Drop the DLL
into `$QILING_ROOTFS/x86_windows/Windows/System32/` and retry — the
rootfs is just a directory.
