---
name: process-injection-hunt
description: Hunt for code injection in memory — classic injection, reflective loaders, process hollowing, APC injection, and thread hijacking. Use after triage flags a suspect process or when the IoC set mentions injection TTPs.
---

# Process Injection Hunt

Maps to [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) and [D3FEND D3-PCSV](https://d3fend.mitre.org/technique/d3f:ProcessCodeSegmentVerification/) (Process Code Segment Verification). Cite the relevant sub-technique in findings (T1055.001 DLL injection, .002 PE injection, .004 APC, .012 hollowing, .013 reflective loading).

## When to Use
- Triage surfaced a suspicious process (anomalous parent, unexpected network, unknown cmdline)
- Report mentions `CreateRemoteThread`, `NtMapViewOfSection`, `QueueUserAPC`, `SetThreadContext`
- You need to confirm whether a process is hosting foreign code

## What Injection Looks Like in Memory

| Technique | Signature |
|---|---|
| Classic RWX injection | VAD with PAGE_EXECUTE_READWRITE, no mapped file, MZ/shellcode contents |
| Reflective DLL load | RWX VAD with PE header but no entry in DllList — PEB unlinked |
| Process hollowing | Main module's on-disk path mismatches the mapped image; unbacked executable region at image base |
| APC / early-bird | Thread start address lands inside an RWX VAD |
| Thread hijacking | Thread's entry point is inside kernel32/ntdll, but EIP/RIP sits in an unbacked region |
| Manual mapping | Executable region backed by Pagefile.sys or no file mapping |

## Procedure

### 1. Baseline with malfind
`volatility_malfind` across all processes first, then re-run with `pid=N` for any hit to get the full dumps.

Read every hit carefully:
- **Protection** — `PAGE_EXECUTE_READWRITE` is the classic flag, but real malware often flips to `PAGE_EXECUTE_READ` after writing. A `VadS` with Protection=6 (RWX) and no file mapping is the strongest signal.
- **First bytes** — `4D 5A` (MZ), `FC E8` / `E8 00` (shellcode prologue), or `55 8B EC` / `48 89 5C 24` (function prologues without module context)
- **Size** — multi-page unbacked executable region

### 2. DLL list gap analysis
For each suspect PID: `volatility_dll_list --pid N`.
- PE found by malfind but not in DllList → reflective/manual map
- DllList entry with no file on disk (path is blank or suspicious) → unlinked/injected module
- Legitimate-looking DLL loaded from `%TEMP%`, `%APPDATA%`, `Public`, `ProgramData\<random>` → DLL sideload or drop-and-load

### 3. Process hollowing check
`volatility_run_plugin` with `windows.ldrmodules.LdrModules --pid N`.
LdrModules compares the three PEB lists (InLoad, InInit, InMem) with the VAD tree. A module present in the VAD but missing from one or more lists = unlinked / hollowed.

Also compare `EPROCESS.ImageFileName` and `EPROCESS.SeAuditProcessCreationInfo.ImageFileName` — mismatches indicate hollowing (PEB rewritten).

### 4. Thread-level inspection
`volatility_run_plugin` with `windows.threads.Threads --pid N` (or the `ethreads` plugin on some Vol3 builds).
Flag threads whose `StartAddress` or `Win32StartAddress` sits inside a VAD region identified as injected in step 1. Thread-start-address outside every loaded module = shellcode thread.

### 5. Handle and named-pipe telemetry
`volatility_handles(pid=N)`. Beacons often keep a named pipe open:
- `\Device\NamedPipe\<random>` with recognizable patterns (`msagent_`, `postex_`, `MSSE-`, Cobalt Strike defaults)
- Token handles duplicated from `lsass` → token theft
- File handles to staging paths

### 6. Extract and analyze
Confirm injection by dumping and inspecting:
```
volatility_dump_process(image, pid=N, output_dir="/tmp/dump-N", mode="vad")
```
Run strings, check PE headers, hash and submit to intel.

### 7. YARA pivot
Derived IoCs from step 6 (unique strings, import hashes, mutex names) go straight into `yara-memory-hunting` to sweep the rest of the image / other hosts.

## Cobalt Strike / Brute Ratel / Sliver Quick Checks
- Malfind hit with `\x48\x89\x5c\x24` at start → often an x64 beacon
- `volatility_yara_scan` with CS `sleep_mask` / `beacon_config` rules
- Named pipes matching `\\.\pipe\postex_*`, `\\.\pipe\msagent_*`, `\\.\pipe\status_*`
- Default Sliver: named pipe `\\.\pipe\<8-char-hex>` + `.gitignore` / `.git/objects` strings

## Common Pitfalls
- .NET processes host RWX regions legitimately (JIT) — correlate with malfind *content*, not just protection
- Browsers and Office also JIT — don't stop at the first RWX hit
- Packed legitimate software (Themida, VMProtect) triggers malfind — use DllList gap and thread-start analysis to disambiguate
