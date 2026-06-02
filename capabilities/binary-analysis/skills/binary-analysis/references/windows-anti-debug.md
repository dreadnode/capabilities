# Windows Anti-Debug Techniques

**This file is the short-form lookup table.** For full per-technique catalog with ATT&CK / MBC IDs, grep the Unprotect mirror first:

```bash
grep -rln "<api-name or technique>" ../external/unprotect/              # cross-platform catalog with ATT&CK / MBC IDs
```

Distilled from the [Check Point Anti-Debug Encyclopedia](https://anti-debug.checkpoint.com/) and MITRE ATT&CK [T1622](https://attack.mitre.org/techniques/T1622/). Organized by detection method with corresponding bypass strategies.

Cross-references for "what the technique looks like in code" and "how to defeat it in practice":
- **[Check Point Anti-Debug Encyclopedia](https://anti-debug.checkpoint.com/)** — canonical per-technique catalog with C + x86/x64 asm + mitigation, organized by category (debug-flags, object-handles, exceptions, timing, process-memory, assembly, interactive, misc). Fetch the relevant category page on demand.
- **[al-khaser](https://github.com/ayoubfaouzi/al-khaser)** — reference implementation of every technique below. GPL-3.0 C++ source; `git clone` to read.
- **[ScyllaHide](https://github.com/x64dbg/ScyllaHide)** — read source to learn which APIs to hook per technique.
- **[Unprotect Project](https://unprotect.it/)** — mirrored at `../external/unprotect/<technique>.md` (70 techniques covering anti-debug + packers + anti-VM).

## API-Based Checks

### IsDebuggerPresent
**Check:** `kernel32!IsDebuggerPresent()` — reads `PEB.BeingDebugged`
**Bypass:** Zero `PEB.BeingDebugged` byte, or hook API to return 0
**Qiling:** covered by `install_antidebug_bypass()` from `qiling-emulation.md`

### CheckRemoteDebuggerPresent
**Check:** `kernel32!CheckRemoteDebuggerPresent(GetCurrentProcess(), &flag)` — internally calls `NtQueryInformationProcess`
**Bypass:** Hook to set `*pbDebuggerPresent = FALSE`
**Qiling:** covered by `install_antidebug_bypass()` from `qiling-emulation.md`

### NtQueryInformationProcess
**Check:** Multiple information classes reveal debugger:
- `ProcessDebugPort` (0x07) — returns non-zero if debugged
- `ProcessDebugObjectHandle` (0x1E) — returns handle if debug object exists
- `ProcessDebugFlags` (0x1F) — returns 0 if debugged (inverse logic)

**Bypass:** Hook to return zeroed output buffer with `STATUS_SUCCESS`
**Qiling:** covered by `install_antidebug_bypass()` from `qiling-emulation.md`

### NtSetInformationThread (HideFromDebugger)
**Check:** `NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0)` — hides thread from debugger; if debugger is present, debugging events stop
**Bypass:** Hook to no-op (return success without calling real API)
**Qiling:** No-op in emulation (no debugger to hide from)

### NtQuerySystemInformation
**Check:** `SystemKernelDebuggerInformation` (0x23) — detects kernel debugger
**Bypass:** Hook to return `KdDebuggerEnabled = FALSE`

## PEB-Based Checks

### BeingDebugged (PEB+0x02)
**Check:** Direct PEB read: `mov eax, fs:[0x30]; movzx eax, byte [eax+0x02]`
**Bypass:** Zero the byte at PEB+0x02 before execution
**Qiling:** covered by `install_antidebug_bypass()` from `qiling-emulation.md`

### NtGlobalFlag (PEB+0x68 / PEB+0xBC for x64)
**Check:** When debugger is attached, `NtGlobalFlag` = `0x70` (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
**Bypass:** Zero the dword at PEB+0x68
**Qiling:** covered by `install_antidebug_bypass()` from `qiling-emulation.md`

### Heap Flags
**Check:** `PEB->ProcessHeap->Flags` and `ForceFlags` are set differently under debugger
**Bypass:** Patch heap flags to normal values (Flags=0x02, ForceFlags=0x00)

## Exception-Based Checks

### INT 2D
**Check:** `int 0x2d` — debugger notification interrupt. Under a debugger, execution continues at next instruction; without debugger, exception is raised
**Bypass:** Handle the exception in emulation
**Qiling:** Dispatched normally (no debugger to absorb it)

### INT 3 (0xCC) trap
**Check:** Insert `int 3` and check if exception handler is called
**Bypass:** Let SEH chain handle it normally

### Single-step trap (Trap Flag)
**Check:** Set trap flag via `pushf; or [esp], 0x100; popf` — if single-step exception not raised, debugger is eating the trap
**Bypass:** Ensure trap flag exception is dispatched

### VEH trick
**Check:** Register VEH, trigger exception, check if VEH was called (debugger may intercept first)
**Bypass:** Don't intercept the exception before VEH

## Timing Checks

### GetTickCount / QueryPerformanceCounter
**Check:** Measure time before/after code block; threshold indicates single-stepping
**Bypass:** Patch the comparison, or hook the timer to return consistent values
**Note:** Emulation is inherently slow — these always trip in Qiling. Must patch.

### RDTSC
**Check:** `rdtsc` instruction reads timestamp counter; delta reveals stepping
**Bypass:** Patch the comparison branch, or emulate `rdtsc` to return small deltas
**Note:** Same emulation caveat as above

## Environment Checks

### Process name scan
**Check:** `CreateToolhelp32Snapshot` + `Process32First/Next` looking for `ollydbg.exe`, `x64dbg.exe`, `ida.exe`, `ghidra`, `wireshark`
**Bypass:** Hook `Process32First/Next` to filter results

### Window name scan
**Check:** `FindWindowA/W` looking for debugger window classes (`OLLYDBG`, `WinDbgFrameClass`)
**Bypass:** Hook `FindWindowA/W` to return NULL

### Registry checks
**Check:** Check for debugger-related registry keys (e.g., `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`)
**Bypass:** Hook registry APIs to return not-found

### Hardware breakpoint detection
**Check:** `GetThreadContext` — check `Dr0`–`Dr3` debug registers for non-zero values
**Bypass:** Hook `GetThreadContext` to zero debug registers in returned context

## Bypass Strategy Summary

| Priority | Technique | Tool |
|----------|-----------|------|
| 1 | `install_antidebug_bypass(ql, arch)` then `ql.run()` | Qiling — handles the four core APIs + PEB.BeingDebugged + NtGlobalFlag (see `qiling-emulation.md`) |
| 2 | Patch timing comparisons | Ghidra decompile → identify branch → patch |
| 3 | Patch environment checks | Same as above |
| 4 | Custom hooks for exotic checks | Extend `install_antidebug_bypass` with `ql.os.set_api(...)` or use LD_PRELOAD on Linux |
| 5 | Per-technique deep dive | Grep `external/unprotect/<technique>.md` for full catalog entries; fetch from anti-debug.checkpoint.com for canonical per-category coverage |
