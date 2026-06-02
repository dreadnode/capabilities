# Linux Anti-Debug Techniques

**This file is the short-form lookup.** For full per-technique detail, grep the local mirror:

```bash
grep -rln "<technique or syscall>" ../external/unprotect/   # cross-platform catalog (sysctl, ptrace, /proc, signal-based)
```

Common anti-debug and anti-analysis checks in Linux ELF binaries, with bypass strategies.

No Check Point–style canonical catalog exists for Linux. Closest references: [al-khaser](https://github.com/ayoubfaouzi/al-khaser) (Linux portions; GPL-3.0, `git clone` to read), and [Unprotect Project](https://unprotect.it/category/anti-debugging/) techniques (mirrored at `../external/unprotect/` — see `kernel-flag-inspection-via-sysctl.md`, `manipulating-debug-logs.md`, `clearing-kernel-message.md`, `deleting-troubleshoot-information-and-core-dumps.md`). Maps to MITRE ATT&CK [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622/). If you encounter a check not covered below, flag the gap — the corpus is genuinely thinner than Windows.

## ptrace-Based

### PTRACE_TRACEME self-attach
**Check:** `ptrace(PTRACE_TRACEME, 0, 0, 0)` — if already being traced (debugger attached), returns -1
```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    exit(1);  // debugger detected
}
```
**Bypass options:**
1. LD_PRELOAD a library that hooks `ptrace` to return 0
2. Patch the `ptrace` call to `nop` or patch the conditional branch
3. `strace -e inject=ptrace:retval=0` (inject return value)

**LD_PRELOAD hook:**
```c
// anti_ptrace.c — compile with: gcc -shared -o anti_ptrace.so anti_ptrace.c
#include <sys/ptrace.h>
long ptrace(int request, ...) { return 0; }
```
```bash
LD_PRELOAD=./anti_ptrace.so ./target
```

### Double ptrace check
**Check:** Call `ptrace(PTRACE_TRACEME)` twice — first succeeds, second fails (since you're now self-traced). If second succeeds, someone detached you.
**Bypass:** Same as above — hook `ptrace` to always return 0

## /proc Filesystem Checks

### TracerPid
**Check:** Read `/proc/self/status` and parse `TracerPid:` field — non-zero means a debugger is attached
```c
FILE *f = fopen("/proc/self/status", "r");
// parse for "TracerPid:\t0" vs "TracerPid:\t<pid>"
```
**Bypass options:**
1. Hook `open`/`fopen` via LD_PRELOAD to return a fake `/proc/self/status`
2. Patch the comparison to always take the "not debugged" branch
3. Use a mount namespace to shadow `/proc/self/status`

### /proc/self/exe link check
**Check:** `readlink("/proc/self/exe")` and compare against expected path — detects if running under a different name or from a debugger's temp directory
**Bypass:** Patch the comparison or hook `readlink`

### /proc/self/maps inspection
**Check:** Read memory maps looking for debugger-related shared libraries or suspicious regions
**Bypass:** Hook file reads or patch the check

### /proc/self/cmdline
**Check:** Read cmdline to detect if launched with `gdb`, `strace`, etc. as parent
**Bypass:** Hook or patch

## Timing Checks

### clock_gettime / gettimeofday
**Check:** Measure wall-clock time around a code block; threshold detects single-stepping
```c
struct timespec t1, t2;
clock_gettime(CLOCK_MONOTONIC, &t1);
// ... sensitive code ...
clock_gettime(CLOCK_MONOTONIC, &t2);
if (t2.tv_nsec - t1.tv_nsec > THRESHOLD) exit(1);
```
**Bypass:** Patch the comparison, or LD_PRELOAD a hook returning consistent times

### RDTSC (x86 inline assembly)
**Check:** Same as Windows — `rdtsc` delta check
**Bypass:** Patch the branch

## Signal-Based

### SIGTRAP handler
**Check:** Install a `SIGTRAP` handler, then execute `int 3`. Under a debugger, the debugger catches it; without a debugger, the signal handler runs and sets a flag.
```c
volatile int flag = 0;
void handler(int sig) { flag = 1; }
signal(SIGTRAP, handler);
__asm__("int3");
if (!flag) exit(1);  // debugger ate our SIGTRAP
```
**Bypass:** Configure debugger to pass SIGTRAP to the program, or patch the check

### SIGALRM timeout
**Check:** Set an alarm; if code takes too long (single-stepping), SIGALRM kills the process
**Bypass:** Hook `alarm()` to no-op, or patch the signal handler

## Environment Checks

### Parent process inspection
**Check:** Read `/proc/self/status` for `PPid:`, then check `/proc/<ppid>/comm` for `gdb`, `strace`, `ltrace`
**Bypass:** Hook file reads or reparent

### LD_PRELOAD detection
**Check:** Read `/proc/self/environ` or check `getenv("LD_PRELOAD")` — detects the very technique used for bypasses
**Bypass:** Hook `getenv` to hide `LD_PRELOAD`, or use a different injection method (ptrace inject, `LD_AUDIT`)

### Executable integrity
**Check:** Hash own executable (`/proc/self/exe`) and compare against expected — detects patching
**Bypass:** Ensure patches don't change the on-disk binary (use runtime patching), or patch the hash check

## Bypass Strategy Summary

| Priority | Technique | Method |
|----------|-----------|--------|
| 1 | LD_PRELOAD ptrace/timing hooks | Fast, non-invasive |
| 2 | Binary patching (nop/invert branches) | Ghidra decompile → identify → patch |
| 3 | strace return value injection | `strace -e inject=ptrace:retval=0` |
| 4 | GDB scripting | `catch syscall ptrace` + modify return |
| 5 | Kernel module / seccomp | Heavy — last resort |
