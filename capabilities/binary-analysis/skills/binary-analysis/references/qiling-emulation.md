# Qiling Emulation Reference

Qiling is a Python emulator built on Unicorn that ships user-space OS shims (Windows / Linux / macOS / Android / RTOSes) so binaries can be run on a host of a different OS. The library is the right tool when:

- The target needs to *execute* to reveal what you're after (runtime-constructed strings, comparison-site values, IAT reconstruction at OEP)
- You can't (or don't want to) attach a debugger on the target OS
- Static analysis got you to "this function decrypts the flag" but reimplementing the algorithm in Python is more work than just running it

If static analysis can answer the question, do that first. Emulation is slower, has rootfs setup cost, and the agent must write code each time.

## Why this is a reference, not an MCP tool

Wrapping Qiling as an MCP with one-shot tools (e.g. `qiling_emulate`, `qiling_dump_at_api`, `qiling_api_trace`, each taking `bypass_antidebug=True/False`) is convenient for the common case but pins the surface: any non-default analysis (a custom hook for a packer-specific IAT rebuild, a syscall-level intercept for a Linux unpacker, a code-hook that skips a timing check) needs new tool plumbing.

Qiling is a general-purpose emulator; the value is in *what you hook*, and that varies per binary. Wrapping a fixed slice of it as MCP tools constrains what the agent can analyze to whatever the wrapper exposes. Instead, this capability ships verified Python templates below — `install_antidebug_bypass`, `install_api_logger`, `install_dump_at_api`, end-to-end `emulate()` — that the agent copies into a `/tmp/emulate.py` script and adapts as needed. Same applies to angr; see `symbolic-execution.md`.

Decision rule: stored value at a known compare site → use `install_dump_at_api` verbatim. Anything else → adapt the templates to the binary.

## Setup

Qiling requires a rootfs (per-arch DLL/shim directory). It is **not bundled** — populate once with:

```bash
git clone --depth=1 https://github.com/qilingframework/rootfs.git ~/.qiling/rootfs
# Or set QILING_ROOTFS to point at an existing rootfs directory.
```

The `qilingframework/rootfs` repo is ~169 MB and carries no LICENSE file; it lives outside the capability for that reason. Install the rootfs once per host; the cache persists.

Quick presence check:
```python
from pathlib import Path
import os
root = Path(os.environ.get("QILING_ROOTFS", str(Path.home() / ".qiling" / "rootfs")))
print({d.name: (root / d.name).is_dir() for d in root.iterdir()} if root.exists() else "missing")
```

Or shell:
```bash
ls ${QILING_ROOTFS:-$HOME/.qiling/rootfs}/
```

If the rootfs is missing, surface the `git clone` command to the user and ask before fetching it (~169 MB download).

## The basic emulation pattern

```python
import io
from qiling import Qiling
from qiling.const import QL_VERBOSE

stdout = io.StringIO()
class _StdOut:
    def write(self, s):
        stdout.write(s.decode(errors="replace") if isinstance(s, bytes) else s)
        return len(s)
    def flush(self): pass

ql = Qiling([str(binary_path)], str(rootfs_path), verbose=QL_VERBOSE.OFF)
ql.os.stdout = _StdOut()
ql.os.stderr = _StdOut()

# ... install hooks here ...

ql.run(timeout=30_000_000)   # microseconds
print(stdout.getvalue())
```

Pick `rootfs_path` from the qilingframework/rootfs subdirs based on the target:
- Windows PE x86 → `x86_windows`
- Windows PE x64 → `x8664_windows`
- Linux ELF x86 → `x86_linux`
- Linux ELF x64 → `x8664_linux`
- Linux ELF ARM → `arm_linux`
- Linux ELF ARM64 → `arm64_linux`
- Linux ELF MIPS / MIPSEL → `mips32_linux` / `mips32el_linux`
- Linux ELF PowerPC → `powerpc_linux`
- macOS Mach-O → currently no rootfs subdir; Qiling's macOS support is partial

Auto-detect arch by reading the binary's format header:

```python
def detect_arch(path):
    with open(path, "rb") as f:
        head = f.read(0x40)
    if head[:2] == b"MZ":                              # PE
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        with open(path, "rb") as f:
            f.seek(e_lfanew + 4)
            machine = int.from_bytes(f.read(2), "little")
        return "x8664_windows" if machine == 0x8664 else "x86_windows"
    if head[:4] == b"\x7fELF":                         # ELF
        bits = "x8664" if head[4] == 2 else "x86"
        # EM_MACHINE at offset 18 — see ELF gABI for the full table
        # 0x3E = AMD64, 0x03 = i386, 0x28 = ARM, 0xB7 = AArch64, 0x08 = MIPS, ...
        return f"{bits}_linux"  # adjust for actual EM_MACHINE
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):  # Mach-O (LE/BE)
        return None   # Qiling macOS support is incomplete
    raise ValueError(f"unknown binary format at {path}")
```

## Anti-debug bypass — Windows PE

The standard bypass neutralizes the four most common API checks plus the two PEB-resident flags. Drop this `install_antidebug_bypass()` next to the emulation pattern above and call it after constructing `ql`, before `ql.run()`.

**What it does:**
- Hooks `IsDebuggerPresent` → return 0
- Hooks `CheckRemoteDebuggerPresent` → write 0 to the out-param, return 1
- Hooks `NtQueryInformationProcess` + `ZwQueryInformationProcess` → STATUS_SUCCESS with cleared output buffer
- Writes 0 to `PEB.BeingDebugged` (PEB+2, 1 byte)
- Writes 0 to `NtGlobalFlag` (PEB+0x68 on x86, PEB+0xBC on x64, 4 bytes)

**Code:**

```python
from qiling.const import QL_INTERCEPT

def install_antidebug_bypass(ql, arch):
    """Neutralize the four most common Win32 anti-debug checks + PEB flags.

    arch: 'x86' or 'x8664'. NtGlobalFlag offset is arch-dependent.
    """
    api_log = []

    def _is_debugger_present(_ql, _addr, _params):
        api_log.append("BYPASS IsDebuggerPresent -> 0")
        return 0

    def _check_remote(ql_inner, _addr, params):
        # The hook replaces the API entirely, so write the out-param ourselves.
        # Qiling decodes Win32 prototypes into a dict keyed by parameter name;
        # fall back to positional indexing if the decode shape changes.
        out_ptr = None
        try:
            if isinstance(params, dict):
                out_ptr = params.get("pbDebuggerPresent")
            elif params and len(params) >= 2:
                out_ptr = int(params[1])
        except Exception:
            out_ptr = None
        if isinstance(out_ptr, int) and out_ptr:
            ql_inner.mem.write(out_ptr, b"\x00\x00\x00\x00")
        api_log.append("BYPASS CheckRemoteDebuggerPresent -> *pbDebuggerPresent=0, return 1")
        return 1

    def _nt_query_info(_ql, _addr, _params):
        api_log.append("BYPASS NtQueryInformationProcess -> STATUS_SUCCESS (cleared)")
        return 0

    for name, hook in [
        ("IsDebuggerPresent", _is_debugger_present),
        ("CheckRemoteDebuggerPresent", _check_remote),
        ("NtQueryInformationProcess", _nt_query_info),
        ("ZwQueryInformationProcess", _nt_query_info),
    ]:
        try:
            ql.os.set_api(name, hook, QL_INTERCEPT.CALL)
        except Exception as e:
            api_log.append(f"FAIL {name}: {e}")

    peb = getattr(ql.loader, "peb_address", None)
    if peb is not None:
        ql.mem.write(peb + 2, b"\x00")                        # BeingDebugged
        ng_offset = 0xBC if arch == "x8664" else 0x68         # NtGlobalFlag
        ql.mem.write(peb + ng_offset, b"\x00\x00\x00\x00")
        api_log.append(f"BYPASS PEB.BeingDebugged + NtGlobalFlag @0x{ng_offset:x}")
    else:
        api_log.append("SKIP PEB: ql.loader.peb_address unavailable")

    return api_log
```

**Why these specific facts:**

| Fact | Why |
|---|---|
| 4 APIs hooked | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `Nt+ZwQueryInformationProcess` cover ~90% of casual anti-debug. The Nt/Zw pair is the same routine; Windows exports both names so packers call whichever convention they prefer. |
| `CheckRemoteDebuggerPresent` out-param convention | This API takes `(HANDLE, PBOOL pbDebuggerPresent)` and writes the result through the pointer. When you replace the implementation entirely, you must write the out-param yourself; returning 1 only sets the success/failure boolean. |
| `PEB.BeingDebugged` at `+2` | Documented at byte offset 2 in `_PEB`. 1-byte write; not a DWORD. |
| `NtGlobalFlag` at `0x68` (x86) / `0xBC` (x64) | Documented in `_PEB`. 4-byte DWORD. Debugger-attached value is `0x70`; we write all zeros. |

**What this bypass does NOT cover** — for these, decompile and patch the branch, or extend the bypass:
- Timing checks (`GetTickCount`, `QueryPerformanceCounter`, `rdtsc`) — emulation is slow, these always trip falsely
- Environment scans (`CreateToolhelp32Snapshot` walking for `ollydbg.exe`, `FindWindowA` for `OLLYDBG`)
- Hardware breakpoint detection (`GetThreadContext` reading `Dr0-Dr3`)
- Heap flags (`PEB->ProcessHeap->Flags / ForceFlags`)
- INT 2D, INT 3, single-step trap tricks
- VEH-based detection

See `windows-anti-debug.md` for the per-technique table covering all of these.

## Anti-debug bypass — Linux ELF (gap)

There is no canonical bypass installer for Linux because the technique surface is different: ptrace syscall hooks, `/proc/self/status` file reads, signal-based traps, parent-process inspection. Most bypasses are LD_PRELOAD or binary-patch shaped rather than emulation-shaped.

Within Qiling, `ql.os.set_syscall("ptrace", hook)` can intercept the ptrace syscall, and file reads can be redirected by hooking `open`/`openat`. The per-technique table is in `linux-anti-debug.md`; the practical bypass for most ELF targets is LD_PRELOAD on the host, not emulation.

Cite [Unprotect Project's Linux-relevant techniques](https://unprotect.it/category/anti-debugging/) (mirrored at `external/unprotect/`) and [al-khaser's Linux portions](https://github.com/ayoubfaouzi/al-khaser) for the technique corpus.

## Anti-debug bypass — macOS Mach-O (gap)

Qiling's macOS emulation is partial — no rootfs subdir in `qilingframework/rootfs`. For Mach-O anti-debug bypass, the practical approaches are decompile-and-patch (Ghidra) or runtime entitlement workarounds on a macOS host. Per-technique guidance: [Objective-See](https://objective-see.org/blog.html) and [TAOMM](https://taomm.org/).

## API tracing

Log every call to a set of Win32 APIs during emulation. Useful for identifying which comparison API the binary is calling (so you know where to dump-at-API), and for tracing IAT-reconstruction sequences in custom loaders.

```python
from qiling.const import QL_INTERCEPT

DEFAULT_TRACE_APIS = [
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
    "VirtualAlloc", "VirtualProtect",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "strcmp", "wcscmp", "lstrcmpA", "lstrcmpW",
    "MessageBoxA", "MessageBoxW", "OutputDebugStringA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
]

def install_api_logger(ql, api_log, names=None):
    targets = names or DEFAULT_TRACE_APIS
    for name in targets:
        def _maker(api):
            def _hook(_ql, _addr, params):
                api_log.append(f"CALL {api}({params})")
            return _hook
        try:
            ql.os.set_api(name, _maker(name), QL_INTERCEPT.ENTER)
        except Exception as e:
            api_log.append(f"FAIL trace {name}: {e}")
```

`QL_INTERCEPT.ENTER` runs the hook *and* the underlying API; `QL_INTERCEPT.CALL` replaces the API entirely. Use ENTER for logging, CALL for bypass.

## Dump-at-API (the comparison-site primitive)

For PE binaries that validate input against a protected value, the value usually ends up as an argument to a string-compare function (`strcmp`, `wcscmp`, `lstrcmpA`, `memcmp`) at validation time. Break on that API and read the buffer the parameter points at — that's the expected value, without needing a debugger or to patch the binary.

```python
from qiling.const import QL_INTERCEPT

def install_dump_at_api(ql, api, param_index, length, dumps):
    """When `api` is called, dump `length` bytes from the buffer pointed
    to by `params[param_index]`.

    Common patterns:
      - api='strcmp',   param_index=1  → expected value (param 0 is user input)
      - api='wcscmp',   param_index=1  → expected wide value
      - api='memcmp',   param_index=1  → expected buffer (length is in param 2)
      - api='lstrcmpA', param_index=1  → expected value
    """
    def _on_call(ql_inner, _addr, params):
        try:
            values = list(params.values()) if isinstance(params, dict) else list(params)
            if param_index >= len(values):
                dumps.append(f"{api}: param index {param_index} out of range")
                return
            ptr = int(values[param_index])
            raw = ql_inner.mem.read(ptr, length)
            printable = bytes(raw).split(b"\x00", 1)[0].decode(errors="replace")
            dumps.append(f"{api}[{param_index}] @ 0x{ptr:x}: {bytes(raw).hex()}  ({printable!r})")
        except Exception as e:
            dumps.append(f"{api}: dump failed: {e}")
    ql.os.set_api(api, _on_call, QL_INTERCEPT.ENTER)
```

**Usage:**

```python
dumps = []
install_dump_at_api(ql, api="strcmp", param_index=1, length=128, dumps=dumps)
install_antidebug_bypass(ql, arch="x86")
ql.run(timeout=30_000_000)
for line in dumps:
    print(line)
```

Try `param_index=0` and `param_index=1` separately — whichever is *not* your input is the target artifact. For `memcmp`, the comparison length is in `param_index=2` and the two buffers are at indices 0 and 1.

## Combined: end-to-end emulate with bypass + trace + dump

```python
import io
from pathlib import Path
from qiling import Qiling
from qiling.const import QL_VERBOSE

# ... copy detect_arch, install_antidebug_bypass, install_dump_at_api from above ...

def emulate(binary_path, dump_api="strcmp", dump_param=1, dump_len=128, timeout_us=30_000_000):
    rootfs_key = detect_arch(binary_path)
    rootfs = Path.home() / ".qiling" / "rootfs" / rootfs_key
    if not rootfs.exists():
        raise FileNotFoundError(
            f"Rootfs missing at {rootfs}.\n"
            f"Populate with: git clone --depth=1 https://github.com/qilingframework/rootfs.git ~/.qiling/rootfs"
        )

    stdout = io.StringIO()
    class _StdOut:
        def write(self, s):
            stdout.write(s.decode(errors="replace") if isinstance(s, bytes) else s)
            return len(s)
        def flush(self): pass

    ql = Qiling([str(binary_path)], str(rootfs), verbose=QL_VERBOSE.OFF)
    ql.os.stdout = _StdOut()
    ql.os.stderr = _StdOut()

    arch = "x8664" if rootfs_key == "x8664_windows" else "x86"
    api_log = install_antidebug_bypass(ql, arch)
    dumps = []
    install_dump_at_api(ql, api=dump_api, param_index=dump_param, length=dump_len, dumps=dumps)

    try:
        ql.run(timeout=timeout_us)
    except Exception as e:
        api_log.append(f"EMULATION ERROR: {type(e).__name__}: {e}")

    return {
        "stdout": stdout.getvalue(),
        "dumps": dumps,
        "api_log": api_log,
    }

if __name__ == "__main__":
    import sys, json
    result = emulate(sys.argv[1])
    print(json.dumps(result, indent=2))
```

Drop into a file (`/tmp/emulate.py`), run with `python /tmp/emulate.py /path/to/sample.exe`. Adjust `dump_api` / `dump_param` based on what the decompilation showed is the comparison site.

## Common errors

| Error | Cause | Fix |
|---|---|---|
| `Rootfs missing at ...` | First-time setup not done | `git clone --depth=1 https://github.com/qilingframework/rootfs.git ~/.qiling/rootfs` |
| `Cannot find <DLL>` | Rootfs is missing a specific Windows DLL the target imports | Drop the DLL into `$QILING_ROOTFS/x86_windows/Windows/System32/` and retry |
| `failed to install ENTER hook for <api>` | Qiling doesn't ship a prototype for that API name | Try a sibling name (`lstrcmpA` vs `strcmp`), or attach `install_api_logger` first to see which API names Qiling actually dispatches |
| Emulation hangs / times out | Real anti-emulation (timing, exotic checks), or an infinite loop in legitimate code | Increase `timeout_us`; if still hangs, decompile to find the offending loop and patch or skip |
| `IsDebuggerPresent` not called but binary still exits | Direct PEB reads bypass the API hooks — make sure the PEB writes (BeingDebugged + NtGlobalFlag) ran successfully | Check `api_log` for "BYPASS PEB" line; if absent, `ql.loader.peb_address` was None |
