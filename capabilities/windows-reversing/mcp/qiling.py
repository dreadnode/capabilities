#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "qiling>=1.4.6",
#   "unicorn>=2.0.1",
#   "capstone>=5.0.1",
#   "keystone-engine>=0.9.2",
# ]
# ///
"""Qiling PE-emulation MCP.

Emulate Windows PE binaries on macOS or Linux without a Windows host.
Qiling runs on Unicorn + a user-space Windows DLL shim so common HTB-
style anti-debug checks (IsDebuggerPresent, PEB.BeingDebugged,
NtGlobalFlag, CheckRemoteDebuggerPresent, NtQueryInformationProcess)
can be bypassed by hooking the API rather than patching the binary.

The Qiling rootfs (Windows DLLs + registry) is required for emulation.
It is NOT bundled here — point QILING_ROOTFS at a directory you have
populated via Qiling's `examples/rootfs/x86_windows` or the
`qltool setup` helper. qiling_status reports what the MCP can see.

Tools:

  * qiling_status        — rootfs / arch availability
  * qiling_emulate       — run a PE end-to-end; pass bypass_antidebug=True
                           to neutralize common anti-debug APIs
  * qiling_api_trace     — run and log every Win32 API call
  * qiling_dump_at_api   — break on an API call, dump a buffer pointed
                           at by a parameter (e.g. strcmp lpString1 → flag)

All tools take a 32/64-bit hint; if omitted, the PE's IMAGE_FILE_HEADER
Machine field is used to pick the rootfs.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from fastmcp import FastMCP

mcp = FastMCP("qiling")

MAX_OUTPUT_CHARS = int(os.environ.get("QILING_MAX_OUTPUT_CHARS", "100000"))
DEFAULT_TIMEOUT_US = int(os.environ.get("QILING_TIMEOUT_US", str(30 * 1_000_000)))
DEFAULT_ROOTFS = Path(
    os.environ.get("QILING_ROOTFS", str(Path.home() / ".qiling" / "rootfs"))
)

Arch = Literal["x86", "x8664", "auto"]


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _detect_arch(path: Path) -> str:
    """Peek at IMAGE_FILE_HEADER.Machine to pick x86 vs x86_64."""
    with path.open("rb") as f:
        data = f.read(0x200)
    if data[:2] != b"MZ":
        raise ValueError(f"not a PE file: {path}")
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    machine = int.from_bytes(data[e_lfanew + 4 : e_lfanew + 6], "little")
    return "x8664" if machine == 0x8664 else "x86"


def _rootfs_for(arch: str) -> Path:
    sub = "x8664_windows" if arch == "x8664" else "x86_windows"
    return DEFAULT_ROOTFS / sub


def _missing_rootfs_message(arch: str) -> str:
    target = _rootfs_for(arch)
    return (
        f"Error: Qiling rootfs not found at {target}.\n"
        "Populate it by cloning https://github.com/qilingframework/qiling\n"
        "and copying examples/rootfs/{x86_windows,x8664_windows} to\n"
        f"{DEFAULT_ROOTFS}, or set QILING_ROOTFS to an existing rootfs.\n"
        "The rootfs bundles user-mode Windows DLLs required for emulation.\n"
        "Qiling itself is installed in this MCP's uv venv."
    )


def _resolve(path: str, arch_hint: Arch) -> tuple[Path, str, Path]:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"file does not exist: {p}")
    arch = _detect_arch(p) if arch_hint == "auto" else arch_hint
    rootfs = _rootfs_for(arch)
    return p, arch, rootfs


# ── tools ────────────────────────────────────────────────────────────


@mcp.tool
async def qiling_status() -> dict[str, Any]:
    """Check Qiling importability and rootfs availability for x86 and x86_64."""
    try:
        import qiling  # noqa: F401

        qiling_ok: Any = True
    except Exception as e:
        qiling_ok = f"unavailable: {e}"
    return {
        "platform": sys.platform,
        "qiling": qiling_ok,
        "rootfs_root": str(DEFAULT_ROOTFS),
        "x86_rootfs_present": _rootfs_for("x86").exists(),
        "x8664_rootfs_present": _rootfs_for("x8664").exists(),
        "timeout_us": DEFAULT_TIMEOUT_US,
        "hint": (
            None
            if _rootfs_for("x86").exists() or _rootfs_for("x8664").exists()
            else _missing_rootfs_message("x86")
        ),
    }


def _new_ql(path: Path, rootfs: Path, stdout_buf: io.StringIO) -> Any:
    """Construct a Qiling instance that writes emulated stdout to stdout_buf."""
    from qiling import Qiling
    from qiling.const import QL_VERBOSE

    class _StdOut:
        def write(self, s: str | bytes) -> int:
            if isinstance(s, bytes):
                s = s.decode(errors="replace")
            stdout_buf.write(s)
            return len(s)

        def flush(self) -> None:
            pass

    ql = Qiling([str(path)], str(rootfs), verbose=QL_VERBOSE.OFF)
    ql.os.stdout = _StdOut()
    ql.os.stderr = _StdOut()
    return ql


def _install_antidebug_bypass(ql: Any, arch: str, api_log: list[str]) -> dict[str, str]:
    """Replace common anti-debug APIs with 'no debugger present' answers.

    Returns a per-hook status map so callers (and pe_triage_status-style
    diagnostics) can surface installation failures rather than silently
    no-op'ing them.
    """
    from qiling.const import QL_INTERCEPT

    def _is_debugger_present(_ql: Any, _address: int, _params: Any) -> int:
        api_log.append("BYPASS IsDebuggerPresent -> 0")
        return 0

    def _check_remote(ql_inner: Any, _address: int, params: Any) -> int:
        api_log.append(
            "BYPASS CheckRemoteDebuggerPresent -> *pbDebuggerPresent=0, return 1"
        )
        # The hook replaces the API entirely, so we must write the out-param
        # ourselves. Qiling decodes Win32 prototypes into a dict whose keys
        # match parameter names; fall back to positional indexing.
        out_ptr: int | None = None
        try:
            if isinstance(params, dict):
                out_ptr = params.get("pbDebuggerPresent")
            elif params and len(params) >= 2:
                out_ptr = int(params[1])
        except Exception:
            out_ptr = None
        if isinstance(out_ptr, int) and out_ptr:
            ql_inner.mem.write(out_ptr, b"\x00\x00\x00\x00")
        return 1

    def _nt_query_info(_ql: Any, _address: int, _params: Any) -> int:
        api_log.append("BYPASS NtQueryInformationProcess -> STATUS_SUCCESS (cleared)")
        return 0

    statuses: dict[str, str] = {}
    hook_table: list[tuple[str, Any]] = [
        ("IsDebuggerPresent", _is_debugger_present),
        ("CheckRemoteDebuggerPresent", _check_remote),
        ("NtQueryInformationProcess", _nt_query_info),
        ("ZwQueryInformationProcess", _nt_query_info),
    ]
    for name, hook in hook_table:
        try:
            ql.os.set_api(name, hook, QL_INTERCEPT.CALL)
            statuses[name] = "installed"
        except Exception as e:
            statuses[name] = f"failed: {e}"

    peb = getattr(ql.loader, "peb_address", None)
    if peb is None:
        statuses["peb"] = "skipped: ql.loader.peb_address unavailable"
    else:
        try:
            ql.mem.write(peb + 2, b"\x00")  # BeingDebugged byte
            # NtGlobalFlag lives at PEB+0x68 (x86) and PEB+0xBC (x64).
            ng_offset = 0xBC if arch == "x8664" else 0x68
            ql.mem.write(peb + ng_offset, b"\x00\x00\x00\x00")
            statuses["peb"] = (
                f"BeingDebugged + NtGlobalFlag (offset 0x{ng_offset:x}) cleared"
            )
        except Exception as e:
            statuses["peb"] = f"failed: {e}"

    return statuses


_DEFAULT_TRACE_APIS = (
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "VirtualAlloc",
    "VirtualProtect",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "strcmp",
    "wcscmp",
    "lstrcmpA",
    "lstrcmpW",
    "MessageBoxA",
    "MessageBoxW",
    "OutputDebugStringA",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
)


def _install_api_logger(
    ql: Any,
    api_log: list[str],
    names: list[str] | None,
) -> dict[str, str]:
    """Install ENTER hooks logging each call. Returns per-API install status."""
    from qiling.const import QL_INTERCEPT

    targets = list(names) if names else list(_DEFAULT_TRACE_APIS)
    statuses: dict[str, str] = {}
    for name in targets:

        def _maker(api: str) -> Any:
            def _hook(_ql: Any, _address: int, params: Any) -> None:
                api_log.append(f"CALL {api}({params})")

            return _hook

        try:
            ql.os.set_api(name, _maker(name), QL_INTERCEPT.ENTER)
            statuses[name] = "installed"
        except Exception as e:
            statuses[name] = f"failed: {e}"
    return statuses


def _run_ql(ql: Any, timeout_us: int) -> str | None:
    try:
        ql.run(timeout=timeout_us)
        return None
    except Exception as e:
        return f"emulation error: {type(e).__name__}: {e}"


def _new_ql_or_raise(path: Path, rootfs: Path, stdout_buf: io.StringIO) -> Any:
    try:
        return _new_ql(path, rootfs, stdout_buf)
    except Exception as e:
        raise RuntimeError(f"failed to construct Qiling instance: {e}") from e


def _format_install_status(label: str, statuses: dict[str, str]) -> list[str]:
    failed = [
        f"{name}: {status}"
        for name, status in statuses.items()
        if not status.startswith("installed") and not status.startswith("Being")
    ]
    if not failed:
        return []
    return [f"# {label}_install_failures", *failed]


@mcp.tool
async def qiling_emulate(
    path: Annotated[str, "Path to the PE"],
    arch: Annotated[Arch, "x86 | x8664 | auto"] = "auto",
    bypass_antidebug: Annotated[
        bool, "Install the common anti-debug bypass before running"
    ] = False,
    timeout_us: Annotated[
        int, "Emulation timeout in microseconds"
    ] = DEFAULT_TIMEOUT_US,
) -> str:
    """Emulate the PE end-to-end and return its stdout.

    For pure CLI crackmes this often produces the flag directly. For
    binaries with stock anti-debug (IsDebuggerPresent, PEB.BeingDebugged,
    NtQueryInformationProcess, ZwQueryInformationProcess, NtGlobalFlag),
    pass `bypass_antidebug=True` to neutralize them before the run.
    """
    p, a, rootfs = _resolve(path, arch)
    if not rootfs.exists():
        raise FileNotFoundError(_missing_rootfs_message(a))

    stdout_buf = io.StringIO()
    ql = _new_ql_or_raise(p, rootfs, stdout_buf)

    api_log: list[str] = []
    bypass_status: dict[str, str] = {}
    if bypass_antidebug:
        bypass_status = _install_antidebug_bypass(ql, a, api_log)

    err = _run_ql(ql, timeout_us)
    result = ["# stdout", stdout_buf.getvalue()]
    if api_log:
        result.extend(["", "# api_log", *api_log])
    result.extend(_format_install_status("antidebug", bypass_status))
    if err:
        result.extend(["", "# emulation", err])
    return _truncate("\n".join(result))


@mcp.tool
async def qiling_api_trace(
    path: Annotated[str, "Path to the PE"],
    arch: Annotated[Arch, "x86 | x8664 | auto"] = "auto",
    apis: Annotated[
        list[str] | None,
        "API names to log (None = a sensible default set)",
    ] = None,
    bypass_antidebug: Annotated[bool, "Also install the anti-debug bypass"] = True,
    timeout_us: Annotated[
        int, "Emulation timeout in microseconds"
    ] = DEFAULT_TIMEOUT_US,
) -> str:
    """Log every call to the given Win32 APIs during emulation.

    Pass `apis=["strcmp","wcscmp","lstrcmpA","lstrcmpW"]` and the first
    argument recorded in params is almost always the expected flag
    value (because the crackme is comparing user input against it).
    """
    p, a, rootfs = _resolve(path, arch)
    if not rootfs.exists():
        raise FileNotFoundError(_missing_rootfs_message(a))

    stdout_buf = io.StringIO()
    ql = _new_ql_or_raise(p, rootfs, stdout_buf)

    api_log: list[str] = []
    bypass_status = (
        _install_antidebug_bypass(ql, a, api_log) if bypass_antidebug else {}
    )
    trace_status = _install_api_logger(ql, api_log, apis)
    err = _run_ql(ql, timeout_us)

    result = ["# stdout", stdout_buf.getvalue(), "", "# api_log", *api_log]
    result.extend(_format_install_status("antidebug", bypass_status))
    result.extend(_format_install_status("trace", trace_status))
    if err:
        result.extend(["", "# emulation", err])
    return _truncate("\n".join(result))


@mcp.tool
async def qiling_dump_at_api(
    path: Annotated[str, "Path to the PE"],
    api: Annotated[str, "API to break on (e.g. 'strcmp', 'wcscmp', 'lstrcmpA')"],
    param_index: Annotated[int, "Which parameter to follow as a pointer (0-based)"] = 0,
    length: Annotated[int, "Bytes to read from the pointed-to buffer"] = 128,
    arch: Annotated[Arch, "x86 | x8664 | auto"] = "auto",
    bypass_antidebug: Annotated[bool, "Also install the anti-debug bypass"] = True,
    timeout_us: Annotated[
        int, "Emulation timeout in microseconds"
    ] = DEFAULT_TIMEOUT_US,
) -> str:
    """Break on `api`, dump the buffer at `params[param_index]`.

    For HTB-style "find the flag" crackmes, the flag usually ends up as
    an argument to a string-compare function at the moment of
    validation. This tool captures that buffer without requiring a
    debugger or patching.
    """
    from qiling.const import QL_INTERCEPT

    p, a, rootfs = _resolve(path, arch)
    if not rootfs.exists():
        raise FileNotFoundError(_missing_rootfs_message(a))

    stdout_buf = io.StringIO()
    ql = _new_ql_or_raise(p, rootfs, stdout_buf)

    dumps: list[str] = []
    api_log: list[str] = []
    bypass_status = (
        _install_antidebug_bypass(ql, a, api_log) if bypass_antidebug else {}
    )

    def _on_call(ql_inner: Any, _address: int, params: Any) -> None:
        try:
            if isinstance(params, dict):
                values = list(params.values())
            else:
                values = list(params)
            if param_index >= len(values):
                dumps.append(
                    f"{api}: param index {param_index} out of range ({len(values)} params)"
                )
                return
            ptr = int(values[param_index])
            raw = ql_inner.mem.read(ptr, length)
            printable = bytes(raw).split(b"\x00", 1)[0].decode(errors="replace")
            dumps.append(
                f"{api}[{param_index}] @ 0x{ptr:x}: "
                f"{bytes(raw).hex()}  ({printable!r})"
            )
        except Exception as e:
            dumps.append(f"{api}: dump failed: {e}")

    try:
        ql.os.set_api(api, _on_call, QL_INTERCEPT.ENTER)
    except Exception as e:
        raise RuntimeError(
            f"failed to install ENTER hook for {api!r}: {e}. "
            f"Verify Qiling supports this API name (try qiling_api_trace first)."
        ) from e

    err = _run_ql(ql, timeout_us)
    result = ["# dumps", *dumps, "", "# stdout", stdout_buf.getvalue()]
    if api_log:
        result.extend(["", "# api_log", *api_log])
    result.extend(_format_install_status("antidebug", bypass_status))
    if err:
        result.extend(["", "# emulation", err])
    return _truncate("\n".join(result))


if __name__ == "__main__":
    mcp.run()
