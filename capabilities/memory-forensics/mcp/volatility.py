#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "volatility3>=2.7",
#   "yara-python>=4.5",
# ]
# ///
"""Volatility3 MCP server — memory forensics triage over memory images.

Thin Python MCP wrapper around the Volatility3 CLI. This does not vendor
or modify a local Volatility install. It resolves the command in this
order:

  1. VOLATILITY_COMMAND, if set (full command string, e.g. "vol")
  2. vol on PATH (uv run --script puts the venv-installed script there)
  3. The volatility3.cli entry point via the current interpreter
     (volatility3 is a package without __main__, so we invoke main()
     directly with sys.argv[0] set to "vol" so argparse behaves)

All plugin output is requested as JSON (-r json). Tool results return
parsed JSON where possible, falling back to raw text on renderer errors.

Most plugins are OS-specific. Tools that accept an `os_kind` parameter
(values: windows | linux | mac) route to the correct plugin namespace.
Run `volatility_info` first to determine the image OS.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from fastmcp import FastMCP

mcp = FastMCP("volatility")

MAX_OUTPUT_CHARS = int(os.environ.get("VOLATILITY_MAX_OUTPUT_CHARS", "200000"))
DEFAULT_TIMEOUT = int(os.environ.get("VOLATILITY_TIMEOUT", "600"))

# volatility3.cli reads its own argv. We invoke main() but argparse uses
# sys.argv[0] as the program name — "-c" (from python -c) collides with
# the --config flag. Set it explicitly so the fallback works.
_VOLATILITY3_BOOTSTRAP = "import sys; sys.argv[0]='vol'; from volatility3.cli import main; main()"

OSType = Literal["windows", "linux", "mac"]


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_command() -> list[str] | None:
    configured = os.environ.get("VOLATILITY_COMMAND")
    if configured:
        parts = shlex.split(configured)
        if parts and shutil.which(parts[0]):
            return parts
        return None

    if shutil.which("vol"):
        return ["vol"]

    # Fallback: call volatility3.cli.main() directly. The PEP 723 deps
    # ensure volatility3 is importable under `uv run`. Verified against
    # volatility3 2.7.x — `python -m volatility3` does not work because
    # the package has no __main__.py.
    try:
        import volatility3  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-c", _VOLATILITY3_BOOTSTRAP]


def _missing_dependency_message() -> str:
    return (
        "Error: volatility3 is unavailable. Install it with:\n"
        "  pipx install volatility3  (or)  uv tool install volatility3\n"
        "Alternatively set VOLATILITY_COMMAND to an explicit command."
    )


async def _run_vol(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: str | None = None,
) -> tuple[int, bytes, str]:
    command = _resolve_command()
    if not command:
        return 127, b"", _missing_dependency_message()

    proc = await asyncio.create_subprocess_exec(
        *(command + args),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, b"", f"Error: volatility command timed out after {timeout}s"

    return (
        proc.returncode if proc.returncode is not None else 1,
        stdout,
        stderr.decode(errors="replace"),
    )


def _render_plugin_result(returncode: int, stdout: bytes, stderr: str) -> str:
    """Try to parse JSON output; fall back to raw text."""
    text = stdout.decode(errors="replace")
    if returncode != 0:
        combined = f"{text}\n{stderr}".strip()
        return _truncate(f"Error (exit {returncode}): {combined}")
    try:
        parsed = json.loads(text) if text.strip() else []
        return _truncate(json.dumps(parsed, indent=2, default=str))
    except json.JSONDecodeError:
        return _truncate(text)


async def _run_plugin(
    image: str,
    plugin: str,
    extra: list[str] | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    output_dir: str | None = None,
) -> str:
    image_path = Path(image).expanduser()
    if not image_path.exists():
        return f"Error: image does not exist: {image_path}"
    args = ["-q", "-r", "json", "-f", str(image_path)]
    if output_dir is not None:
        args.extend(["-o", output_dir])
    args.append(plugin)
    if extra:
        args.extend(extra)
    returncode, stdout, stderr = await _run_vol(args, timeout=timeout)
    return _render_plugin_result(returncode, stdout, stderr)


def _plugin_for(os_kind: OSType, name: str) -> str:
    """Map (os, short_name) to a fully qualified Volatility3 plugin path."""
    return f"{os_kind}.{name}"


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool
async def volatility_status() -> str:
    """Report how the MCP would invoke Volatility3 on this host."""
    command = _resolve_command()
    if not command:
        return _missing_dependency_message()
    return _truncate(
        json.dumps(
            {
                "available": True,
                "command": command,
                "timeout_seconds": DEFAULT_TIMEOUT,
                "max_output_chars": MAX_OUTPUT_CHARS,
            },
            indent=2,
        )
    )


@mcp.tool
async def volatility_info(
    image: Annotated[str, "Path to the memory image file"],
    os_hint: Annotated[
        OSType | None,
        "Skip auto-detection and run the OS-specific info plugin directly",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Identify OS, kernel, and profile metadata for the memory image.

    With no `os_hint`, tries Windows → Linux → Mac in order and returns
    the first plugin that succeeds along with the resolved `os_kind` —
    use that value for every subsequent tool call.

    When the OS is already known, pass `os_hint` to skip auto-detection
    and run the matching info plugin directly.
    """
    if os_hint is not None:
        plugin = "linux.banners.Banners" if os_hint == "linux" else _plugin_for(os_hint, "info.Info")
        return await _run_plugin(image, plugin, timeout=timeout)

    attempts: list[tuple[OSType, str]] = [
        ("windows", "windows.info.Info"),
        ("linux", "linux.banners.Banners"),
        ("mac", "mac.info.Info"),
    ]
    failures: list[str] = []
    for os_kind, plugin in attempts:
        result = await _run_plugin(image, plugin, timeout=timeout)
        if not result.startswith("Error"):
            return f"Detected os_kind={os_kind}\n{result}"
        failures.append(f"{os_kind}: {result.splitlines()[0]}")
    return "Error: could not identify image OS.\n" + "\n".join(failures)


@mcp.tool
async def volatility_processes(
    image: Annotated[str, "Path to the memory image file"],
    os_kind: Annotated[OSType, "Image OS (run volatility_info first)"] = "windows",
    pid: Annotated[int | None, "Filter to a single PID"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """List running processes via the EPROCESS/task_struct walk (pslist)."""
    extra: list[str] = []
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    return await _run_plugin(image, _plugin_for(os_kind, "pslist.PsList"), extra, timeout=timeout)


@mcp.tool
async def volatility_process_tree(
    image: Annotated[str, "Path to the memory image file"],
    os_kind: Annotated[OSType, "Image OS"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Display the parent/child process tree (pstree)."""
    return await _run_plugin(image, _plugin_for(os_kind, "pstree.PsTree"), timeout=timeout)


@mcp.tool
async def volatility_process_scan(
    image: Annotated[str, "Path to the memory image file"],
    os_kind: Annotated[OSType, "Image OS (Windows only supports psscan)"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Pool-tag carve for processes (psscan) — finds hidden/terminated.

    Compare against volatility_processes output: entries present here
    but missing from pslist indicate DKOM hiding or recently exited
    processes.
    """
    return await _run_plugin(image, _plugin_for(os_kind, "psscan.PsScan"), timeout=timeout)


@mcp.tool
async def volatility_cmdlines(
    image: Annotated[str, "Path to the memory image file"],
    os_kind: Annotated[OSType, "Image OS"] = "windows",
    pid: Annotated[int | None, "Filter to a single PID"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Recover command-line arguments from the PEB/task (cmdline)."""
    plugin = "windows.cmdline.CmdLine" if os_kind == "windows" else _plugin_for(os_kind, "psaux.PsAux")
    extra: list[str] = []
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    return await _run_plugin(image, plugin, extra, timeout=timeout)


@mcp.tool
async def volatility_network(
    image: Annotated[str, "Path to the memory image file"],
    os_kind: Annotated[OSType, "Image OS"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Recover network connections and sockets.

    Uses netscan on Windows (pool-tag carve of TCP/UDP endpoints),
    sockstat on Linux, and netstat on Mac.
    """
    mapping = {
        "windows": "windows.netscan.NetScan",
        "linux": "linux.sockstat.Sockstat",
        "mac": "mac.netstat.Netstat",
    }
    return await _run_plugin(image, mapping[os_kind], timeout=timeout)


@mcp.tool
async def volatility_malfind(
    image: Annotated[str, "Path to the memory image file"],
    pid: Annotated[int | None, "Restrict scan to a single PID"] = None,
    os_kind: Annotated[OSType, "Image OS"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Detect injected or unmapped executable regions (malfind).

    Flags VADs that are PAGE_EXECUTE_READWRITE, not backed by a file,
    and/or contain MZ/shellcode patterns — classic process injection
    signatures.
    """
    extra: list[str] = []
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    return await _run_plugin(image, _plugin_for(os_kind, "malfind.Malfind"), extra, timeout=timeout)


@mcp.tool
async def volatility_dll_list(
    image: Annotated[str, "Path to the memory image file"],
    pid: Annotated[int | None, "Restrict to a single PID"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """List DLLs loaded by Windows processes (dlllist)."""
    extra: list[str] = []
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    return await _run_plugin(image, "windows.dlllist.DllList", extra, timeout=timeout)


@mcp.tool
async def volatility_handles(
    image: Annotated[str, "Path to the memory image file"],
    pid: Annotated[int | None, "PID to enumerate handles for (omit to scan all)"] = None,
    object_types: Annotated[
        list[str] | None,
        "Filter by object types, e.g. ['Process', 'File', 'Key']. Omit for all.",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Enumerate open handles for Windows processes (handles).

    Use `object_types=['Process']` to find handles into other processes
    — the canonical way to spot LSASS dumpers.
    """
    extra: list[str] = []
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    if object_types:
        extra.append("--object-types")
        extra.extend(object_types)
    return await _run_plugin(image, "windows.handles.Handles", extra, timeout=timeout)


@mcp.tool
async def volatility_registry_hives(
    image: Annotated[str, "Path to the memory image file"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """List loaded Windows registry hives with offsets (hivelist).

    Hive offsets feed volatility_registry_key.
    """
    return await _run_plugin(image, "windows.registry.hivelist.HiveList", timeout=timeout)


@mcp.tool
async def volatility_registry_key(
    image: Annotated[str, "Path to the memory image file"],
    key: Annotated[
        str,
        "Registry key path, e.g. 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    ],
    hive_offset: Annotated[
        int | None,
        "Hive offset from volatility_registry_hives (omit to scan all hives)",
    ] = None,
    recurse: Annotated[bool, "Recurse into subkeys"] = False,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Print a Windows registry key and its values (printkey)."""
    extra: list[str] = ["--key", key]
    if hive_offset is not None:
        extra.extend(["--offset", hex(hive_offset)])
    if recurse:
        extra.append("--recurse")
    return await _run_plugin(image, "windows.registry.printkey.PrintKey", extra, timeout=timeout)


@mcp.tool
async def volatility_hashdump(
    image: Annotated[str, "Path to the memory image file"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Extract local SAM account NT hashes (hashdump).

    For cached domain credentials use volatility_run_plugin with
    windows.cachedump.Cachedump. For LSA secrets use windows.lsadump.Lsadump.
    """
    return await _run_plugin(image, "windows.hashdump.Hashdump", timeout=timeout)


@mcp.tool
async def volatility_services(
    image: Annotated[str, "Path to the memory image file"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Enumerate Windows services (svcscan)."""
    return await _run_plugin(image, "windows.svcscan.SvcScan", timeout=timeout)


@mcp.tool
async def volatility_yara_scan(
    image: Annotated[str, "Path to the memory image file"],
    rules_file: Annotated[
        str | None,
        "Path to a YARA rules file (.yar). Mutually exclusive with rules_inline.",
    ] = None,
    rules_inline: Annotated[str | None, "Inline YARA rule source. Written to a temp file before scanning."] = None,
    pid: Annotated[int | None, "Restrict scan to a single PID"] = None,
    os_kind: Annotated[OSType, "Image OS"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Scan process memory against YARA rules (yarascan).

    Exactly one of rules_file or rules_inline must be provided.
    """
    if (rules_file is None) == (rules_inline is None):
        return "Error: provide exactly one of rules_file or rules_inline."

    plugin = _plugin_for(os_kind, "yarascan.YaraScan")

    if rules_inline is not None:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="volatility-yara-",
            suffix=".yar",
            delete=False,
        ) as tmp:
            tmp.write(rules_inline)
            rules_path = tmp.name
        try:
            extra = ["--yara-file", rules_path]
            if pid is not None:
                extra.extend(["--pid", str(pid)])
            return await _run_plugin(image, plugin, extra, timeout=timeout)
        finally:
            Path(rules_path).unlink(missing_ok=True)

    assert rules_file is not None
    path = Path(rules_file).expanduser()
    if not path.exists():
        return f"Error: rules_file does not exist: {path}"
    extra = ["--yara-file", str(path)]
    if pid is not None:
        extra.extend(["--pid", str(pid)])
    return await _run_plugin(image, plugin, extra, timeout=timeout)


@mcp.tool
async def volatility_dump_process(
    image: Annotated[str, "Path to the memory image file"],
    pid: Annotated[int, "PID to dump"],
    output_dir: Annotated[str, "Directory to write dumped files into"],
    mode: Annotated[
        Literal["pe", "vad", "memmap"],
        "pe: process executable | vad: all VAD regions | memmap: full process memory map",
    ] = "vad",
    os_kind: Annotated[OSType, "Image OS (Windows recommended)"] = "windows",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Dump process memory artifacts to disk for offline analysis.

    Files land in `output_dir`. `vad` is the right default for hunting
    injected regions; `pe` carves the main module; `memmap` dumps the
    full memory map (large, slow).
    """
    out = Path(output_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    plugin_map = {
        "pe": f"{os_kind}.pslist.PsList",
        "vad": f"{os_kind}.vadinfo.VadInfo",
        "memmap": f"{os_kind}.memmap.Memmap",
    }
    extra = ["--pid", str(pid), "--dump"]
    return await _run_plugin(image, plugin_map[mode], extra, timeout=timeout, output_dir=str(out))


@mcp.tool
async def volatility_timeline(
    image: Annotated[str, "Path to the memory image file"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Build a cross-plugin timeline of timestamped artifacts (timeliner)."""
    return await _run_plugin(image, "timeliner.Timeliner", timeout=timeout)


@mcp.tool
async def volatility_list_plugins(
    timeout: Annotated[int, "Command timeout in seconds"] = 60,
) -> str:
    """List every Volatility3 plugin available on this host."""
    returncode, stdout, stderr = await _run_vol(["--help"], timeout=timeout)
    text = stdout.decode(errors="replace")
    # The plugin list appears after "Plugins:" in --help output.
    marker = "Plugins:"
    if marker in text:
        text = text[text.index(marker) :]
    if returncode != 0:
        return _truncate(f"Error (exit {returncode}): {text}\n{stderr}")
    return _truncate(text)


@mcp.tool
async def volatility_run_plugin(
    image: Annotated[str, "Path to the memory image file"],
    plugin: Annotated[str, "Fully qualified plugin name, e.g. 'windows.lsadump.Lsadump'"],
    args: Annotated[
        list[str] | None,
        "Extra CLI args for the plugin (e.g. ['--pid', '1234'])",
    ] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Run any Volatility3 plugin — escape hatch for the long tail.

    Use the curated tools first. Reach for this when you need a plugin
    that isn't wrapped: cachedump, lsadump, driverscan, ssdt, dumpfiles,
    userassist, shimcachemem, pe_symbols, etc.
    """
    return await _run_plugin(image, plugin, list(args or []), timeout=timeout)


if __name__ == "__main__":
    mcp.run(transport="stdio")
