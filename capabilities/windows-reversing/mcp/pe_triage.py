#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "pefile>=2024.8.26",
#   "flare-capa>=7.3",
#   "flare-floss>=3.1",
# ]
# ///
"""Windows PE static-triage MCP.

Triage tools that work identically on macOS and Linux:

  * pe_info          — headers, imports, exports, sections (+ entropy),
                       detected compiler/packer hints (pefile, in-process)
  * pe_strings       — ASCII + UTF-16LE extraction (in-process)
  * pe_floss         — FLOSS stack/tight/decoded strings (subprocess
                       wrapper around the `floss` CLI shipped by
                       flare-floss)
  * pe_capa          — MITRE capa capability tags + ATT&CK / MBC
                       (subprocess wrapper around the `capa` CLI shipped
                       by flare-capa)
  * pe_hash          — sha256 / md5 / imphash for VT cross-reference
  * pe_bytes_at      — peek raw bytes at a file offset
  * pe_triage_status — report which backends actually work

flare-capa requires a rules directory; we point it at $CAPA_RULES, then
~/.dreadnode/windows-reversing/capa-rules (auto-cloned on first call),
then capa's embedded default if the package shipped one.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json as _json
import math
import os
import shutil
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP

mcp = FastMCP("pe-triage")

MAX_OUTPUT_CHARS = int(os.environ.get("PE_TRIAGE_MAX_OUTPUT_CHARS", "200000"))
DEFAULT_TIMEOUT = int(os.environ.get("PE_TRIAGE_TIMEOUT", "300"))
CAPA_CACHE_ROOT = Path(
    os.environ.get(
        "PE_TRIAGE_CAPA_CACHE",
        str(Path.home() / ".dreadnode" / "windows-reversing"),
    )
)
CAPA_RULES_CACHE = CAPA_CACHE_ROOT / "capa-rules"
CAPA_SIGS_CACHE = CAPA_CACHE_ROOT / "capa-sigs"
CAPA_RULES_REPO = "https://github.com/mandiant/capa-rules.git"
CAPA_REPO = "https://github.com/mandiant/capa.git"


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"file does not exist: {p}")
    if not p.is_file():
        raise IsADirectoryError(f"not a file: {p}")
    return p


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts if c)


# ── helpers shared by the subprocess-backed tools ────────────────────


def _which(name: str) -> str | None:
    return shutil.which(name)


async def _run(
    argv: list[str],
    *,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"command timed out after {timeout}s: {argv[0]}") from None
    return (proc.returncode if proc.returncode is not None else 1, stdout, stderr)


async def _shallow_clone(repo: str, dest: Path, timeout: int = 180) -> bool:
    if not _which("git"):
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    rc, _, _ = await _run(
        ["git", "clone", "--depth=1", repo, str(dest)],
        timeout=timeout,
    )
    return rc == 0 and dest.exists()


async def _ensure_capa_rules() -> Path:
    """Resolve a capa rules directory, auto-cloning on first call.

    Order: $CAPA_RULES, the dreadnode cache, capa's embedded default.
    """
    explicit = os.environ.get("CAPA_RULES")
    if explicit:
        p = Path(explicit).expanduser()
        if (p / "lib").exists() or any(p.glob("*.yml")):
            return p

    if (CAPA_RULES_CACHE / "lib").exists():
        return CAPA_RULES_CACHE

    if await _shallow_clone(CAPA_RULES_REPO, CAPA_RULES_CACHE):
        return CAPA_RULES_CACHE

    try:
        import capa.main as _capa_main

        embedded = _capa_main.get_default_root() / "rules"
        if embedded.exists():
            return embedded
    except Exception:
        pass

    raise FileNotFoundError(
        f"capa rules not available. Set CAPA_RULES to a clone of {CAPA_RULES_REPO}, "
        f"or install git so the MCP can clone it to {CAPA_RULES_CACHE} on first call."
    )


async def _ensure_capa_sigs() -> Path | None:
    """Resolve a capa signatures directory, auto-cloning on first call.

    capa needs FLIRT signatures separately from rules; they live in the
    main capa repo under sigs/. Returns the sigs dir, or None if capa's
    embedded default works.
    """
    explicit = os.environ.get("CAPA_SIGNATURES")
    if explicit:
        p = Path(explicit).expanduser()
        if p.exists():
            return p

    sigs_in_cache = CAPA_SIGS_CACHE / "sigs"
    if sigs_in_cache.exists():
        return sigs_in_cache

    if await _shallow_clone(CAPA_REPO, CAPA_SIGS_CACHE):
        if sigs_in_cache.exists():
            return sigs_in_cache

    return None


# ── pe_triage_status ─────────────────────────────────────────────────


@mcp.tool
async def pe_triage_status() -> dict[str, Any]:
    """Report which triage backends actually work on this host.

    Each entry is "ok" (verified callable) or a one-line reason. Status
    is checked end-to-end (CLI presence + a `--help` probe), not by
    importing the package — so a tool that can't run reports broken
    here, not silently at first call.
    """
    status: dict[str, Any] = {"platform_independent": True}

    try:
        import pefile  # noqa: F401

        status["pefile"] = "ok"
    except Exception as e:
        status["pefile"] = f"unavailable: {e}"

    floss_path = _which("floss")
    if floss_path:
        rc, _, err = await _run([floss_path, "--help"], timeout=15)
        status["floss"] = (
            "ok"
            if rc == 0
            else f"unavailable: floss --help exited {rc}: {err.decode(errors='replace')[:200]}"
        )
    else:
        status["floss"] = (
            "unavailable: `floss` CLI not on PATH (flare-floss installs it as a console_script)"
        )

    capa_path = _which("capa")
    if not capa_path:
        status["capa"] = (
            "unavailable: `capa` CLI not on PATH (flare-capa installs it as a console_script)"
        )
    else:
        try:
            rules = await _ensure_capa_rules()
            sigs = await _ensure_capa_sigs()
            status["capa"] = "ok"
            status["capa_rules"] = str(rules)
            status["capa_signatures"] = str(sigs) if sigs else "embedded (default)"
        except Exception as e:
            status["capa"] = f"degraded: {e}"

    status["max_output_chars"] = MAX_OUTPUT_CHARS
    status["timeout_seconds"] = DEFAULT_TIMEOUT
    return status


# ── pe_info ──────────────────────────────────────────────────────────


@mcp.tool
async def pe_info(
    path: Annotated[str, "Path to a Windows PE file (.exe, .dll, .sys, ...)"],
) -> dict[str, Any]:
    """Parse PE headers and return a structured summary.

    Fields include architecture, subsystem, compile timestamp, entry
    point, section table with per-section entropy (>7.0 ≈ packed or
    encrypted), imports grouped by DLL, and export table if present.
    High-entropy sections and suspicious imports (VirtualAlloc,
    IsDebuggerPresent, NtQueryInformationProcess, ...) are the first
    things to look at in an HTB-style challenge.
    """
    import pefile

    p = _resolve_path(path)
    data = p.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)

    arch = {
        0x014C: "i386",
        0x8664: "amd64",
        0x01C0: "arm",
        0xAA64: "arm64",
    }.get(pe.FILE_HEADER.Machine, f"unknown (0x{pe.FILE_HEADER.Machine:04x})")

    subsystem = {
        1: "native",
        2: "windows_gui",
        3: "windows_cui",
        9: "efi_application",
    }.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))

    sections = []
    for s in pe.sections:
        raw = s.get_data()
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        ent = _entropy(raw)
        sections.append(
            {
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(ent, 3),
                "packed_hint": ent > 7.0,
                "characteristics": hex(s.Characteristics),
            }
        )

    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            names = [
                (
                    imp.name.decode(errors="replace")
                    if imp.name
                    else f"ordinal_{imp.ordinal}"
                )
                for imp in entry.imports
            ]
            imports[dll] = names

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="replace"))
            else:
                exports.append(f"ordinal_{exp.ordinal}")

    anti_debug_apis = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "NtSetInformationThread",
        "GetTickCount",
        "QueryPerformanceCounter",
        "RtlAddVectoredExceptionHandler",
    }
    flagged_imports = sorted(
        {api for apis in imports.values() for api in apis if api in anti_debug_apis}
    )

    return {
        "path": str(p),
        "size": len(data),
        "sha256": _sha256(data),
        "architecture": arch,
        "subsystem": subsystem,
        "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "flagged_anti_debug_imports": flagged_imports,
        "is_dll": pe.is_dll(),
        "is_exe": pe.is_exe(),
        "is_driver": pe.is_driver(),
    }


# ── pe_strings ───────────────────────────────────────────────────────


def _scan_ascii(data: bytes, min_len: int) -> list[tuple[int, str]]:
    out, start, buf = [], None, bytearray()
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if start is None:
                start = i
            buf.append(b)
        else:
            if start is not None and len(buf) >= min_len:
                out.append((start, buf.decode("ascii", errors="replace")))
            start, buf = None, bytearray()
    if start is not None and len(buf) >= min_len:
        out.append((start, buf.decode("ascii", errors="replace")))
    return out


def _scan_utf16le(data: bytes, min_len: int) -> list[tuple[int, str]]:
    out, start, buf = [], None, bytearray()
    i = 0
    while i < len(data) - 1:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
            if start is None:
                start = i
            buf.append(lo)
            i += 2
        else:
            if start is not None and len(buf) >= min_len:
                out.append((start, buf.decode("ascii", errors="replace")))
            start, buf = None, bytearray()
            i += 1
    if start is not None and len(buf) >= min_len:
        out.append((start, buf.decode("ascii", errors="replace")))
    return out


@mcp.tool
async def pe_strings(
    path: Annotated[str, "Path to the PE file"],
    min_length: Annotated[int, "Minimum string length"] = 6,
    encoding: Annotated[str, "ascii | utf16 | both"] = "both",
    limit: Annotated[int, "Maximum strings returned (newest policy: first-N)"] = 2000,
) -> str:
    """Extract ASCII and/or UTF-16LE strings from the file bytes.

    Reimplemented in pure Python so behavior is identical on macOS and
    Linux — does not shell out to `strings`. Each line is
    `offset\\tencoding\\tstring`.
    """
    p = _resolve_path(path)
    data = p.read_bytes()

    results: list[tuple[int, str, str]] = []
    if encoding in ("ascii", "both"):
        results.extend((off, "A", s) for off, s in _scan_ascii(data, min_length))
    if encoding in ("utf16", "both"):
        results.extend((off, "W", s) for off, s in _scan_utf16le(data, min_length))

    results.sort(key=lambda x: x[0])
    results = results[:limit]
    lines = [f"0x{off:08x}\t{enc}\t{s}" for off, enc, s in results]
    return _truncate("\n".join(lines))


# ── pe_floss ─────────────────────────────────────────────────────────


@mcp.tool
async def pe_floss(
    path: Annotated[str, "Path to the PE file"],
    min_length: Annotated[int, "Minimum string length"] = 6,
    enable_stack: Annotated[bool, "Extract stack strings"] = True,
    enable_tight: Annotated[bool, "Extract tight strings"] = True,
    enable_decoded: Annotated[bool, "Extract decoded strings (slow)"] = True,
    timeout: Annotated[int, "Subprocess timeout (seconds)"] = DEFAULT_TIMEOUT,
) -> str:
    """Run FLOSS to recover stack / tight / decoded obfuscated strings.

    Slower than pe_strings but catches strings built at runtime by the
    common crackme pattern of pushing bytes one-by-one onto the stack
    then passing a pointer to strcmp/wcscmp. Use on small binaries
    (< ~1 MB); for larger binaries scope with a time budget.
    """
    p = _resolve_path(path)
    floss_bin = _which("floss")
    if not floss_bin:
        raise RuntimeError(
            "`floss` CLI not on PATH. flare-floss should install it; "
            "if running outside `uv run`, install with `uv tool install flare-floss`."
        )

    enabled = ["static"]
    if enable_stack:
        enabled.append("stack")
    if enable_tight:
        enabled.append("tight")
    if enable_decoded:
        enabled.append("decoded")
    argv = [floss_bin, "-n", str(min_length), "-j", "--only", *enabled, "--", str(p)]

    rc, stdout, stderr = await _run(argv, timeout=timeout)
    if rc != 0:
        raise RuntimeError(
            f"floss exited {rc}: {stderr.decode(errors='replace')[:500]}"
        )

    try:
        doc = _json.loads(stdout.decode(errors="replace"))
    except _json.JSONDecodeError as e:
        raise RuntimeError(f"floss produced unparseable JSON: {e}") from None

    strings = doc.get("strings", {})
    blocks: list[str] = []
    for label in (
        "static_strings",
        "stack_strings",
        "tight_strings",
        "decoded_strings",
    ):
        items = strings.get(label, [])
        if not items:
            continue
        lines = [f"# {label} ({len(items)})"]
        for it in items:
            s = it.get("string", "")
            # FLOSS records use 'address' for stack/tight/decoded, 'offset' for static.
            addr = (
                it.get("address") if it.get("address") is not None else it.get("offset")
            )
            if isinstance(addr, int):
                lines.append(f"0x{addr:08x}\t{s}")
            else:
                lines.append(s)
        blocks.append("\n".join(lines))

    return _truncate("\n\n".join(blocks) or "no strings recovered")


# ── pe_capa ──────────────────────────────────────────────────────────


@mcp.tool
async def pe_capa(
    path: Annotated[str, "Path to the PE file"],
    summary_only: Annotated[
        bool, "Return just the capability names (no per-match details)"
    ] = False,
    timeout: Annotated[int, "Subprocess timeout (seconds)"] = DEFAULT_TIMEOUT,
) -> str:
    """Run MITRE capa against the binary and return capability tags.

    capa identifies behaviors (e.g. "check for debugger", "decode data
    via XOR", "hash data with CRC32") by matching rules against the
    disassembly, and emits ATT&CK / MBC mappings per rule. For an HTB
    crackme this usually surfaces the flag-checking routine and any
    anti-analysis tricks in one pass.
    """
    p = _resolve_path(path)
    capa_bin = _which("capa")
    if not capa_bin:
        raise RuntimeError(
            "`capa` CLI not on PATH. flare-capa should install it; "
            "if running outside `uv run`, install with `uv tool install flare-capa`."
        )

    rules_dir = await _ensure_capa_rules()
    sigs_dir = await _ensure_capa_sigs()
    argv = [capa_bin, "-j", "-r", str(rules_dir)]
    if sigs_dir:
        argv += ["-s", str(sigs_dir)]
    argv += ["--", str(p)]
    rc, stdout, stderr = await _run(argv, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"capa exited {rc}: {stderr.decode(errors='replace')[:500]}")

    try:
        doc = _json.loads(stdout.decode(errors="replace"))
    except _json.JSONDecodeError as e:
        raise RuntimeError(f"capa produced unparseable JSON: {e}") from None

    if summary_only:
        rules_block = doc.get("rules", {})
        names = sorted(rules_block.keys())
        return _truncate("\n".join(names))

    return _truncate(_json.dumps(doc, indent=2, default=str))


# ── pe_hash_at ───────────────────────────────────────────────────────


@mcp.tool
async def pe_hash(
    path: Annotated[str, "Path to the PE file"],
) -> dict[str, str]:
    """Return SHA-256 + imphash + size for cross-referencing with
    VT/MalwareBazaar. imphash groups binaries by import table, which
    often survives minor recompiles.
    """
    import pefile

    p = _resolve_path(path)
    data = p.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    return {
        "path": str(p),
        "size": str(len(data)),
        "sha256": _sha256(data),
        "imphash": pe.get_imphash(),
        "md5": hashlib.md5(data).hexdigest(),
    }


# ── pe_bytes_at ──────────────────────────────────────────────────────


@mcp.tool
async def pe_bytes_at(
    path: Annotated[str, "Path to the PE file"],
    offset: Annotated[int, "File offset (decimal or 0xHEX accepted as int)"],
    length: Annotated[int, "Number of bytes to read"] = 64,
) -> dict[str, Any]:
    """Read `length` bytes at file `offset` and return hex + base64.

    Useful after spotting a suspicious section or finding a string with
    pe_strings — lets you peek at the raw bytes without pulling the
    whole binary into context.
    """
    p = _resolve_path(path)
    data = p.read_bytes()
    if offset < 0 or offset >= len(data):
        raise IndexError(f"offset {offset} out of range (size {len(data)})")
    chunk = data[offset : offset + length]
    return {
        "offset": offset,
        "length": len(chunk),
        "hex": chunk.hex(),
        "base64": base64.b64encode(chunk).decode(),
        "printable": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
    }


if __name__ == "__main__":
    mcp.run()
