#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "pefile>=2024.8.26",
#   "flare-capa>=7.3",
#   "flare-floss>=3.1",
#   "lief>=0.16",
#   "yara-python>=4.5",
# ]
# ///
"""Static-triage MCP for native binaries.

Triage tools that work identically on macOS and Linux. The `pe_*` tools
require a Windows PE input; the `bin_*` tools work on any binary
(PE / ELF / Mach-O for the LIEF-backed format info; PE / ELF / .NET /
shellcode for capa; any file for strings/bytes_at/yara).

  * pe_info          — PE only: headers, imports, exports, sections
                       (+ entropy), packer hints (pefile, in-process)
  * pe_floss         — PE/shellcode only: FLOSS stack/tight/decoded
                       strings (subprocess wrapper around `floss`)
  * pe_hash          — PE only: sha256 / md5 / imphash for VT
                       cross-reference (pefile)
  * bin_format_info  — PE / ELF / Mach-O: uniform format summary
                       (arch, entrypoint, sections, libs, imports/exports)
                       via LIEF
  * bin_strings      — any file: ASCII + UTF-16LE extraction (in-process)
  * bin_capa         — PE / ELF / .NET / shellcode: MITRE capa
                       capability tags + ATT&CK / MBC (subprocess
                       wrapper around `capa`)
  * bin_yara         — any file: YARA rule matching with auto-cached
                       Neo23x0/signature-base rule set (yara-python,
                       in-process)
  * bin_bytes_at     — any file: peek raw bytes at a file offset
  * debuginfod_symbols — ELF only: recover function names by GNU Build-ID
                       via debuginfod (distro debug-symbol federation;
                       outbound network, explicit-invocation, honours
                       $DEBUGINFOD_URLS — empty disables it)
  * triage_status    — report which backends actually work

Cache root: $BINANAL_CACHE_ROOT or ~/.dreadnode/cache/binary-analysis/
(legacy ~/.dreadnode/binary-analysis/ content is auto-migrated on first
call). Subsystem subdirs:

  * capa rules:      $CAPA_RULES       → <root>/capa-rules
                     → capa's embedded default
  * capa signatures: $CAPA_SIGNATURES  → <root>/capa-sigs
  * YARA rules:      $YARA_RULES       → <root>/yara-rules
                     (Neo23x0/signature-base, DRL-1.1 licensed)
  * Ghidra projects: <root>/ghidra-projects (configured in capability.yaml
                     via pyghidra-mcp `--project-path`)
  * Fetched refs:    <root>/refs (populated by the skill's
                     references/scripts/fetch_external.py helper for
                     sources that can't be redistributed in-tree)

Qiling rootfs stays at the upstream-default ~/.qiling/rootfs/ (or
$QILING_ROOTFS) — that location is shared with any other Qiling user
on the host, so per-capability isolation would just force a duplicate
169 MB download.

Why bespoke (vs. upstream MCPs that wrap the same surface):
  * eversinc33/TriageMCP (78★) — ships no LICENSE file, hard-codes
    Windows paths, PE-only, mixes return shapes.
  * Ap3x/BinaryAnalysis-MCP (24★) — GPL-3.0, incompatible with this
    capability's MIT license; LIEF-based, no capa/FLOSS/YARA integration.
  * cycraft-corp/BinaryAnalysisMCPs (112★, MIT) — different toolset
    (IDA Pro, x64dbg, Speakeasy), not a static-triage wrapper; not a
    duplicate of this MCP's surface.
This wrapper exists for: (1) rule-pack auto-bootstrap (capa + YARA),
(2) a format-agnostic bin_* family that runs identically on
PE/ELF/Mach-O/shellcode, (3) end-to-end CLI-presence probing in
triage_status.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json as _json
import math
import os
import shutil
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP

mcp = FastMCP("static-triage")

# Canonical env-var name is BINANAL_*; PE_TRIAGE_* is honoured as a fallback
# for callers who set it before the server rename. Same pattern as
# BINANAL_CACHE_ROOT below.
MAX_OUTPUT_CHARS = int(
    os.environ.get(
        "BINANAL_MAX_OUTPUT_CHARS",
        os.environ.get("PE_TRIAGE_MAX_OUTPUT_CHARS", "200000"),
    )
)
DEFAULT_TIMEOUT = int(
    os.environ.get(
        "BINANAL_TIMEOUT",
        os.environ.get("PE_TRIAGE_TIMEOUT", "300"),
    )
)

# Cache root for all on-disk artifacts this capability owns. Common pattern
# across dreadnode capabilities is `~/.dreadnode/cache/<capability>/`.
# `BINANAL_CACHE_ROOT` is the canonical env-var override; we still honour
# the legacy `PE_TRIAGE_CAPA_CACHE` for users who set it before this
# rename, and `_migrate_legacy_cache()` (below) moves content from the
# old `~/.dreadnode/binary-analysis/` location on first call.
_LEGACY_CACHE_ROOT = Path.home() / ".dreadnode" / "binary-analysis"
CAPA_CACHE_ROOT = Path(
    os.environ.get(
        "BINANAL_CACHE_ROOT",
        os.environ.get(
            "PE_TRIAGE_CAPA_CACHE",
            str(Path.home() / ".dreadnode" / "cache" / "binary-analysis"),
        ),
    )
)
CAPA_RULES_CACHE = CAPA_CACHE_ROOT / "capa-rules"
CAPA_SIGS_CACHE = CAPA_CACHE_ROOT / "capa-sigs"
CAPA_RULES_REPO = "https://github.com/mandiant/capa-rules.git"
CAPA_REPO = "https://github.com/mandiant/capa.git"

YARA_RULES_CACHE = CAPA_CACHE_ROOT / "yara-rules"
YARA_RULES_REPO = "https://github.com/Neo23x0/signature-base.git"


def _migrate_legacy_cache() -> None:
    """Move pre-rename cache content from `~/.dreadnode/binary-analysis/`
    to the new `~/.dreadnode/cache/binary-analysis/` root, one-time.

    No-op when the legacy root doesn't exist, when the new root is the
    legacy root (user set BINANAL_CACHE_ROOT explicitly to the old
    location), or when a target subdir already has content.
    """
    if not _LEGACY_CACHE_ROOT.exists():
        return
    if CAPA_CACHE_ROOT.resolve() == _LEGACY_CACHE_ROOT.resolve():
        return
    CAPA_CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    for sub in ("capa-rules", "capa-sigs", "yara-rules", "ghidra-projects"):
        src = _LEGACY_CACHE_ROOT / sub
        dst = CAPA_CACHE_ROOT / sub
        if src.exists() and not dst.exists():
            try:
                src.rename(dst)
            except OSError:
                # Cross-device or permission issue — caller will see the
                # missing subdir and re-clone. Don't fail the import.
                pass


_migrate_legacy_cache()


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


async def _ensure_yara_rules() -> Path:
    """Resolve a YARA rules directory, auto-cloning on first call.

    Order: $YARA_RULES, the dreadnode cache. Returns a directory that
    contains at least one `.yar` / `.yara` file under it (recursively).
    """
    explicit = os.environ.get("YARA_RULES")
    if explicit:
        p = Path(explicit).expanduser()
        if p.exists() and (any(p.rglob("*.yar")) or any(p.rglob("*.yara"))):
            return p

    if YARA_RULES_CACHE.exists() and (
        any(YARA_RULES_CACHE.rglob("*.yar")) or any(YARA_RULES_CACHE.rglob("*.yara"))
    ):
        return YARA_RULES_CACHE

    if await _shallow_clone(YARA_RULES_REPO, YARA_RULES_CACHE):
        if any(YARA_RULES_CACHE.rglob("*.yar")) or any(
            YARA_RULES_CACHE.rglob("*.yara")
        ):
            return YARA_RULES_CACHE

    raise FileNotFoundError(
        f"YARA rules not available. Set YARA_RULES to a directory of "
        f"rule files, or install git so the MCP can clone "
        f"{YARA_RULES_REPO} to {YARA_RULES_CACHE} on first call."
    )


# ── triage_status ────────────────────────────────────────────────────


@mcp.tool
async def triage_status() -> dict[str, Any]:
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

    try:
        import lief  # noqa: F401

        status["lief"] = "ok"
    except Exception as e:
        status["lief"] = f"unavailable: {e}"

    try:
        import yara  # noqa: F401

        try:
            ydir = await _ensure_yara_rules()
            status["yara"] = "ok"
            status["yara_rules"] = str(ydir)
        except Exception as e:
            status["yara"] = f"degraded: {e}"
    except Exception as e:
        status["yara"] = f"unavailable: yara-python not importable: {e}"

    try:
        status["debuginfod_servers"] = _resolve_debuginfod_servers(None)
    except RuntimeError as e:
        status["debuginfod_servers"] = str(e)

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
    signals to triage on.
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


# ── bin_strings ──────────────────────────────────────────────────────


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
async def bin_strings(
    path: Annotated[str, "Path to a binary file (PE/ELF/Mach-O/shellcode/any)"],
    min_length: Annotated[int, "Minimum string length"] = 6,
    encoding: Annotated[str, "ascii | utf16 | both"] = "both",
    limit: Annotated[int, "Maximum strings returned (newest policy: first-N)"] = 2000,
) -> str:
    """Extract ASCII and/or UTF-16LE strings from any file's bytes.

    Reimplemented in pure Python so behavior is identical on macOS and
    Linux — does not shell out to `strings`. Format-agnostic: works on
    PE, ELF, Mach-O, raw blobs, anything. Each line is
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

    PE / shellcode only — FLOSS does not support ELF or Mach-O.
    Slower than bin_strings but catches strings built at runtime by the
    common pattern of pushing bytes one-by-one onto the stack
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


# ── bin_capa ─────────────────────────────────────────────────────────


@mcp.tool
async def bin_capa(
    path: Annotated[
        str,
        "Path to a PE, ELF, .NET, or shellcode binary (Mach-O is unsupported by capa)",
    ],
    summary_only: Annotated[
        bool, "Return just the capability names (no per-match details)"
    ] = False,
    timeout: Annotated[int, "Subprocess timeout (seconds)"] = DEFAULT_TIMEOUT,
) -> str:
    """Run MITRE capa against the binary and return capability tags.

    Supported formats: PE, .NET, ELF, 32/64-bit shellcode. Mach-O is
    NOT supported by capa — use Ghidra for those targets.

    capa identifies behaviors (e.g. "check for debugger", "decode data
    via XOR", "hash data with CRC32") by matching rules against the
    disassembly, and emits ATT&CK / MBC mappings per rule. This usually
    surfaces validation routines, crypto usage, and anti-analysis tricks
    in one pass.
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


# ── bin_bytes_at ─────────────────────────────────────────────────────


@mcp.tool
async def bin_bytes_at(
    path: Annotated[str, "Path to a binary file (any format)"],
    offset: Annotated[int, "File offset (decimal or 0xHEX accepted as int)"],
    length: Annotated[int, "Number of bytes to read"] = 64,
) -> dict[str, Any]:
    """Read `length` bytes at file `offset` and return hex + base64.

    Format-agnostic. Useful after spotting a suspicious section or
    finding a string with bin_strings — lets you peek at the raw bytes
    without pulling the whole binary into context.
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


# ── bin_format_info ──────────────────────────────────────────────────


def _lief_lib_name(lib: Any) -> str:
    """Normalize LIEF library entries: PE/ELF return strings, Mach-O
    returns DylibCommand objects with a .name attribute.
    """
    if isinstance(lib, str):
        return lib
    name = getattr(lib, "name", None)
    return name if isinstance(name, str) else repr(lib)


@mcp.tool
async def bin_format_info(
    path: Annotated[str, "Path to a PE, ELF, or Mach-O binary"],
    max_imports: Annotated[int, "Max imported symbols returned"] = 200,
    max_exports: Annotated[int, "Max exported symbols returned"] = 200,
) -> dict[str, Any]:
    """Uniform format summary across PE / ELF / Mach-O using LIEF.

    Returns format, architecture, entrypoint, image base, PIE/NX flags,
    section table (with per-section entropy), libraries, and the first
    N imported / exported function names. Use this as the cross-format
    first-pass when the input might be any of the three; use `pe_info`
    for PE-specific depth (imphash, anti-debug import flagging,
    subsystem detection) and `readelf` / `otool` for ELF / Mach-O
    field-level detail beyond what's here.
    """
    import lief

    p = _resolve_path(path)
    binary = lief.parse(str(p))
    if binary is None:
        raise ValueError(f"LIEF could not parse {p} (unrecognized format)")

    data = p.read_bytes()
    fmt = binary.format.name  # 'PE' | 'ELF' | 'MACHO'

    sections = []
    for s in binary.sections:
        name = s.name if isinstance(s.name, str) else s.name.decode(errors="replace")
        sections.append(
            {
                "name": name,
                "size": int(getattr(s, "size", 0)),
                "virtual_size": int(getattr(s, "virtual_size", 0) or 0),
                "entropy": round(float(s.entropy), 3),
                "packed_hint": float(s.entropy) > 7.0,
            }
        )

    imports = [
        f.name
        for f in list(binary.imported_functions)[:max_imports]
        if getattr(f, "name", None)
    ]
    exports = [
        f.name
        for f in list(binary.exported_functions)[:max_exports]
        if getattr(f, "name", None)
    ]
    libraries = [_lief_lib_name(lib) for lib in binary.libraries]

    result: dict[str, Any] = {
        "path": str(p),
        "size": len(data),
        "sha256": _sha256(data),
        "format": fmt,
        "entrypoint": hex(binary.entrypoint),
        "image_base": hex(binary.imagebase),
        "is_pie": bool(binary.is_pie),
        "has_nx": bool(getattr(binary, "has_nx", False)),
        "sections": sections,
        "libraries": libraries,
        "imports": imports,
        "imports_truncated": len(list(binary.imported_functions)) > max_imports,
        "exports": exports,
        "exports_truncated": len(list(binary.exported_functions)) > max_exports,
    }

    if fmt == "PE":
        result["pe"] = {
            "machine": binary.header.machine.name,
            "subsystem": binary.optional_header.subsystem.name,
            "compile_timestamp": int(binary.header.time_date_stamps),
            "is_dll": bool(getattr(binary, "is_dll", False)),
            "has_imports": bool(binary.has_imports),
        }
    elif fmt == "ELF":
        result["elf"] = {
            "type": binary.header.file_type.name,
            "machine": binary.header.machine_type.name,
            "os_abi": binary.header.identity_os_abi.name,
            "interpreter": binary.interpreter if binary.has_interpreter else None,
        }
    elif fmt == "MACHO":
        result["macho"] = {
            "cpu": binary.header.cpu_type.name,
            "file_type": binary.header.file_type.name,
            "has_main_command": bool(binary.has_main_command),
        }

    return result


# ── bin_yara ─────────────────────────────────────────────────────────


@mcp.tool
async def bin_yara(
    path: Annotated[str, "Path to any file (format-agnostic)"],
    rules: Annotated[
        str | None,
        "Path to a YARA rules file or directory (overrides $YARA_RULES / "
        "the cached Neo23x0/signature-base set)",
    ] = None,
    summary_only: Annotated[
        bool, "Return just matched rule names + tags (no per-string offsets)"
    ] = False,
    max_rules: Annotated[int, "Max rule sources to load when given a directory"] = 1000,
    timeout: Annotated[int, "Scan timeout (seconds)"] = 120,
) -> str:
    """Match YARA rules against any file.

    By default uses an auto-cached clone of Neo23x0/signature-base
    (DRL-1.1 licensed; the canonical community rule set). Override by
    setting `$YARA_RULES` or by passing the `rules=` arg explicitly to
    a `.yar` file or a directory of rule files. capa surfaces behavior
    tags via its rule engine; YARA matches against family signatures
    and IOCs the rule packs catalogue.

    Output (default): one line per match instance —
    `rule_name<TAB>0x<offset><TAB>$var<TAB>matched_bytes`. With
    `summary_only=True`, one line per matched rule with tag list.
    """
    import yara as _yara

    p = _resolve_path(path)

    if rules is not None:
        rules_path = Path(rules).expanduser().resolve()
        if not rules_path.exists():
            raise FileNotFoundError(f"YARA rules path does not exist: {rules_path}")
    else:
        rules_path = await _ensure_yara_rules()

    if rules_path.is_file():
        compiled = _yara.compile(filepath=str(rules_path))
    else:
        sources: dict[str, str] = {}
        files = list(rules_path.rglob("*.yar")) + list(rules_path.rglob("*.yara"))
        for rf in files[:max_rules]:
            sources[str(rf.relative_to(rules_path))] = str(rf)
        if not sources:
            raise FileNotFoundError(f"No .yar/.yara files under {rules_path}")
        # compile() raises if any file fails; tolerate broken rule files
        # by compiling one-by-one and dropping the noisy ones.
        good: dict[str, str] = {}
        skipped: list[tuple[str, str]] = []
        for label, rf in sources.items():
            try:
                _yara.compile(filepath=rf)
                good[label] = rf
            except _yara.SyntaxError as e:
                skipped.append((label, str(e)[:120]))
        if not good:
            raise RuntimeError(
                f"No compilable rule files under {rules_path}. "
                f"First skip reason: {skipped[0][1] if skipped else 'unknown'}"
            )
        compiled = _yara.compile(filepaths=good)

    matches = compiled.match(str(p), timeout=timeout)

    if summary_only:
        lines = []
        for m in matches:
            tags = ",".join(m.tags) if m.tags else "-"
            instances = sum(len(s.instances) for s in m.strings)
            lines.append(f"{m.rule}\t{instances} matches\ttags={tags}")
        return _truncate("\n".join(lines) or "no matches")

    lines = []
    for m in matches:
        for s in m.strings:
            for inst in s.instances:
                hexdump = bytes(inst.matched_data[:64]).hex()
                lines.append(
                    f"{m.rule}\t0x{inst.offset:08x}\t{s.identifier}\t{hexdump}"
                )
    return _truncate("\n".join(lines) or "no matches")


# ── debuginfod_symbols ───────────────────────────────────────────────

DEBUGINFOD_FALLBACK = "https://debuginfod.elfutils.org"


def _parse_build_id_note(raw: bytes, little: bool = True) -> str | None:
    """Parse a `.note.gnu.build-id` section's bytes → hex build-id, or None.

    Note layout: namesz, descsz, type (3× uint32) + name (padded to 4) + desc;
    the desc is the build-id. Pure/synchronous so it unit-tests without an ELF.
    """
    if len(raw) < 12:
        return None
    namesz, descsz, _ntype = struct.unpack("<III" if little else ">III", raw[:12])
    if descsz == 0 or descsz > 1024:
        return None
    start = 12 + ((namesz + 3) & ~3)
    desc = raw[start : start + descsz]
    return desc.hex() if len(desc) == descsz else None


def _resolve_debuginfod_servers(servers: str | None) -> list[str]:
    """Resolve the debuginfod base URLs to query.

    Precedence: explicit `servers` arg → `$DEBUGINFOD_URLS` → the public
    elfutils federation. A `$DEBUGINFOD_URLS` that is set but blank means
    "disabled" and raises — a kill-switch for isolated/sensitive analysis.
    """

    def _split(s: str) -> list[str]:
        return [u.strip() for u in s.replace(",", " ").split() if u.strip()]

    if servers:
        return _split(servers)
    env = os.environ.get("DEBUGINFOD_URLS")
    if env is not None:
        urls = _split(env)
        if not urls:
            raise RuntimeError("debuginfod disabled: DEBUGINFOD_URLS is set but empty")
        return urls
    return [DEBUGINFOD_FALLBACK]


def _http_get(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "binary-analysis-mcp"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https)
        return resp.read()


@mcp.tool
async def debuginfod_symbols(
    path: Annotated[str, "Path to an ELF binary that carries a GNU Build-ID"],
    servers: Annotated[
        str | None,
        "Comma/space-separated debuginfod base URLs; defaults to $DEBUGINFOD_URLS, "
        "then the public elfutils federation. Set DEBUGINFOD_URLS empty to disable.",
    ] = None,
    max_symbols: Annotated[
        int, "Max function symbols to return (ordered by address)"
    ] = 1000,
    timeout: Annotated[int, "Per-request HTTP timeout (seconds)"] = 90,
) -> dict[str, Any]:
    """Recover function names for an ELF via its GNU Build-ID using debuginfod.

    For binaries a distro indexes (Fedora / Debian / Ubuntu / Arch / ...), this
    fetches the exact debug info for the binary's Build-ID and returns the
    recovered function name → address map: current, exact, no signature
    database, none of FID/FLIRT's version brittleness. Apply the names with the
    ghidra `rename_function` tool.

    NETWORK: makes an outbound request that reveals the Build-ID to the server.
    Runs ONLY when you call it (never automatically). Point it at a
    local/self-hosted server, or disable it, via $DEBUGINFOD_URLS or `servers`.

    Only distro-indexed builds resolve; custom-compiled or malware binaries
    usually have no indexed Build-ID and raise "no debuginfo found" — use FID /
    BSim / similarity for those.
    """
    import lief

    p = _resolve_path(path)
    binary = lief.parse(str(p))
    if binary is None or binary.format.name != "ELF":
        raise ValueError("debuginfod_symbols requires an ELF binary")
    if not binary.has_section(".note.gnu.build-id"):
        raise ValueError(
            "ELF has no .note.gnu.build-id section — cannot query debuginfod"
        )

    raw = bytes(binary.get_section(".note.gnu.build-id").content)
    build_id = _parse_build_id_note(raw, little=True) or _parse_build_id_note(
        raw, little=False
    )
    if not build_id:
        raise ValueError("could not parse a GNU Build-ID from this ELF")

    urls = _resolve_debuginfod_servers(servers)
    content: bytes | None = None
    used: str | None = None
    errors: list[str] = []
    for base in urls:
        url = f"{base.rstrip('/')}/buildid/{build_id}/debuginfo"
        try:
            content = await asyncio.to_thread(_http_get, url, timeout)
            used = base
            break
        except urllib.error.HTTPError as e:
            errors.append(f"{base}: HTTP {e.code}")
        except Exception as e:  # noqa: BLE001 — try the next server
            errors.append(f"{base}: {type(e).__name__}")
    if content is None:
        raise RuntimeError(
            f"no debuginfo found for build-id {build_id} "
            f"(tried {len(urls)}: {'; '.join(errors)}). "
            "Binary may not be a distro-indexed build — use FID / BSim instead."
        )

    dbg = lief.parse(list(content))
    if dbg is None:
        raise RuntimeError("debuginfod returned data LIEF could not parse as ELF")
    # Only DEFINED functions (nonzero address); skip undefined/imported symbols
    # (e.g. `free@GLIBC_2.2.5`) which carry address 0 and aren't ours to name.
    funcs: dict[str, str] = {}
    for s in dbg.symbols:
        if s.is_function and s.name and s.value:
            funcs.setdefault(s.name, hex(s.value))
    ordered = sorted(funcs.items(), key=lambda kv: kv[1])
    total = len(ordered)

    out: dict[str, Any] = {
        "path": str(p),
        "build_id": build_id,
        "server": used,
        "function_count": total,
        "functions": dict(ordered[:max_symbols]),
    }
    if total > max_symbols:
        out["truncated"] = True
    return out


if __name__ == "__main__":
    mcp.run()
