#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
# ]
# ///
"""Ghidra headless MCP.

Thin wrapper around Ghidra's `analyzeHeadless` launcher. The Ghidra
install is resolved at invocation time (not bundled) so this works
identically on macOS and Linux as long as a JDK 17+ and a Ghidra
distribution are installed.

Resolve order for the headless launcher:

  1. GHIDRA_HEADLESS, if set (full path to analyzeHeadless)
  2. GHIDRA_INSTALL_DIR, if set (standard Ghidra env var)
     → $GHIDRA_INSTALL_DIR/support/analyzeHeadless
  3. `analyzeHeadless` on PATH (Homebrew `ghidra` exposes it; some
     Linux packages do too)
  4. Fallback: search common install locations on macOS and Linux

Per-binary projects are cached under ~/.dreadnode/windows-reversing/
ghidra/<sha256>/ so the expensive auto-analysis runs once per binary.
Subsequent tool calls re-use the cached project.

All analysis outputs are produced by small Ghidra post-scripts written
to a temp file per invocation — we never modify the user's Ghidra
install.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP

mcp = FastMCP("ghidra")

MAX_OUTPUT_CHARS = int(os.environ.get("GHIDRA_MAX_OUTPUT_CHARS", "200000"))
DEFAULT_TIMEOUT = int(os.environ.get("GHIDRA_TIMEOUT", "900"))
PROJECT_ROOT = Path(
    os.environ.get(
        "GHIDRA_PROJECT_ROOT",
        str(Path.home() / ".dreadnode" / "windows-reversing" / "ghidra"),
    )
)


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mac_candidates() -> list[Path]:
    home = Path.home()
    cask_globs = [
        Path("/opt/homebrew/Caskroom/ghidra"),
        Path("/usr/local/Caskroom/ghidra"),
    ]
    cask_hits: list[Path] = []
    for root in cask_globs:
        if not root.exists():
            continue
        for entry in sorted(root.iterdir(), reverse=True):
            cask_hits.extend(entry.glob("ghidra_*_PUBLIC/support/analyzeHeadless"))
    return [
        *cask_hits,
        Path("/Applications/ghidra/support/analyzeHeadless"),
        Path("/opt/homebrew/opt/ghidra/bin/analyzeHeadless"),
        Path("/usr/local/opt/ghidra/bin/analyzeHeadless"),
        home / "ghidra" / "support" / "analyzeHeadless",
    ]


def _linux_candidates() -> list[Path]:
    home = Path.home()
    return [
        Path("/opt/ghidra/support/analyzeHeadless"),
        Path("/usr/share/ghidra/support/analyzeHeadless"),
        Path("/usr/local/ghidra/support/analyzeHeadless"),
        home / "ghidra" / "support" / "analyzeHeadless",
    ]


def _resolve_headless() -> Path | None:
    explicit = os.environ.get("GHIDRA_HEADLESS")
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        p = Path(install_dir).expanduser() / "support" / "analyzeHeadless"
        if p.exists():
            return p

    on_path = shutil.which("analyzeHeadless")
    if on_path:
        return Path(on_path)

    candidates = _mac_candidates() if sys.platform == "darwin" else _linux_candidates()
    for c in candidates:
        if c.exists():
            return c
    return None


def _missing_message() -> str:
    return (
        "Error: Ghidra headless launcher not found. Install Ghidra and either:\n"
        "  * export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x_PUBLIC, or\n"
        "  * export GHIDRA_HEADLESS=/path/to/support/analyzeHeadless, or\n"
        "  * put analyzeHeadless on PATH (Homebrew: `brew install ghidra`;\n"
        "    Linux: extract the official tarball from\n"
        "    https://github.com/NationalSecurityAgency/ghidra/releases).\n"
        "  Ghidra requires JDK 17+."
    )


def _project_for(binary: Path) -> tuple[Path, str, str]:
    digest = _sha256_file(binary)
    project_dir = PROJECT_ROOT / digest
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir, digest, binary.name


async def _run_headless(args: list[str], timeout: int) -> tuple[int, str, str]:
    headless = _resolve_headless()
    if not headless:
        return 127, "", _missing_message()

    proc = await asyncio.create_subprocess_exec(
        str(headless),
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, "", f"Error: Ghidra headless timed out after {timeout}s"

    return (
        proc.returncode if proc.returncode is not None else 1,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


async def _ensure_analyzed(binary: Path, timeout: int) -> tuple[Path, str]:
    """Import + auto-analyze the binary into a cached project if needed."""
    project_dir, digest, name = _project_for(binary)
    marker = project_dir / ".analyzed"
    if marker.exists():
        return project_dir, digest

    args = [
        str(project_dir),
        digest,
        "-import",
        str(binary),
        "-analysisTimeoutPerFile",
        str(timeout - 30),
        "-overwrite",
    ]
    rc, out, err = await _run_headless(args, timeout=timeout)
    if rc == 127:
        raise RuntimeError(err)
    if rc != 0:
        raise RuntimeError(f"Ghidra import failed (exit {rc}):\n{out}\n{err}")
    marker.write_text(name)
    return project_dir, digest


_SCRIPT_CLASSES: dict[str, str] = {}


def _register_script(class_name: str, body: str) -> str:
    _SCRIPT_CLASSES[body] = class_name
    return body


# ── Ghidra post-scripts (Java, because Jython ships but Java is safest) ──

_LIST_FUNCTIONS = _register_script(
    "ListFunctions",
    """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class ListFunctions extends GhidraScript {
    public void run() throws Exception {
        String out = System.getenv("GHIDRA_OUT");
        PrintWriter w = new PrintWriter(out);
        w.println("[");
        boolean first = true;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!first) w.println(",");
            first = false;
            w.print(String.format(
                "  {\\"name\\": \\"%s\\", \\"entry\\": \\"0x%s\\", \\"size\\": %d, \\"thunk\\": %b, \\"external\\": %b}",
                f.getName().replace("\\"", "\\\\\\""),
                f.getEntryPoint().toString(),
                f.getBody().getNumAddresses(),
                f.isThunk(),
                f.isExternal()
            ));
        }
        w.println();
        w.println("]");
        w.close();
    }
}
""",
)

_DECOMPILE_FUNCTION = _register_script(
    "DecompileFunction",
    """
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DecompileFunction extends GhidraScript {
    public void run() throws Exception {
        String target = System.getenv("GHIDRA_TARGET");
        String out = System.getenv("GHIDRA_OUT");
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Function fn = null;
        if (target.startsWith("0x") || target.matches("[0-9a-fA-F]+")) {
            Address addr = currentProgram.getAddressFactory().getAddress(
                target.startsWith("0x") ? target.substring(2) : target);
            fn = getFunctionContaining(addr);
        } else {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(target)) { fn = f; break; }
            }
        }
        PrintWriter w = new PrintWriter(out);
        if (fn == null) {
            w.println("// function not found: " + target);
        } else {
            DecompileResults r = di.decompileFunction(fn, 60, monitor);
            if (r != null && r.getDecompiledFunction() != null) {
                w.println("// " + fn.getName() + " @ " + fn.getEntryPoint());
                w.println(r.getDecompiledFunction().getC());
            } else {
                w.println("// decompilation failed for " + target);
            }
        }
        w.close();
    }
}
""",
)

_LIST_STRINGS = _register_script(
    "ListStrings",
    """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;

public class ListStrings extends GhidraScript {
    public void run() throws Exception {
        String out = System.getenv("GHIDRA_OUT");
        String pattern = System.getenv("GHIDRA_PATTERN");
        PrintWriter w = new PrintWriter(out);
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                if (pattern == null || pattern.isEmpty() || val.contains(pattern)) {
                    w.print(d.getAddress() + "\\t" + val);
                    Reference[] refs = getReferencesTo(d.getAddress());
                    if (refs.length > 0) {
                        w.print("\\t<-");
                        for (Reference r : refs) w.print(" " + r.getFromAddress());
                    }
                    w.println();
                }
            }
        }
        w.close();
    }
}
""",
)

_XREFS_TO = _register_script(
    "XrefsTo",
    """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class XrefsTo extends GhidraScript {
    public void run() throws Exception {
        String target = System.getenv("GHIDRA_TARGET");
        String out = System.getenv("GHIDRA_OUT");
        Address addr = currentProgram.getAddressFactory().getAddress(
            target.startsWith("0x") ? target.substring(2) : target);
        PrintWriter w = new PrintWriter(out);
        for (Reference r : getReferencesTo(addr)) {
            Function from = getFunctionContaining(r.getFromAddress());
            w.println(r.getFromAddress() + "\\t" + r.getReferenceType() +
                "\\t" + (from == null ? "<none>" : from.getName()));
        }
        w.close();
    }
}
""",
)


async def _run_script(
    binary: Path,
    script_body: str,
    target: str | None,
    pattern: str | None,
    timeout: int,
) -> str:
    headless = _resolve_headless()
    if not headless:
        raise RuntimeError(_missing_message())

    project_dir, digest = await _ensure_analyzed(binary, timeout)
    class_name = _SCRIPT_CLASSES[script_body]

    # Each invocation gets its own scratch dir so concurrent calls
    # don't clobber each other's <ClassName>.java / <ClassName>.out.
    script_dir = Path(tempfile.mkdtemp(prefix="dn-ghidra-"))
    try:
        final_path = script_dir / f"{class_name}.java"
        final_path.write_text(script_body)
        out_path = script_dir / f"{class_name}.out"

        env_overrides = os.environ.copy()
        env_overrides["GHIDRA_OUT"] = str(out_path)
        if target is not None:
            env_overrides["GHIDRA_TARGET"] = target
        if pattern is not None:
            env_overrides["GHIDRA_PATTERN"] = pattern

        args = [
            str(project_dir),
            digest,
            "-process",
            binary.name,
            "-scriptPath",
            str(script_dir),
            "-postScript",
            final_path.name,
            "-noanalysis",
            "-readOnly",
        ]

        proc = await asyncio.create_subprocess_exec(
            str(headless),
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env_overrides,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise TimeoutError(f"Ghidra script timed out after {timeout}s") from None

        result = out_path.read_text() if out_path.exists() else ""
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)

    if proc.returncode != 0 and not result:
        raise RuntimeError(
            f"Ghidra exited {proc.returncode}\n"
            f"--- stdout ---\n{stdout.decode(errors='replace')}\n"
            f"--- stderr ---\n{stderr.decode(errors='replace')}"
        )
    return _truncate(result or "(no output produced)")


# ── tools ────────────────────────────────────────────────────────────


@mcp.tool
async def ghidra_status() -> dict[str, Any]:
    """Report how the MCP would invoke Ghidra on this host."""
    headless = _resolve_headless()
    return {
        "platform": sys.platform,
        "headless": str(headless) if headless else None,
        "project_root": str(PROJECT_ROOT),
        "timeout_seconds": DEFAULT_TIMEOUT,
        "hint": None if headless else _missing_message(),
    }


@mcp.tool
async def ghidra_analyze(
    path: Annotated[str, "Path to the PE to import and auto-analyze"],
    timeout: Annotated[int, "Analysis timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Import the binary and run Ghidra auto-analysis (idempotent, cached).

    Subsequent tool calls (list/decompile/strings/xrefs) re-use the
    cached project under GHIDRA_PROJECT_ROOT. Call this first; it is a
    no-op for any binary that has already been analyzed.
    """
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"file does not exist: {p}")
    project_dir, digest = await _ensure_analyzed(p, timeout)
    return json.dumps(
        {
            "project": str(project_dir),
            "project_name": digest,
            "binary": p.name,
            "cached": (project_dir / ".analyzed").exists(),
        },
        indent=2,
    )


@mcp.tool
async def ghidra_list_functions(
    path: Annotated[str, "Path to the PE"],
    timeout: Annotated[int, "Timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """List every function (name, entry address, size, thunk/external) as JSON."""
    p = Path(path).expanduser().resolve()
    return await _run_script(p, _LIST_FUNCTIONS, None, None, timeout)


@mcp.tool
async def ghidra_decompile(
    path: Annotated[str, "Path to the PE"],
    target: Annotated[str, "Function name OR address like 0x401000"],
    timeout: Annotated[int, "Timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Decompile a single function to pseudo-C.

    Use ghidra_list_functions first to discover names/addresses. For
    crackmes the interesting function is usually reachable from main,
    WinMain, or a thread proc.
    """
    p = Path(path).expanduser().resolve()
    return await _run_script(p, _DECOMPILE_FUNCTION, target, None, timeout)


@mcp.tool
async def ghidra_strings(
    path: Annotated[str, "Path to the PE"],
    pattern: Annotated[str, "Optional substring filter (empty = all)"] = "",
    timeout: Annotated[int, "Timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """List defined strings and the addresses that reference them.

    Unlike pe_strings (raw byte scan), this uses Ghidra's string
    detection so each hit is tied to code that reads it. That makes it
    easy to jump from a suspected flag string to the checking routine.
    """
    p = Path(path).expanduser().resolve()
    return await _run_script(p, _LIST_STRINGS, None, pattern, timeout)


@mcp.tool
async def ghidra_xrefs_to(
    path: Annotated[str, "Path to the PE"],
    address: Annotated[str, "Address like 0x401000"],
    timeout: Annotated[int, "Timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Return all code references to `address` (caller, ref-type, containing function)."""
    p = Path(path).expanduser().resolve()
    return await _run_script(p, _XREFS_TO, address, None, timeout)


if __name__ == "__main__":
    mcp.run()
