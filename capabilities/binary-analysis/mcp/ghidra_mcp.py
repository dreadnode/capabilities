#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pyghidra-mcp",
# ]
# ///
"""ghidra-mcp — the capability's Ghidra MCP server: pyghidra-mcp extended in-process.

pyghidra-mcp ships decompilation, xrefs, callgraph, symbol/string search,
semantic `search_code`, and write-back (rename / retype / prototype / comment).
It does NOT ship the surface the validated-annotation loop needs for similarity
(#3), deeper dataflow reasoning (#2), and executable proof (Tier-3). This module
adds exactly those, reachable through the same embedded PyGhidra process — no
second server, no Java build, no HTTP bridge.

  * ghidra_status        — report which extra Ghidra features (FID / BSim /
                           emulator / decompiler) load in this runtime
  * function_fid_hash    — FunctionID fingerprint of a function; the basis of
                           library/function matching (Tier-1 similarity, #3).
                           No FID database needed to GENERATE the hash — a .fidb
                           is only needed to MATCH it against known libraries.
  * function_dataflow    — decompiler HighFunction dataflow summary: recovered
                           params/locals + types, calls, P-code op count (#2)
  * emulate_function     — EmulatorHelper concrete execution: run the real
                           function on test inputs and read back registers, to
                           PROVE a hypothesized semantics (Tier-3; the
                           reimplementation is the deliverable)
  * diff_binaries        — function-level diff of two project binaries (#5
                           patch / variant diffing): unchanged / changed / added /
                           removed, via Ghidra's MatchFunctions hasher cascade
                           (exact instructions → symbol name → structural CFG
                           hash). DB-free; stripped binaries included.
  * diff_function        — side-by-side decompilation + unified C diff of one
                           matched pair surfaced by diff_binaries
  * bsim_build_database  — build/extend a local BSim signature DB (embedded H2)
                           from project binaries — the corpus for fuzzy
                           similarity (#3)
  * bsim_query_function  — query one function against a BSim DB for similar
                           functions (Tier-1 FUZZY library/variant ID — the
                           complement to function_fid_hash's exact match)
  * bsim_overview        — best BSim match per function: the annotation-queue
                           denoiser (drop known/library code, keep novel)

Architecture (why composition, not a fork or a backend swap): pyghidra-mcp
registers tools as plain `def fn(..., ctx)` functions on an importable FastMCP
`mcp` object and exposes a Click `main()` that runs that same object. We import
it, register our tools on its `mcp`, and delegate to `base.main()`. The result
is one stdio server exposing the FULL pyghidra-mcp surface PLUS these extras,
all sharing the one analyzed Ghidra project (so no project-lock conflict). This
keeps the headless / uvx / no-build / Apache-2.0 / semantic-search identity of
the incumbent. Chosen over the in-Ghidra-plugin servers (bethington/ghidra-mcp,
LaurieWired/GhidraMCP — they need a Java build + HTTP bridge and default to the
GUI) and the GPL / Binary-Ninja alternatives after a per-MCP audit; every
mechanism below is plain Ghidra Java API reached in-process via PyGhidra.

The diff tools (diff_binaries / diff_function) reimplement the function-matching
cascade of ghidriff (clearbluejar; 769*, Apache-Ghidra underneath but GPL-3.0
licensed) against Ghidra's own Apache-2.0 `match` API — clean-room from its
documented design, deliberately NOT vendored: `import ghidriff` is
distribution-triggered copyleft that would conflict with this repo's MIT/Apache
posture, and subprocessing its CLI reintroduces the out-of-process boundary that
in-process composition exists to avoid. We reproduce the approach, not the code.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import os
from collections import defaultdict
from typing import Annotated, Any

import pyghidra_mcp.server as base
from mcp.server.fastmcp import Context

# Extend the incumbent's FastMCP instance in place. base.main() runs THIS object.
mcp = base.mcp


# ── helpers (pure / JVM-free so they unit-test without Ghidra) ────────────


def _drop_empty(d: dict[str, Any]) -> dict[str, Any]:
    """Null-omit per repo convention: drop None/""/[]/{}, keep 0 and False."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _u64(v: int) -> str:
    """Format a (possibly Java-signed) integer as an unsigned 64-bit hex string."""
    return f"0x{int(v) & 0xFFFFFFFFFFFFFFFF:016x}"


def _is_default_name(name: str) -> bool:
    """True if `name` is a Ghidra auto-generated function name (no human label).

    Such names carry no cross-binary signal, so the symbol-name diff pass skips
    them — a stripped binary is all `FUN_*`, and pairing two unrelated `FUN_*` by
    string equality would be noise. Mirrors the annotation loop's only-touch-
    default-names rule.
    """
    return name.startswith(("FUN_", "thunk_FUN_"))


def _struct_hash(features: list[tuple[int, int]]) -> str:
    """Stable hash of a function's control-flow shape.

    `features` is the per-basic-block (in-degree, out-degree) list. We hash the
    block count, total edge count, and the SORTED degree multiset — so the hash
    is invariant to block ordering and to instruction-level edits, but changes
    when the control-flow topology does. Two functions with the same shape but
    edited instructions hash equal: exactly the *changed* pair a stripped diff
    must recover when exact-instruction and symbol-name matching both miss.
    Grounded in CFG fingerprinting (Dullien & Rolles, graph-based comparison of
    executable objects) — reimplemented from that public technique, not copied.
    """
    edges = sum(out for _, out in features)
    degrees = ";".join(f"{i},{o}" for i, o in sorted(features))
    return hashlib.sha256(f"{len(features)}:{edges}:{degrees}".encode()).hexdigest()[
        :16
    ]


def _similarity_ratio(a: list[str], b: list[str]) -> float:
    """0..1 ratio over two instruction-mnemonic sequences — how much a matched
    pair actually changed. 1.0 = identical mnemonic stream; lower = more edited.
    Used to rank changed functions (most-changed first) for a patch-diff reader.
    """
    if not a and not b:
        return 1.0
    return round(difflib.SequenceMatcher(None, a, b).ratio(), 3)


def _bsim_db_path(database: str) -> str:
    """Filesystem base path for a named BSim H2 database under the cache root.

    Mirrors the capability.yaml cache convention
    (`$BINANAL_CACHE_ROOT` or `~/.dreadnode/cache/binary-analysis`) with a `bsim/`
    subdir. The H2 engine appends its own extension to this base. Creates the
    directory so callers can write into it."""
    root = os.environ.get("BINANAL_CACHE_ROOT") or os.path.expanduser(
        "~/.dreadnode/cache/binary-analysis"
    )
    bsim_dir = os.path.join(root, "bsim")
    os.makedirs(bsim_dir, exist_ok=True)
    return os.path.join(bsim_dir, database)


# ── helpers that touch the JVM (import Ghidra lazily, at call time) ────────


def _program(ctx: Context, binary_name: str):
    """Resolve the raw Ghidra Program for a project binary via pyghidra-mcp's
    lifespan context. Raises (surfaced as a tool error) if the name is unknown."""
    pyghidra_context = ctx.request_context.lifespan_context
    return pyghidra_context.get_program_info(binary_name).program


def _monitor():
    from ghidra.util.task import ConsoleTaskMonitor

    return ConsoleTaskMonitor()


def _resolve_function(program, target: str):
    """Resolve a function by symbol name or by address (hex `0x...` or decimal).

    Raises ValueError if no function matches — let it surface as a tool error
    rather than returning an error union (FastMCP renders raises cleanly).
    """
    fm = program.getFunctionManager()
    try:
        addr = program.getAddressFactory().getAddress(target)
    except Exception:
        addr = None
    if addr is not None:
        fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if fn is not None:
            return fn
    for fn in fm.getFunctions(True):
        if fn.getName() == target:
            return fn
    raise ValueError(f"function not found by name or address: {target!r}")


# ── ghidra_status ─────────────────────────────────────────────────────────


@mcp.tool()
async def ghidra_status() -> dict[str, Any]:
    """Report which extra Ghidra features load in this PyGhidra runtime.

    Each entry is "ok" or a one-line reason. These are Ghidra Java features that
    a stripped/minimal Ghidra install could lack — probe here so a missing
    feature surfaces explicitly instead of failing mid-analysis. (The core
    pyghidra-mcp tools and Qiling/angr are reported elsewhere; this covers only
    the tools this server adds.)
    """

    def _probe() -> dict[str, Any]:
        status: dict[str, Any] = {}
        for label, importer in (
            (
                "fid",
                lambda: __import__(
                    "ghidra.feature.fid.service", fromlist=["FidService"]
                ),
            ),
            (
                "emulator",
                lambda: __import__("ghidra.app.emulator", fromlist=["EmulatorHelper"]),
            ),
            (
                "decompiler",
                lambda: __import__(
                    "ghidra.app.decompiler", fromlist=["DecompInterface"]
                ),
            ),
            (
                "bsim",
                lambda: __import__(
                    "ghidra.features.bsim.query", fromlist=["GenSignatures"]
                ),
            ),
        ):
            try:
                importer()
                status[label] = "ok"
            except Exception as e:  # noqa: BLE001 — report, don't crash status
                status[label] = f"unavailable: {e}"
        return status

    return await asyncio.to_thread(_probe)


# ── function_fid_hash ─────────────────────────────────────────────────────


@mcp.tool()
async def function_fid_hash(
    binary_name: Annotated[str, "Binary as listed by list_project_binaries"],
    name_or_address: Annotated[str, "Function name, or address as 0xHEX / decimal"],
    ctx: Context,
) -> dict[str, Any]:
    """Compute Ghidra FunctionID (FID) hashes for a function.

    FID hashes are the fingerprints library/function matching is built on: two
    functions sharing a full hash are near-identical code. This GENERATES the
    fingerprint with no FID database — a .fidb is only needed to MATCH it against
    known libraries (Tier-1 similarity / library denoise, #3). Returns
    `fid: null` with a reason when the function is below FID's size threshold
    (too small to fingerprint meaningfully).
    """
    program = _program(ctx, binary_name)

    def _hash() -> dict[str, Any]:
        from ghidra.feature.fid.service import FidService

        fn = _resolve_function(program, name_or_address)
        hq = FidService().hashFunction(fn)
        if hq is None:
            return {
                "function": fn.getName(),
                "address": str(fn.getEntryPoint()),
                "fid": None,
                "reason": "below FID size threshold",
            }
        return _drop_empty(
            {
                "function": fn.getName(),
                "address": str(fn.getEntryPoint()),
                "full_hash": _u64(hq.getFullHash()),
                "specific_hash": _u64(hq.getSpecificHash()),
                "code_unit_size": int(hq.getCodeUnitSize()),
            }
        )

    return await asyncio.to_thread(_hash)


# ── function_dataflow ─────────────────────────────────────────────────────


@mcp.tool()
async def function_dataflow(
    binary_name: Annotated[str, "Binary as listed by list_project_binaries"],
    name_or_address: Annotated[str, "Function name, or address as 0xHEX / decimal"],
    ctx: Context,
    timeout_sec: Annotated[int, "Per-function decompile timeout"] = 30,
) -> dict[str, Any]:
    """Decompiler dataflow summary for a function (HighFunction / P-code).

    Returns recovered parameters and local variables with inferred types, the
    functions it calls, and the P-code op count — the dataflow basis for
    reasoning about what feeds a function and where its data goes (#2). Use it to
    cross-check a hypothesized label against actual data movement BEFORE
    committing a rename (Tier-0 structural validation in the annotation loop).
    """
    program = _program(ctx, binary_name)

    def _flow() -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface

        fn = _resolve_function(program, name_or_address)
        ifc = DecompInterface()
        try:
            ifc.openProgram(program)
            res = ifc.decompileFunction(fn, timeout_sec, _monitor())
            high = res.getHighFunction() if res is not None else None

            params = [
                _drop_empty({"name": p.getName(), "type": p.getDataType().getName()})
                for p in fn.getParameters()
            ]
            calls = sorted({f.getName() for f in fn.getCalledFunctions(_monitor())})

            local_vars: list[dict[str, Any]] = []
            pcode_ops = 0
            if high is not None:
                pcode_ops = sum(1 for _ in high.getPcodeOps())
                for sym in high.getLocalSymbolMap().getSymbols():
                    dt = sym.getDataType()
                    local_vars.append(
                        _drop_empty(
                            {
                                "name": sym.getName(),
                                "type": dt.getName() if dt else None,
                            }
                        )
                    )

            return _drop_empty(
                {
                    "function": fn.getName(),
                    "address": str(fn.getEntryPoint()),
                    "return_type": fn.getReturnType().getName(),
                    "parameters": params,
                    "local_variables": local_vars,
                    "calls": calls,
                    "pcode_op_count": pcode_ops,
                }
            )
        finally:
            ifc.dispose()

    return await asyncio.to_thread(_flow)


# ── emulate_function ──────────────────────────────────────────────────────


@mcp.tool()
async def emulate_function(
    binary_name: Annotated[str, "Binary as listed by list_project_binaries"],
    name_or_address: Annotated[str, "Function name, or address as 0xHEX / decimal"],
    ctx: Context,
    registers: Annotated[
        dict[str, int] | None, "Register presets before run, e.g. arg registers"
    ] = None,
    memory: Annotated[
        dict[str, str] | None, "Memory to write first: {address(0xHEX): hex-bytes}"
    ] = None,
    read_registers: Annotated[
        list[str] | None, "Register names to read back after the run"
    ] = None,
    max_steps: Annotated[int, "Max instructions before giving up"] = 200,
) -> dict[str, Any]:
    """Concretely execute a function under Ghidra's emulator (Tier-3 repro).

    Writes any `memory` inputs and `registers` presets, runs from the function
    entry until it returns (execution leaves the function body) or `max_steps`,
    then reads back `read_registers`. Use it to PROVE a hypothesized function
    semantics: run the real function on test inputs and compare to your
    reimplementation — the reimplementation is the deliverable, the match is the
    proof. Best on side-effect-light, self-contained functions (crypto / codec /
    checksum / custom cipher). Functions with heavy global or external
    dependencies may not emulate in isolation; that's expected — fall back to
    structural validation and record the function as repro-infeasible.
    """
    program = _program(ctx, binary_name)

    def _emu() -> dict[str, Any]:
        from ghidra.app.emulator import EmulatorHelper
        from java.math import BigInteger

        fn = _resolve_function(program, name_or_address)
        af = program.getAddressFactory()
        emu = EmulatorHelper(program)
        try:
            if memory:
                for addr_s, hexbytes in memory.items():
                    emu.writeMemory(af.getAddress(addr_s), bytes.fromhex(hexbytes))
            if registers:
                for rname, val in registers.items():
                    emu.writeRegister(rname, BigInteger(str(int(val))))

            entry = fn.getEntryPoint()
            emu.writeRegister(emu.getPCRegister(), BigInteger(str(entry.getOffset())))

            body = fn.getBody()
            steps = 0
            halt_error = None
            for _ in range(max_steps):
                if not emu.step(_monitor()):
                    halt_error = str(emu.getLastError())
                    break
                steps += 1
                cur = emu.getExecutionAddress()
                if cur is None or not body.contains(cur):
                    break

            reads: dict[str, Any] = {}
            for rname in read_registers or []:
                try:
                    reads[rname] = _u64(emu.readRegister(rname).longValue())
                except Exception as e:  # noqa: BLE001 — per-register, keep going
                    reads[rname] = f"error: {e}"

            return _drop_empty(
                {
                    "function": fn.getName(),
                    "steps": steps,
                    "final_pc": str(emu.getExecutionAddress()),
                    "registers": reads,
                    "halt_error": halt_error,
                    "max_steps_reached": steps >= max_steps and halt_error is None,
                }
            )
        finally:
            emu.dispose()

    return await asyncio.to_thread(_emu)


# ── diffing helpers (JVM; #5) ─────────────────────────────────────────────


def _iter_functions(program) -> list:
    """Real, non-external, non-thunk functions in a program (the diff universe).

    Thunks are skipped — they're trivial forwarders that pair noisily."""
    fm = program.getFunctionManager()
    return [f for f in fm.getFunctions(True) if not f.isExternal() and not f.isThunk()]


def _function_body_set(functions: list):
    """AddressSet covering every function body — what MatchFunctions matches over."""
    from ghidra.program.model.address import AddressSet

    s = AddressSet()
    for f in functions:
        s.add(f.getBody())
    return s


def _cfg_features(bbm, func, monitor) -> list[tuple[int, int]]:
    """Per-basic-block (in-degree, out-degree) for a function's CFG (for _struct_hash)."""
    feats: list[tuple[int, int]] = []
    blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)
    while blocks.hasNext():
        block = blocks.next()
        in_deg = 0
        srcs = block.getSources(monitor)
        while srcs.hasNext():
            srcs.next()
            in_deg += 1
        out_deg = 0
        dsts = block.getDestinations(monitor)
        while dsts.hasNext():
            dsts.next()
            out_deg += 1
        feats.append((in_deg, out_deg))
    return feats


def _mnemonics(program, func) -> list[str]:
    """Ordered instruction mnemonics over a function's body (for _similarity_ratio)."""
    out: list[str] = []
    instrs = program.getListing().getInstructions(func.getBody(), True)
    while instrs.hasNext():
        out.append(instrs.next().getMnemonicString())
    return out


def _diff_programs(p1, p2, monitor) -> dict[str, Any]:
    """Function-level diff of two analyzed programs via the MatchFunctions cascade.

    Three passes, each over the survivors of the last:
      1. exact instructions (Ghidra `ExactInstructionsFunctionHasher`) → UNCHANGED
      2. symbol name, non-default only (`MatchSymbol`-style) → CHANGED
      3. structural CFG hash (`_struct_hash`) → CHANGED (recovers stripped edits)
    Leftovers are added (only in p2) / removed (only in p1).
    """
    from ghidra.app.plugin.match import (
        ExactInstructionsFunctionHasher,
        MatchFunctions,
    )
    from ghidra.program.model.block import BasicBlockModel

    funcs1 = {f.getEntryPoint(): f for f in _iter_functions(p1)}
    funcs2 = {f.getEntryPoint(): f for f in _iter_functions(p2)}
    matched: list[tuple[Any, Any, str, float | None]] = []  # (f1, f2, how, similarity)
    m1: set = set()
    m2: set = set()

    # Mnemonic sequences are reused for both similarity scoring and structural
    # bucket refinement — cache them per (program, function).
    _mnem: dict = {}

    def mnem(program, addr, fn) -> list[str]:
        key = (id(program), addr)
        if key not in _mnem:
            _mnem[key] = _mnemonics(program, fn)
        return _mnem[key]

    # Pass 1 — exact instructions ⇒ unchanged.
    hasher = (
        getattr(ExactInstructionsFunctionHasher, "INSTANCE", None)
        or ExactInstructionsFunctionHasher()
    )
    for r in MatchFunctions.matchFunctions(
        p1,
        _function_body_set(list(funcs1.values())),
        p2,
        _function_body_set(list(funcs2.values())),
        1,  # minimum function size; keep small so tiny funcs still pair as unchanged
        True,  # include one-to-one
        False,  # exclude non-one-to-one (ambiguous; later passes handle the rest)
        hasher,
        monitor,
    ):
        a, b = r.getAFunctionAddress(), r.getBFunctionAddress()
        if a in funcs1 and b in funcs2 and a not in m1 and b not in m2:
            matched.append((funcs1[a], funcs2[b], "exact", None))
            m1.add(a)
            m2.add(b)

    # Pass 2 — symbol name (non-default) ⇒ changed (renamed-or-edited same symbol).
    name2: dict[str, list] = defaultdict(list)
    for a, f in funcs2.items():
        if a not in m2 and not _is_default_name(f.getName()):
            name2[f.getName()].append((a, f))
    for a, f in funcs1.items():
        if a in m1 or _is_default_name(f.getName()):
            continue
        bucket = name2.get(f.getName())
        if bucket:
            b, fb = bucket.pop(0)
            sim = _similarity_ratio(mnem(p1, a, f), mnem(p2, b, fb))
            matched.append((f, fb, "symbol-name", sim))
            m1.add(a)
            m2.add(b)

    # Pass 3 — structural CFG hash ⇒ changed (stripped edits exact+name miss).
    # The CFG-degree hash is a COARSE bucketer — trivial leaf functions collide —
    # so within each bucket we score every candidate pair by mnemonic similarity
    # and assign greedily best-first, one-to-one. This is what stops a stripped
    # `mul` from pairing with an unrelated same-shape `sub`.
    bbm1, bbm2 = BasicBlockModel(p1), BasicBlockModel(p2)
    buckets2: dict[str, list] = defaultdict(list)
    for a, f in funcs2.items():
        if a not in m2:
            buckets2[_struct_hash(_cfg_features(bbm2, f, monitor))].append((a, f))
    candidates: list[tuple[float, Any, Any]] = []  # (similarity, a1, b2)
    for a, f in funcs1.items():
        if a in m1:
            continue
        for b, fb in buckets2.get(_struct_hash(_cfg_features(bbm1, f, monitor)), []):
            candidates.append(
                (_similarity_ratio(mnem(p1, a, f), mnem(p2, b, fb)), a, b)
            )
    candidates.sort(key=lambda c: c[0], reverse=True)  # best matches first
    for sim, a, b in candidates:
        if a in m1 or b in m2:
            continue
        matched.append((funcs1[a], funcs2[b], "structural", sim))
        m1.add(a)
        m2.add(b)

    # Partition.
    unchanged = 0
    changed: list[dict[str, Any]] = []
    for f1, f2, how, sim in matched:
        if how == "exact":
            unchanged += 1
            continue
        changed.append(
            {
                "primary_address": str(f1.getEntryPoint()),
                "secondary_address": str(f2.getEntryPoint()),
                "primary_name": f1.getName(),
                "secondary_name": f2.getName(),
                "similarity": sim,
                "matched_by": how,
            }
        )
    changed.sort(key=lambda c: c["similarity"])  # most-changed first
    removed = [
        {"address": str(a), "name": funcs1[a].getName()} for a in funcs1 if a not in m1
    ]
    added = [
        {"address": str(a), "name": funcs2[a].getName()} for a in funcs2 if a not in m2
    ]
    return _drop_empty(
        {
            "summary": {
                "unchanged": unchanged,
                "changed": len(changed),
                "added": len(added),
                "removed": len(removed),
            },
            "changed": changed,
            "added": added,
            "removed": removed,
        }
    )


# ── diff_binaries ─────────────────────────────────────────────────────────


@mcp.tool()
async def diff_binaries(
    primary: Annotated[str, "Baseline binary, as listed by list_project_binaries"],
    secondary: Annotated[str, "Comparison binary (e.g. the patched or variant build)"],
    ctx: Context,
) -> dict[str, Any]:
    """Diff two project binaries at function granularity (#5 patch / variant diff).

    Matches functions between the two binaries and reports the partition:
    `unchanged` (count only — not the signal), `changed` (matched but edited, with
    a 0..1 `similarity` and `matched_by` provenance, sorted most-changed first),
    `added` (only in secondary), `removed` (only in primary). The changed set IS
    the patch / the variant delta — feed it to the annotation loop as the queue.

    Both binaries must be loaded in the Ghidra project first (`import_binary`).
    Stripped binaries diff too: exact-instruction matching finds unchanged
    functions and a control-flow-structure hash recovers changed ones even with no
    symbols (a changed function with neither identical instructions nor a stable
    symbol falls to added+removed — the structural pass is what prevents that).
    """
    p1 = _program(ctx, primary)
    p2 = _program(ctx, secondary)

    def _run() -> dict[str, Any]:
        out = _diff_programs(p1, p2, _monitor())
        return {"primary": primary, "secondary": secondary, **out}

    return await asyncio.to_thread(_run)


# ── diff_function ─────────────────────────────────────────────────────────


@mcp.tool()
async def diff_function(
    primary: Annotated[str, "Baseline binary, as listed by list_project_binaries"],
    secondary: Annotated[str, "Comparison binary"],
    primary_name_or_address: Annotated[
        str, "Function in the baseline — name or 0xHEX / decimal address"
    ],
    secondary_name_or_address: Annotated[
        str, "The matched function in the comparison — name or 0xHEX / decimal"
    ],
    ctx: Context,
    timeout_sec: Annotated[int, "Per-function decompile timeout"] = 30,
) -> dict[str, Any]:
    """Side-by-side decompilation of one matched function pair from diff_binaries.

    Decompiles both functions and returns each one's C plus a unified diff of the
    two — so reading *what* changed in a flagged function is one tool call instead
    of two `decompile_function`s and a manual compare. Pass the
    `primary_address` / `secondary_address` of a `changed` entry from
    `diff_binaries`.
    """
    p1 = _program(ctx, primary)
    p2 = _program(ctx, secondary)

    def _run() -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface

        f1 = _resolve_function(p1, primary_name_or_address)
        f2 = _resolve_function(p2, secondary_name_or_address)

        def _decompile(program, fn) -> str:
            ifc = DecompInterface()
            try:
                ifc.openProgram(program)
                res = ifc.decompileFunction(fn, timeout_sec, _monitor())
                df = res.getDecompiledFunction() if res is not None else None
                return df.getC() if df is not None else ""
            finally:
                ifc.dispose()

        c1 = _decompile(p1, f1)
        c2 = _decompile(p2, f2)
        unified = "".join(
            difflib.unified_diff(
                c1.splitlines(keepends=True),
                c2.splitlines(keepends=True),
                fromfile=f"{primary}:{f1.getName()}",
                tofile=f"{secondary}:{f2.getName()}",
            )
        )
        return _drop_empty(
            {
                "primary_function": f1.getName(),
                "secondary_function": f2.getName(),
                "similarity": _similarity_ratio(_mnemonics(p1, f1), _mnemonics(p2, f2)),
                "primary_c": c1,
                "secondary_c": c2,
                "unified_diff": unified,
            }
        )

    return await asyncio.to_thread(_run)


# ── BSim corpus similarity helpers (JVM; #3 fuzzy) ─────────────────────────
#
# BSim is Ghidra's feature-vector (decompiler P-code → LSH) similarity engine.
# We drive its embedded H2 backend in-process — create a local signature DB,
# ingest project binaries, and query functions against it for fuzzy
# library/variant identification (Tier-1) and queue denoising. All Apache-2.0
# Ghidra API; verified reachable single-process (no project/H2 lock deadlock).
# Each tool call opens its own client and disposes the H2 datasource in an outer
# finally after closing, so independent calls don't collide even when one raises.


def _bsim_server(database: str):
    from ghidra.features.bsim.query import BSimServerInfo

    return BSimServerInfo(_bsim_db_path(database))


def _bsim_db_exists(database: str) -> bool:
    from ghidra.features.bsim.query import BSimServerInfo

    return os.path.exists(_bsim_db_path(database) + BSimServerInfo.H2_FILE_EXTENSION)


def _bsim_dispose_datasource(server) -> None:
    """Fully release the H2 datasource so the next independent tool call can open
    the database without hitting H2's single-connection guard."""
    from ghidra.features.bsim.query.file import BSimH2FileDBConnectionManager

    bds = BSimH2FileDBConnectionManager.getDataSourceIfExists(server)
    if bds is not None:
        bds.dispose()


def _bsim_project_coords(program) -> tuple[str, str]:
    """(project URL, path) for a program — GenSignatures.openProgram parses the
    repo arg as a java.net.URL, so it needs the real project URL (not a
    placeholder). Derived from the domain file as Ghidra's own BSim add-script does."""
    from ghidra.framework.protocol.ghidra import GhidraURL

    dfile = program.getDomainFile()
    furl = dfile.getLocalProjectURL(None) or dfile.getSharedProjectURL(None)
    if furl is None:
        raise ValueError(
            "program has no project URL; BSim needs the binary in the Ghidra project"
        )
    path = GhidraURL.getProjectPathname(furl)
    i = path.rfind("/")
    path = "/" if i == 0 else path[:i]
    return GhidraURL.getProjectURL(furl).toExternalForm(), path


def _bsim_gensig(dbinfo, vector_factory, program, coords):
    """A GenSignatures bound to the DB's vector factory and the program."""
    from ghidra.features.bsim.query import GenSignatures

    repo, path = coords
    g = GenSignatures(dbinfo.trackcallgraph)
    g.setVectorFactory(vector_factory)
    g.addExecutableCategories(dbinfo.execats)
    g.addFunctionTags(dbinfo.functionTags)
    g.addDateColumnName(dbinfo.dateColumnName)
    g.openProgram(program, None, None, None, repo, path)
    return g


def _bsim_create_database(client, database: str) -> None:
    """Create a new embedded H2 BSim database on the open client (medium_nosize
    template, call-graph tracking on). Raises if creation fails."""
    from ghidra.features.bsim.query.description import DatabaseInformation
    from ghidra.features.bsim.query.protocol import CreateDatabase

    cmd = CreateDatabase()
    cmd.info = DatabaseInformation()
    cmd.info.databasename = database
    cmd.config_template = "medium_nosize"
    cmd.info.trackcallgraph = True
    if cmd.execute(client) is None:
        raise RuntimeError(f"BSim create failed: {client.getLastError().message}")


def _bsim_ingest_program(client, dbinfo, vector_factory, program) -> dict[str, Any]:
    """Sign a program's functions and insert them into the open BSim client.

    Returns {"functions_signed": n}, or {"skipped": reason} when the program has
    no signable functions (all below the significance threshold) or the insert is
    rejected (e.g. the executable is already in the database)."""
    from ghidra.features.bsim.query.protocol import InsertRequest

    g = _bsim_gensig(dbinfo, vector_factory, program, _bsim_project_coords(program))
    try:
        fm = program.getFunctionManager()
        g.scanFunctions(fm.getFunctions(True), fm.getFunctionCount(), _monitor())
        manager = g.getDescriptionManager()
        signed = manager.numFunctions()
        if signed == 0:
            return {"skipped": "no signable functions"}
        lit = manager.listAllFunctions()
        while lit.hasNext():
            lit.next().sortCallgraph()
        ins = InsertRequest()
        ins.manage = manager
        if ins.execute(client) is None:
            return {"skipped": client.getLastError().message}
        return {"functions_signed": signed}
    finally:
        g.dispose()


def _bsim_nearest(
    client, manager, max_matches: int, thresh: float, exclude_self: bool
) -> dict[str, list[dict[str, Any]]]:
    """Run QueryNearest for every function in `manager`; return
    {query_function_name: [match dicts sorted by the engine]}. `exclude_self`
    drops matches from the same executable (the queried binary's own self-hits)."""
    from ghidra.features.bsim.query.protocol import QueryNearest

    query = QueryNearest()
    query.manage = manager
    query.max = max_matches
    query.thresh = thresh
    query.signifthresh = 0.0
    nresp = query.execute(client)
    if nresp is None:
        raise RuntimeError(f"BSim query failed: {client.getLastError().message}")

    out: dict[str, list[dict[str, Any]]] = {}
    for simres in nresp.result:
        base = simres.getBase()
        base_md5 = base.getExecutableRecord().getMd5()
        notes: list[dict[str, Any]] = []
        nit = simres.iterator()
        while nit.hasNext():
            note = nit.next()
            fd = note.getFunctionDescription()
            exe = fd.getExecutableRecord()
            if exclude_self and exe.getMd5() == base_md5:
                continue
            notes.append(
                _drop_empty(
                    {
                        "function": fd.getFunctionName(),
                        "executable": exe.getNameExec(),
                        "similarity": round(note.getSimilarity(), 3),
                        "significance": round(note.getSignificance(), 2),
                    }
                )
            )
        out[base.getFunctionName()] = notes
    return out


# ── bsim_build_database ───────────────────────────────────────────────────


@mcp.tool()
async def bsim_build_database(
    binaries: Annotated[
        list[str], "Project binaries to sign (basenames from list_project_binaries)"
    ],
    database: Annotated[
        str,
        "BSim database name under the cache root — created if absent, else appended to",
    ],
    ctx: Context,
) -> dict[str, Any]:
    """Build or extend a local BSim signature database from project binaries (#3 fuzzy).

    Generates Ghidra BSim feature-vector signatures for each binary's functions
    and stores them in an embedded H2 database under the cache root (no server,
    no network). The DB is the corpus that `bsim_query_function` / `bsim_overview`
    match against — for recompiled-library ID, cross-compiler/variant matching,
    and denoising the annotation queue. Created on first call; later calls add
    more binaries. Functions below BSim's significance threshold (too small to
    fingerprint) are skipped. Returns per-binary signed counts; a binary already
    present, or with no signable functions, is reported as skipped rather than
    failing the call.
    """
    programs = {
        b: _program(ctx, b) for b in binaries
    }  # resolve first (raises on unknown)

    def _run() -> dict[str, Any]:
        from ghidra.features.bsim.query import BSimClientFactory

        server = _bsim_server(database)
        existed = _bsim_db_exists(database)
        try:
            client = BSimClientFactory.buildClient(server, False)
            try:
                if not existed:
                    _bsim_create_database(client, database)
                if not client.initialize():
                    raise RuntimeError(
                        f"BSim initialize failed: {client.getLastError().message}"
                    )
                dbinfo = client.getInfo()
                vector_factory = client.getLSHVectorFactory()
                executables = [
                    {
                        "binary": name,
                        **_bsim_ingest_program(client, dbinfo, vector_factory, program),
                    }
                    for name, program in programs.items()
                ]
            finally:
                client.close()
        finally:
            # Dispose in an outer finally so a raised build still releases the H2
            # datasource. Otherwise the next BSim call hits H2's single-connection
            # guard and the whole BSim surface wedges for the rest of the process.
            _bsim_dispose_datasource(server)
        return _drop_empty(
            {
                "database": database,
                "created": not existed,
                "executables": executables,
            }
        )

    return await asyncio.to_thread(_run)


# ── bsim_query_function ───────────────────────────────────────────────────


@mcp.tool()
async def bsim_query_function(
    binary_name: Annotated[str, "Binary as listed by list_project_binaries"],
    name_or_address: Annotated[str, "Function name, or address as 0xHEX / decimal"],
    database: Annotated[str, "BSim database name (built with bsim_build_database)"],
    ctx: Context,
    max_matches: Annotated[int, "Max matches to return"] = 10,
    min_similarity: Annotated[float, "Similarity threshold 0..1"] = 0.7,
    exclude_self: Annotated[
        bool, "Drop matches from the same executable (the binary's own self-hits)"
    ] = True,
) -> dict[str, Any]:
    """Query one function against a BSim database for similar functions (Tier-1 fuzzy ID, #3).

    Returns ranked matches (function name, executable, similarity, significance).
    A high-confidence hit names a stripped/recompiled function from known code —
    a verified Tier-1 label and a candidate to drop from the annotation queue.
    This is the *fuzzy* complement to `function_fid_hash` (exact): it matches
    recompiled/cross-compiler code that exact hashing misses. Build the database
    first. Returns `matches: []` with a reason when the function is below BSim's
    significance threshold (too small to fingerprint).
    """
    program = _program(ctx, binary_name)

    def _run() -> dict[str, Any]:
        from java.util import Collections

        from ghidra.features.bsim.query import BSimClientFactory

        if not _bsim_db_exists(database):
            raise ValueError(
                f"no BSim database {database!r}; build it with bsim_build_database first"
            )
        fn = _resolve_function(program, name_or_address)
        server = _bsim_server(database)
        try:
            client = BSimClientFactory.buildClient(server, False)
            try:
                if not client.initialize():
                    raise RuntimeError(
                        f"BSim initialize failed: {client.getLastError().message}"
                    )
                g = _bsim_gensig(
                    client.getInfo(),
                    client.getLSHVectorFactory(),
                    program,
                    _bsim_project_coords(program),
                )
                try:
                    g.scanFunctions(
                        Collections.singletonList(fn).iterator(), 1, _monitor()
                    )
                    if g.getDescriptionManager().numFunctions() == 0:
                        return {
                            "function": fn.getName(),
                            "address": str(fn.getEntryPoint()),
                            "matches": [],
                            "reason": "below BSim significance threshold",
                        }
                    by_func = _bsim_nearest(
                        client,
                        g.getDescriptionManager(),
                        max_matches,
                        min_similarity,
                        exclude_self,
                    )
                finally:
                    g.dispose()
            finally:
                client.close()
        finally:
            # Outer finally: a raised query (or the early empty-match return
            # above) must still release the H2 datasource, or the next BSim call
            # wedges on H2's single-connection guard.
            _bsim_dispose_datasource(server)
        return _drop_empty(
            {
                "function": fn.getName(),
                "address": str(fn.getEntryPoint()),
                "database": database,
                "matches": by_func.get(fn.getName(), []),
            }
        )

    return await asyncio.to_thread(_run)


# ── bsim_overview ─────────────────────────────────────────────────────────


@mcp.tool()
async def bsim_overview(
    binary_name: Annotated[str, "Binary as listed by list_project_binaries"],
    database: Annotated[str, "BSim database name (built with bsim_build_database)"],
    ctx: Context,
    min_similarity: Annotated[float, "Similarity threshold 0..1"] = 0.7,
) -> dict[str, Any]:
    """Best BSim match for every function in a binary — the annotation-queue denoiser (#3).

    For each function, its single strongest match in the database (excluding the
    binary's own self-hits). Functions with a high-confidence hit are known code
    (library / runtime / already-seen variant) — DROP them from the queue so
    reasoning budget goes to genuinely novel functions. On a statically-linked
    binary this is often the majority. Returns the matched functions sorted by
    descending similarity plus the matched/total counts; functions with no match
    above the threshold are the novel set (not listed). Build the database first.
    """
    program = _program(ctx, binary_name)

    def _run() -> dict[str, Any]:
        from ghidra.features.bsim.query import BSimClientFactory

        if not _bsim_db_exists(database):
            raise ValueError(
                f"no BSim database {database!r}; build it with bsim_build_database first"
            )
        server = _bsim_server(database)
        try:
            client = BSimClientFactory.buildClient(server, False)
            try:
                if not client.initialize():
                    raise RuntimeError(
                        f"BSim initialize failed: {client.getLastError().message}"
                    )
                fm = program.getFunctionManager()
                total = fm.getFunctionCount()
                g = _bsim_gensig(
                    client.getInfo(),
                    client.getLSHVectorFactory(),
                    program,
                    _bsim_project_coords(program),
                )
                try:
                    g.scanFunctions(fm.getFunctions(True), total, _monitor())
                    by_func = _bsim_nearest(
                        client, g.getDescriptionManager(), 1, min_similarity, True
                    )
                finally:
                    g.dispose()
            finally:
                client.close()
        finally:
            # Outer finally so a raised query still releases the H2 datasource —
            # otherwise the next BSim call wedges on the single-connection guard.
            _bsim_dispose_datasource(server)

        matched = [
            {
                "function": name,
                "best_match": notes[0]["function"],
                "executable": notes[0].get("executable"),
                "similarity": notes[0]["similarity"],
            }
            for name, notes in by_func.items()
            if notes
        ]
        matched.sort(key=lambda m: m["similarity"], reverse=True)
        return _drop_empty(
            {
                "database": database,
                "total_functions": total,
                "matched_functions": len(matched),
                "matches": [_drop_empty(m) for m in matched],
            }
        )

    return await asyncio.to_thread(_run)


if __name__ == "__main__":
    # Delegate to pyghidra-mcp's Click CLI; it runs `mcp` (now carrying our
    # extra tools) with the same options the capability.yaml entry passes.
    base.main()
