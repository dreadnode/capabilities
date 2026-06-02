# Symbolic Execution Reference (angr)

[angr](https://github.com/angr/angr) is a Python framework for binary symbolic execution. The library is the right tool when:

- You need to recover an input that drives the binary to a specific state (CTF flag check, license validation, password compare) and Qiling's hook-and-dump doesn't reach it
- The validation logic depends on input *symbolically* (e.g. `(input[0] ^ 0x37) + input[1] == 0xC8`) rather than comparing against a stored constant — Qiling can dump a stored expected value, angr can solve for a derived one
- You want path-aware analysis: "what input takes execution through this branch and not that one"

If you only need to dump a stored expected value at a comparison site, prefer the Qiling **dump-at-API** pattern (`qiling-emulation.md`) — it's cheaper and doesn't pay the symbolic-execution explosion cost.

If static analysis can answer the question, prefer that. Symbolic execution is slow, state-explodes on real-world code, and is non-trivial to scope.

## Install

```bash
# angr is a heavyweight install (pulls z3, claripy, pyvex, cle, ailment, pypcode)
uv tool install angr
# or for one-off scripts: uv run --with angr python script.py
```

Verified working: **angr 9.2.x** (2026-05).

## Pattern 1 — find/avoid: solve for an input that reaches a target state

The bread-and-butter pattern. Make the input symbolic, mark target and dead-end states, let angr's solver give you a satisfying input.

Worked example: a binary that prints `GOOD` if `argv[1] == "OPEN"` and `BAD` otherwise. We recover `b"OPEN"` without reading the binary's logic.

```python
import angr, claripy, logging
logging.getLogger("angr").setLevel("ERROR")
logging.getLogger("cle").setLevel("ERROR")

PATH = "/path/to/target"
proj = angr.Project(PATH, auto_load_libs=False)

# Symbolic argv[1], 16 bytes
arg = claripy.BVS("arg", 16 * 8)
state = proj.factory.entry_state(args=[PATH, arg])

# Constrain bytes to printable-or-NUL (keeps the solver's answer readable)
for i in range(16):
    b = arg.get_byte(i)
    state.solver.add(claripy.Or(b == 0, claripy.And(b >= 0x20, b < 0x7f)))

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"GOOD" in s.posix.dumps(1),    # target: success marker on stdout
    avoid=lambda s: b"BAD" in s.posix.dumps(1),    # dead-end: failure marker
    num_find=1,
)

if simgr.found:
    sol = simgr.found[0].solver.eval(arg, cast_to=bytes).split(b"\x00", 1)[0]
    print(f"input: {sol!r}")
else:
    print("no satisfying input found")
```

**Find / avoid predicates** can be any callable on the state:

| Predicate | When to use |
|---|---|
| `lambda s: b"PASS" in s.posix.dumps(1)` | Success marker on stdout |
| `lambda s: s.addr == 0x401234` | Reached a specific address (use after CFG analysis) |
| `lambda s: s.solver.eval(s.regs.eax) == 0` | Function returned 0 (success on Linux/x86) |
| `lambda s: state.callstack.func_addr in failed_funcs` | Entered a known failure function (`exit`, `abort`) |

`auto_load_libs=False` skips loading every shared library — much faster, and almost always what you want.

## Pattern 2 — dump-at-API via SimProcedure: capture the non-symbolic side of a compare

When the binary calls `strcmp(input, expected)` and you can't tell which arg is which without reading the disassembly, hook the call and dump whichever argument has a concrete pointer that resolves to a concrete string. The non-symbolic side *is* the expected value.

```python
import angr, claripy, logging
logging.getLogger("angr").setLevel("ERROR")
logging.getLogger("cle").setLevel("ERROR")

PATH = "/path/to/target"
proj = angr.Project(PATH, auto_load_libs=False)

dumps = []

class StrcmpDump(angr.SimProcedure):
    def run(self, p1, p2):
        for label, ptr in [("arg0", p1), ("arg1", p2)]:
            try:
                p_int = self.state.solver.eval_one(ptr)
            except Exception:
                continue   # pointer itself is symbolic — skip
            buf = bytearray()
            for off in range(64):
                byte = self.state.memory.load(p_int + off, 1)
                if byte.symbolic:
                    break
                bv = self.state.solver.eval(byte)
                if bv == 0:
                    break
                buf.append(bv)
            if buf:
                dumps.append((label, hex(p_int), bytes(buf)))
        return self.state.solver.BVS("strcmp_ret", 32)

proj.hook_symbol("strcmp", StrcmpDump())

arg = claripy.BVS("arg", 16 * 8)
state = proj.factory.entry_state(args=[PATH, arg])
for i in range(16):
    b = arg.get_byte(i)
    state.solver.add(claripy.Or(b == 0, claripy.And(b >= 0x20, b < 0x7f)))

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"GOOD" in s.posix.dumps(1),
    avoid=lambda s: b"BAD" in s.posix.dumps(1),
    num_find=1,
)

for d in dumps:
    print(d)
# → ('arg1', '0x402004', b'OPEN')   ← the expected value
```

The same shape works for `memcmp`, `wcscmp`, `lstrcmpA`, `RtlEqualMemory`, etc. Replace the symbol name and the SimProcedure's arg layout to match.

**Why this beats reading argv[1] in the found state:** if the binary derives the expected value at runtime (XOR'd constant, decoded blob, runtime-built table), the stored-constant approach Qiling uses misses it. The SimProcedure sees the value at the *moment of comparison*, after any decoding has run.

## Pattern 3 — explicit address find: drive to a function you found in the decompiler

When you've already identified the success function from Ghidra and want angr to find an input that reaches it.

```python
proj = angr.Project(PATH, auto_load_libs=False)

# Address from the decompiler. For PIE binaries angr applies its own base
# (usually 0x400000 for x86_64), so add it: target = 0x400000 + offset.
target_addr = 0x401b40
avoid_addrs = [0x401a20, 0x401a80]   # exit / fail branches

arg = claripy.BVS("arg", 32 * 8)
state = proj.factory.entry_state(args=[PATH, arg])

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=target_addr, avoid=avoid_addrs)

if simgr.found:
    print(simgr.found[0].solver.eval(arg, cast_to=bytes))
```

Find/avoid accept lists, sets, predicates, or single addresses interchangeably.

## Pattern 4 — input via stdin instead of argv

Common in CTF binaries that `scanf` or `read(0, ...)` the input.

```python
inp = claripy.BVS("inp", 64 * 8)
state = proj.factory.entry_state(stdin=inp)
# constrain printable as in pattern 1
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=success_pred, avoid=fail_pred)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))   # solved stdin bytes
```

## Pattern 5 — concrete constraint chains: derived inputs

For checks like `f(input) == constant` where `f` is a non-trivial transform, the solver does the work — you just constrain the output.

```python
# Suppose decompilation shows: sum of input bytes XOR'd with 0x37 must equal 0x4d2
state = proj.factory.entry_state(args=[PATH, arg])
# (no need to model f manually — angr executes the check symbolically)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=success_pred, avoid=fail_pred)
```

Where this shines: input transforms that would be a pain to reimplement in Python but the binary already encodes. angr executes the transform symbolically and asks z3 to solve the resulting expression.

## State explosion — when to stop

If `simgr.explore` runs for more than ~5 minutes without `found`, or `simgr.active` grows past a few hundred states, you're hitting the classic problems:

- **Loops over symbolic data** — strlen-on-symbolic, memcpy-on-symbolic-len. Hook them with SimProcedures.
- **Library functions that aren't modeled** — `auto_load_libs=False` plus `hook_symbol` for the ones the binary actually uses.
- **Symbolic indirect calls** — branching on a symbolic function pointer. Often a sign the binary has a VM/dispatch table; revert to Qiling and read the dispatch.
- **State-space too wide** — narrow the symbolic input (shorter argv, fewer bytes), constrain to a known prefix, or add intermediate `find=` waypoints.

```python
# Drop computation budget; useful for "is this even tractable" probes
simgr.explore(find=pred, n=200)   # at most 200 step rounds
```

If after one round of mitigation the analysis is still stuck, switch tools: emulate with Qiling (see `qiling-emulation.md`) or read the logic in Ghidra.

## Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `Project()` hangs on import | `auto_load_libs=True` is loading every linked .so/.dll | Always pass `auto_load_libs=False` unless you specifically need the libs |
| Symbolic string read fails ("Trying to extract a symbolic string") | `.string.concrete` on a buffer that still has symbolic bytes | Either eval through the solver byte-by-byte (Pattern 2) or run `state.solver.eval(state.mem[ptr].string.resolved, cast_to=bytes)` after constraining |
| `simgr.found` is empty after a long run | The find predicate never matched, or every path got pruned by `avoid` | Loosen `avoid` first; if still empty, the path may be unreachable under your constraints |
| "Unicorn support disabled" warning | Optional native engine missing on macOS | Harmless; angr falls back to pure-Python VEX engine. Slower but correct. |
| PIE base mismatch with Ghidra | Ghidra shows file offsets; angr applies a load base (0x400000 default for x86_64 PIE) | Add the load base to addresses you import from Ghidra: `proj.loader.main_object.mapped_base + ghidra_offset` |

## Comparison to Qiling

| | Qiling | angr |
|---|---|---|
| **Best for** | Stored-value extraction, runtime IAT reconstruction, anti-debug bypass | Derived-value recovery, path-find, constraint-solve |
| **Cost** | Runs near native speed; rootfs setup needed | Slow (path explosion); pure-Python install |
| **State model** | Concrete execution + OS shims | Symbolic execution + solver |
| **Hook surface** | `set_api`, `set_syscall` (high-level) | `SimProcedure` + `hook_symbol` (low-level) |
| **Handles anti-debug?** | Yes (bypass installer template) | Symbolic execution sidesteps most checks naturally |
| **Handles VM/interpreter** | Trace each opcode dispatch | Often state-explodes — read the dispatch in Ghidra |

**Decision rule:** stored value? Qiling. Derived value or path-find? angr. Both struggle? Decompile and read.

## References

- [angr documentation](https://docs.angr.io/) — current API reference
- [angr-doc/examples](https://github.com/angr/angr-doc/tree/master/examples) — worked CTF solutions; mine for patterns
- [angr workshop notes](https://github.com/jakespringer/angr_ctf) — CTF-shaped tutorial set
- [claripy docs](https://docs.angr.io/advanced-topics/claripy) — for the BVS / constraint API
- [Z3 SMT solver](https://github.com/Z3Prover/z3) — the backend; understanding it helps when constraints behave unexpectedly
