# Validated annotation — build trustworthy, compounding project state

Reverse engineering past the first function is a *labelling* problem: as you
understand `FUN_0040…` you give it a name, type its variables, and the next
decompile reads better. The danger is that an LLM names confidently and often
wrongly — and once a wrong name is written back, every caller inherits the
mistake. So the rule is simple: **write understanding back to the Ghidra
project, but only after it survives a validation step proportional to the
stakes.** The Ghidra project (`.gpr`) is the ledger — renames, types, and
comments persist there, so understanding compounds across a session and
survives context compaction without any separate memory.

This is the depth behind FOR610's "manual code reversing" tier. Grounded in
Binary Ninja Sidekick's *attend-before-transform* discipline
(https://docs.sidekick.binary.ninja/tutorials/agent-capabilities.html).

## The loop (per function you decide to understand)

1. **Attend** — read before you rename. `decompile_function`, plus
   `function_dataflow` (params/locals/types, calls, P-code count), `list_xrefs`,
   `list_imports`, and the capa tags overlapping the function's range. Never
   guess a label from a default name.
2. **Hypothesize** — propose what the function *is* and names for its key
   params/locals, with a confidence and the evidence it rests on.
3. **Validate** — climb the ladder below only as far as the function's stakes
   justify.
4. **Commit** — write back with pyghidra-mcp: `rename_function`,
   `rename_variable`, `set_variable_type`, `set_function_prototype`, and a
   `set_comment` recording the evidence + tier (see state model). Commit only
   at/above the Tier-0 floor; below it, leave the default name and drop a comment
   noting the suspicion so the next pass sees it.
5. **Record** — the comment *is* the record. No separate store.

Each commit makes the next decompile richer. Name callees before callers — a
named callee improves the caller's decompilation.

**Only touch Ghidra-default names** (`FUN_*`, `sub_*`, `DAT_*`, `local_*`,
`param_*`). A name a human or an earlier verified pass assigned is ground truth —
use it as context, never overwrite it.

## The validation ladder

Validation is not one mechanism and it is **not** universal. Tier 0 is the floor
for *any* commit; climb higher only when the stakes justify the cost. Gating
every rename on emulation is the wrong instinct — most renames need only Tier 0.

- **Tier 0 — structural cross-check** *(every commit; no execution)*. The label
  must agree with evidence already in the binary: the imports/syscalls the
  function calls, the strings it references, capa tags over its range, the
  labels/types of its callers and callees, and its shape (arg count, loops,
  constants from `function_dataflow`). If the label says "crypto" but the
  function only calls socket APIs, the hypothesis is refuted. Cheap; catches the
  confident-wrong-name failure.
- **Tier 1 — known-code identification** *(strongest signal when it hits — try
  first)*. Several sources, most-exact first:
  - **debuginfod** (`debuginfod_symbols`, ELF) — if the binary, or a statically
    linked library in it, is an *unmodified distro build* (Fedora / Debian /
    Ubuntu / Arch), this returns the exact upstream function names by GNU
    Build-ID: the real symbols, no DB, no staleness, no brittleness. Apply with
    `rename_function`. Outbound network + explicit-invocation (honours
    `$DEBUGINFOD_URLS`; empty disables) — fine for supply-chain/firmware work,
    think twice for isolated malware.
  - **Ghidra FID** — Windows MSVC runtime functions auto-name during analysis
    (Ghidra bundles those signatures). For non-MSVC there is **no current public
    FID database anywhere** — exact-hash matching is too brittle across compiler/
    libc versions for anyone to ship one — so don't expect glibc auto-naming.
  - **`function_fid_hash`** — equal `full_hash` ⇒ near-identical code; use to
    **propagate a verified label** to identical functions within/across loaded
    binaries and to **dedup**.
  - **`search_code`** (semantic) — find behaviourally similar candidates on
    stripped code to seed hypotheses.
  Robust matching of *recompiled* library/variant code (the fuzzy case FID
  can't do) is **BSim** — a follow-on (needs a signature DB stood up).
- **Tier 2 — adversarial second opinion** *(cheap; contested or load-bearing
  labels)*. Re-read the decompilation and the proposed label with intent to
  *refute* it. Use when Tier 0 is ambiguous, or the function is high-fan-in (many
  callers inherit the label, so a wrong one is expensive).
- **Tier 3 — reimplement + concrete test I/O** *(expensive; reserved)*. Write a
  candidate reimplementation, run the **real** function on the same inputs, and
  compare outputs. Reserved for crypto / codec / checksum / custom-cipher / VM
  functions **on the critical path to the artifact** — because there the
  reimplementation *is* the deliverable (a working decryptor), and the match is
  the proof you solved the task. Two execution options:
  - `emulate_function` (Ghidra emulator) — quickest for a single, self-contained
    function: set arg `registers` and input `memory`, run, read back
    `read_registers`. Best on side-effect-light functions.
  - Qiling / angr (see `qiling-emulation.md`, `symbolic-execution.md`) — when you
    need full-binary context, dump-at-API, or symbolic input recovery.

  A repro **mismatch is a success** of the ladder — mark the hypothesis refuted
  and re-hypothesize; don't commit the label.

## Routing: function class → how far to climb

| Function class | Climb to | Why |
|---|---|---|
| Library / runtime / utility | Tier 1 (or skip) | Similarity/imports settle it; don't reason about libc by hand |
| Thin wrappers / plumbing | Tier 0 | Evidence unambiguous, low stakes |
| Control / dispatch / state machines | Tier 0 + Tier 2 | High fan-in; a wrong label poisons many callers |
| Crypto / codec / transform **on the critical path** | Tier 3 | The reimplementation is the artifact; executable proof warranted |
| Crypto / transform **off the critical path** | Tier 0, note residual risk | "hashes data" is good enough; don't spend a repro budget |

You pick the tier; this is routing guidance, not a hard gate.

## Label state (encode in the function's comment)

Prefix the `set_comment` with the state so re-opening the project re-loads what
you concluded:

| State | Meaning | Commit name? |
|---|---|---|
| `unknown` | default name, untouched | no |
| `hypothesized` | proposed, Tier 0 not yet passed | no — comment-only suspicion |
| `verified-structural` | Tier 0 passed | yes |
| `verified-similarity` | Tier 1 match/propagation | yes |
| `verified-executable` | Tier 3 repro matched | yes (+ the reimplementation is an artifact) |
| `refuted` | failed validation | record so the dead label isn't re-proposed |

`refuted` is first-class — recording *why* the obvious guess was wrong stops the
agent re-walking it.

## Naming conventions (keep the project legible across passes)

- Functions: `snake_case` verb phrases — `parse_config`, `decrypt_payload`.
- Locals/params: nouns — `key_len`, `cipher_buf`.
- Globals/data: `g_` prefix — `g_config`.

## Edge cases

- **Stripped, no symbols, no Tier-1 hit** (not a distro build; no FID/`search_code`
  lead) — everything starts `unknown`; run on Tier-0 structural evidence. This is
  the genuinely hard case; BSim (fuzzy, follow-on) is the eventual lever.
- **Compiler-inlined function** (e.g. crypto inlined into its caller) — no
  discrete function to label; annotate at comment granularity inside the caller.
- **Won't emulate in isolation** (heavy global/external deps) — Tier 3 N/A; fall
  back to Tier 2 and record "repro infeasible." Never block the loop on it.
- **Tier 0 passes but the label is subtly wrong** (CRC32 vs custom checksum —
  both "hash data") — accept residual risk off the critical path and mark
  confidence; that's exactly why Tier 3 exists for critical functions.
- **Packed/obfuscated target** — annotate only *after* unpacking (Phases 3–4);
  annotating packed code wastes effort.

## Ordering with the rest of the workflow

Run the loop during decompilation (Phase 5) and data recovery (Phase 6). Seed
*which* functions to understand first from the capability-ranked queue (see the
"Prioritize by capability signal" note in Phase 1) — start at the highest-signal
component (C2, crypto, persistence), name outward from there.
