---
name: binary-analysis
description: Reverse-engineer native binaries (PE, ELF, Mach-O, shellcode) end-to-end — triage, identify and unpack packers, bypass anti-debug checks, decompile and trace, recover protected artifacts (keys, configs, payloads), and emulate cross-arch with Qiling. Use for malware triage, incident response, vulnerability research, license validation, and CTF reversing.
---

# Binary Analysis

End-to-end workflow for static and dynamic reverse engineering of native binaries. The agent body covers high-level orchestration; this skill carries the technique depth, with `references/` for per-topic deep-dives.

## Reference layout — grep first

`references/` has two layers. Always grep both when looking up a technique:

- **`references/*.md` (local short-form)** — distilled how-to: working Qiling code, crypto decoders, format quick-refs, packer-ID tables. Optimized for fast load.
- **`references/external/`** — point-in-time snapshots of the cited authoritative sources (Check Point Anti-Debug Encyclopedia, Unprotect Project, MS PE spec, Apple Mach-O ABI, ELF man pages, ired.team, hasherezade, Objective-See, al-khaser README). ~22,000 lines across 90 files. Grep for full code, disassembly, and per-technique bypass detail that doesn't fit in the local short-form.

```bash
grep -rln "<api-name or technique>" references/external/    # full-corpus search
```

See `references/INDEX.md` for a topic → file map, and `references/SOURCES.md` for attribution + snapshot dates.

## Methodology grounding

- **Workflow** — Lenny Zeltser's [SANS FOR610 four-tier methodology](https://www.sans.org/posters/malware-analysis-and-reverse-engineering-cheat-sheet/): fully-automated triage → static properties → interactive behavior → manual code reversing. Cheap signals first, emulation second, decompilation only when both run out.
- **Standards** — [MITRE ATT&CK](https://attack.mitre.org/) (T1027.002 Software Packing, T1140 Deobfuscate/Decode, T1622 Debugger Evasion); [MBC](https://github.com/MBCProject/mbc-markdown) for malware behavior IDs; capa emits both natively under `obfuscation/packer` and anti-analysis families — pass IDs through to your report.
- **Anti-analysis taxonomy** — [Check Point Anti-Debug Encyclopedia](https://anti-debug.checkpoint.com/) (Windows), [Unprotect Project (Linux-relevant techniques)](https://unprotect.it/category/anti-debugging/) + [al-khaser Linux portions](https://github.com/ayoubfaouzi/al-khaser) (Linux substitute), [Objective-See blog](https://objective-see.org/blog.html) + [TAOMM](https://taomm.org/) (macOS), [Unprotect Project](https://unprotect.it/) (cross-platform searchable catalog), [al-khaser](https://github.com/ayoubfaouzi/al-khaser) + [pafish](https://github.com/a0rtega/pafish) (reference implementations).
- **Practitioner corpora** — [HackTricks Reversing](https://book.hacktricks.wiki/en/reversing/index.html), [ired.team](https://www.ired.team/miscellaneous-reversing-forensics), [hasherezade](https://hshrzd.wordpress.com/), [OALabs research](https://research.openanalysis.net/), [Mandiant Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence).
- **Format references** — [Corkami posters](https://github.com/corkami/pics/tree/master/binary) (PE101 / PE102 / ELF101 / Mach-O101), [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [ELF gABI](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html), [Apple Mach-O mirror](https://github.com/aidansteele/osx-abi-macho-file-format-reference), [LIEF docs](https://lief.re/doc/latest/).
- **Packer signatures** — [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy), [awesome-yara](https://github.com/InQuest/awesome-yara), [pe-sieve](https://github.com/hasherezade/pe-sieve) (in-memory implant detection).

## Phase 1 — Triage

Determine the format and collect cheap static signals before deciding what to do.

### PE files
```
pe_info path=<binary>            # sha256, arch, imports, sections, entropy
bin_format_info path=<binary>    # cross-format summary (LIEF)
bin_strings path=<binary>        # URLs, keys, config strings
pe_floss path=<binary>           # stack strings, XOR-decoded strings
bin_capa path=<binary>           # MITRE ATT&CK / MBC capability tags
bin_yara path=<binary>           # Neo23x0/signature-base family / IOC match
```

### ELF / Mach-O / unknown
```
bin_format_info path=<binary>    # uniform format/section/import summary (LIEF)
bin_strings path=<binary>        # in-process, format-agnostic
bin_yara path=<binary>           # family / IOC match (format-agnostic)
bin_capa path=<binary>           # ELF supported; Mach-O not — use Ghidra
debuginfod_symbols path=<binary> # ELF: recover exact symbols by Build-ID (distro builds)
```
For an ELF that might be an unmodified distro build (or statically links one),
`debuginfod_symbols` recovers the exact upstream function names by GNU Build-ID —
current, no signature DB, no version brittleness. Outbound network, explicit-
invocation (`$DEBUGINFOD_URLS`); apply recovered names via the ghidra
`rename_function` tool. Misses on custom/malware builds (no indexed Build-ID) —
fall back to FID / similarity / structural analysis. See
`references/validated-annotation.md` Tier 1.
```bash
file <binary>
checksec --file=<binary> --output=json
readelf -h -S -l <binary>        # ELF field-level detail beyond bin_format_info
otool -hL <binary>               # Mach-O field-level detail beyond bin_format_info
diec <binary>                    # Detect It Easy: packer / compiler / protector ID
```

`bin_format_info` is the cross-format first pass: PE / ELF / Mach-O all return the same shape (arch, entrypoint, sections + entropy, libraries, first N imports/exports) plus a format-specific block. `pe_info` stays around for PE-specific depth (imphash, anti-debug import flagging, subsystem detection); `readelf` / `otool` for ELF / Mach-O field-level interrogation beyond the LIEF summary.

### Raw shellcode / extracted blobs
Use `references/scripts/capstone_disasm.py <file> --arch x86 --find-xor --find-strings --find-api-hash` for disassembly with pattern detection. See `references/shellcode-patterns.md` for PEB walks, API hashing schemes, and stack-string extraction.

## Phase 2 — Branch on findings

**Prioritize by capability signal first.** Before diving in, rank the triage
output by capability category — C2/network, crypto, persistence, anti-analysis,
injection, credential access — using the strings, imports, capa tags, and YARA
hits together. A single signal is weak; a *cluster* across categories (e.g.
socket APIs + an encrypt loop + a hardcoded host) is a high-confidence lead.
Work the highest-signal component first and name outward from it (this is the
queue the validated-annotation loop consumes — see Phase 5). Map each cluster to
its MITRE ATT&CK / MBC IDs and carry them into the report.

| Signal | Action | Where |
|---|---|---|
| Code-section entropy > 7.0, tiny imports, UPX/ASPack/Themida section names | Identify packer, unpack | [Phase 3](#phase-3--packer-identification--unpacking) |
| Anti-debug imports or capa tags (T1622) | Bypass before continuing | [Phase 4](#phase-4--anti-analysis-bypass) |
| Network activity (socket/connect/send/recv, URLs in strings) | Trace protocol, extract streams, identify crypto | [Phase 6](#phase-6--data-recovery-patterns) |
| Embedded shellcode / second-stage payload | Extract (`bin_bytes_at`), triage separately, recover keys | [Phase 7](#phase-7--multi-stage-payloads) |
| Clean static binary | Skip to decompilation | [Phase 5](#phase-5--decompilation--comparison-site-analysis) |

## Phase 3 — Packer identification & unpacking

Maps to MITRE ATT&CK [T1027.002](https://attack.mitre.org/techniques/T1027/002/) and [T1140](https://attack.mitre.org/techniques/T1140/). capa emits these tags natively — pass through.

### Identification signals

**PE:**
| Signal | Likely packer |
|---|---|
| Sections `UPX0` / `UPX1` | UPX |
| Section `.aspack` | ASPack |
| Imports only `LoadLibraryA`, `GetProcAddress` | UPX / custom |
| Section `.themida` / `.vmp0..vmp2` | Themida / VMProtect (hard) |
| Huge section, low imports, IAT built at runtime | Custom loader |

**ELF:**
| Signal | Likely packer |
|---|---|
| `UPX!` magic in binary | UPX |
| Single LOAD segment with high entropy | UPX or custom |
| Minimal symbol table, stripped | May be packed or just stripped |

**Automated:**
- `bin_capa path=<binary> summary_only=true` — look for packer-family tags
- `bin_yara path=<binary> summary_only=true` — Neo23x0/signature-base
  carries community-curated packer / protector / crypter rules (UPX,
  Themida, VMProtect, Enigma, .NET obfuscators, modern crypter families,
  and named-family malware signatures)
- `diec <binary>` (Detect It Easy CLI) — most precise per-packer
  identification when entropy + section-name heuristics are inconclusive

See `references/packer-signatures.md` for the local quick-ID corpus (section names + entropy + imports). **Beyond UPX, per-packer unpacking detail lives in `references/external/unprotect/<packer>.md`** — `grep -rln <packer-name> references/external/unprotect/` to find the right file. Coverage includes UPX, ASPack, ASProtect, Themida, VMProtect, MPRESS, PECompact, Petite, FSG, Obsidium, Enigma, .NET obfuscators, and modern crypter families (HxOR, CryptOne, EasyCrypter, PureCrypter, LimeCrypter, Cloudeyedarkeye, PyArmor). Community standards if you need to fetch upstream: [DIE](https://github.com/horsicq/Detect-It-Easy), [awesome-yara](https://github.com/InQuest/awesome-yara).

### Unpacking

**UPX:** `upx -d -o <unpacked> <packed>` (ships both PE and ELF unpackers). Re-triage the result.

**Custom loader, PE (dump at OEP via emulation):** see [Phase 4](#phase-4--anti-analysis-bypass) for the Qiling pattern. Trace `LoadLibraryA`/`GetProcAddress`/`VirtualAlloc`/`VirtualProtect`. The last `VirtualProtect` before `GetProcAddress` calls stop is typically on the reconstructed code section — dump that region, carve PE header, re-run static triage.

**Custom loader, ELF (dynamic):**
```bash
strace -f -e trace=mmap,mprotect,write <binary>             # find unpack sequence
gdb -batch -ex "catch syscall mprotect" -ex run -ex bt <binary>
# Dump executable region from /proc/<pid>/maps
```

**Themida / VMProtect / custom VM:** out of scope for first-pass automation. Look for side-channel solves (weakness in the checker logic, not the VM itself).

**Mach-O packers:** the community signature corpus is thin compared to PE — DIE has limited Mach-O coverage and there's no awesome-yara equivalent for Mach-O. Cite [Objective-See](https://objective-see.org/blog.html) and [TAOMM](https://taomm.org/) for per-technique write-ups; expect entropy + section-layout heuristics rather than named-packer matches.

## Phase 4 — Anti-analysis bypass

Maps to MITRE ATT&CK [T1622](https://attack.mitre.org/techniques/T1622/) and MBC [B0001](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/debugger-detection.md).

**When to suspect anti-debug:**
- Imports include `IsDebuggerPresent`, `NtQueryInformationProcess` (Windows), `ptrace(PTRACE_TRACEME)` or `/proc/self/status` reads (Linux), `sysctl` P_TRACED check (macOS)
- Binary exits early, prints "debugger detected", or crashes under a debugger
- Documentation / context mentions anti-debug protections

**For full per-technique C + x86/x64 asm + bypass detail** (every check named below + many more), grep the Unprotect mirror first:
```bash
grep -rln "<api-name or technique>" references/external/unprotect/              # cross-platform catalog with ATT&CK / MBC IDs
```
For canonical per-category coverage (debug-flags, object-handles, exceptions, timing, process-memory, assembly, interactive, misc) fetch [anti-debug.checkpoint.com](https://anti-debug.checkpoint.com/) on demand.

### Windows PE — emulate with bypass

The most efficient path: run the binary under Qiling with the standard anti-debug hooks installed. The full template lives in `references/qiling-emulation.md` and covers the 4 APIs to hook, the PEB byte/dword writes, the arch-correct NtGlobalFlag offset, and the API-trace + dump-at-API patterns. Per-technique table for individual checks (heap flags, INT 2D, timing, environment scans) in `references/windows-anti-debug.md`; full bypass code for techniques the four-API installer doesn't cover lives in the external mirror cited above.

### Linux ELF — LD_PRELOAD, patch, or strace inject

```bash
# ptrace hook via LD_PRELOAD
cat > anti_ptrace.c <<'EOF'
#include <sys/ptrace.h>
long ptrace(int request, ...) { return 0; }
EOF
gcc -shared -o anti_ptrace.so anti_ptrace.c
LD_PRELOAD=./anti_ptrace.so ./target

# strace return-value injection
strace -e inject=ptrace:retval=0 ./target

# /proc/self/status TracerPid faking, hardware breakpoint detection, SIGTRAP tricks, etc.
# Per-technique table in references/linux-anti-debug.md
```

When LD_PRELOAD isn't an option, decompile in Ghidra, identify the check, and patch the branch. The `bin_bytes_at` tool reads the file offset; modify with Python or `r2 -w` (`wa nop`).

### macOS — patch or hook

`PT_DENY_ATTACH` via `ptrace`, sysctl `KERN_PROC_PID` checks, `task_for_pid` denial, amfid checks. No canonical catalog — `external/objective-see/blog-index.md` carries the post titles + URLs for Patrick Wardle's macOS anti-debug research; fetch specific posts on demand. Pattern: decompile in Ghidra, patch the conditional branch.

### Any format — decompile-and-patch fallback

1. **Ghidra MCP** (preferred): `decompile_function` for the function containing the check
2. **r2 + Ghidra plugin**: `r2 -q -e scr.color=0 -c 'aaa; s <func>; pdg' <binary>`
3. **r2 disassembly**: `r2 -q -e scr.color=0 -c 'aaa; s <func>; pdr' <binary>`
4. Identify the conditional branch (typically `if (check) exit()`)
5. Note branch address, apply NOP/invert via `bin_bytes_at` + Python or `r2 -w`

### Timing checks

`GetTickCount` / `QueryPerformanceCounter` / `rdtsc` / `clock_gettime` always trip falsely under emulation (it's slow). Options:
- Patch the API to return a small monotonic delta
- Decompile and patch/skip the timing comparison branch

## Phase 5 — Decompilation & comparison-site analysis

### Decompilation chain (use first available)

1. **Ghidra MCP** (pyghidra-mcp). The server auto-analyzes binaries listed at startup; for anything else call `import_binary` first. `binary_name` for every other tool is the basename (e.g. `target.exe`) as listed by `list_project_binaries`.
   ```
   import_binary binary_path=<binary>             # if not preloaded
   list_project_binaries                          # confirm binary_name
   search_symbols_by_name binary_name=<base> query="main|check|validate|verify|auth|license" functions_only=true
   decompile_function binary_name=<base> name_or_address=main include_callees=true include_strings=true include_xrefs=true
   search_strings binary_name=<base> query="<term>"
   list_imports binary_name=<base>                # for anti-debug API detection
   list_xrefs binary_name=<base> name_or_address=<api>
   search_code binary_name=<base> query="<pseudo-c snippet>" search_mode=semantic
   function_dataflow binary_name=<base> name_or_address=<fn>   # params/locals/types, calls, P-code count
   ```
   The `ghidra` MCP also exposes write-back (`rename_function`, `rename_variable`,
   `set_variable_type`, `set_function_prototype`, `set_comment`),
   `function_fid_hash` / `emulate_function`, the BSim corpus-similarity tools
   (`bsim_build_database` / `bsim_query_function` / `bsim_overview`), and the
   two-binary diff tools (`diff_binaries` / `diff_function`, [Phase 8](#phase-8--binary--patch-diffing))
   — use these via the validated-annotation loop and Phase 8 below, not ad hoc.
2. **radare2 + Ghidra plugin**: `r2 -q -e scr.color=0 -c 'aaa; s main; pdg' <binary>`
3. **radare2 recursive disassembly**: `r2 -q -e scr.color=0 -c 'aaa; s main; pdr' <binary>`
4. **objdump**: `objdump -d -M intel <binary>` (last resort)

### Find the comparison

Interesting callers are typically named `main`, `check`, `validate`, `verify`, `license`, `auth`, or a thread proc. The compare API is one of `strcmp`, `wcscmp`, `lstrcmpA`, `memcmp`, or an inlined byte-by-byte loop.

```
search_symbols_by_name binary_name=<base> query=".*" functions_only=true   # preferred
r2 -q -e scr.color=0 -c 'aaa; afl' <binary>                                 # fallback
bin_capa path=<binary> summary_only=true                                    # "compare strings" tags
```

### Read the logic

Trace the call graph from entry to the comparison. Identify:
- What buffer holds the expected value
- How it's constructed (hardcoded? XOR'd? derived from input?)
- What key/algorithm is used

Format references for understanding what you're looking at:
- `references/pe-format-quick-ref.md` — local short-form: PE headers, sections, suspicious import combinations, .data/.rdata layout, entropy table.
- `references/external/formats/ms-pe-format.md` — canonical Microsoft PE/COFF spec (every field, data directory, characteristic, certificate format).
- `references/external/formats/apple-macho.md` — Apple Mach-O ABI reference (load commands, segments, section flags, symbol/string tables).
- `references/external/formats/elf-man5.md` — Linux `elf(5)` (ELF header / sections / dynamic / symbol structures).
- [ired.team / exploring-the-peb](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block) — PEB walkthrough; [ired.team / pe-file-header-parser-in-c++](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++) — worked PE-header parser. Fetch on demand.
- [ired.team / reversing-a-password-protected-application](https://www.ired.team/miscellaneous-reversing-forensics/reversing-c-c++-binaries-with-radare2/reversing-a-password-protected-application) — worked example of reversing a comparison-site validation routine. Fetch on demand.

### Annotate as you go — the validated-annotation loop

Don't reverse a multi-function binary in your head. As you understand each
function, **write the understanding back into the Ghidra project** (rename the
function and its vars, set types, add a comment) so the next decompile reads
better and the work compounds — the `.gpr` is your ledger and survives context
compaction. The catch: an LLM mislabels confidently, and a wrong name poisons
every caller. So commit a name only after it passes a validation step sized to
the stakes:

1. **Attend** — `decompile_function` + `function_dataflow` + xrefs/imports/capa.
   Read before you rename.
2. **Hypothesize** — what it is + var names, with confidence and the evidence.
3. **Validate** — climb only as far as the stakes justify: **Tier 0** structural
   cross-check (label must agree with the function's calls/strings/tags — every
   commit); **Tier 1** `function_fid_hash` (exact) to propagate a verified label
   to identical functions, `bsim_query_function` (fuzzy — names recompiled /
   cross-compiler / variant library code that exact hashing misses) against a
   corpus built with `bsim_build_database`, and `search_code` for similar ones —
   plus `bsim_overview` to drop known-library functions from the queue before you
   start; **Tier 2** adversarial
   re-read for high-fan-in functions; **Tier 3** `emulate_function` (or
   Qiling/angr) to run the real function and compare to a reimplementation —
   reserved for crypto/codec/transform on the critical path, where the
   reimplementation *is* the deliverable.
4. **Commit** — write back; only touch Ghidra-default names (`FUN_*`, `sub_*`),
   never a name a human assigned. Prefix the comment with the validation tier.

A repro mismatch is the ladder *working* — mark refuted and re-hypothesize.

**Full ladder, function-class routing, label-state model, naming conventions,
and edge cases: `references/validated-annotation.md` — load it when you start
annotating.**

## Phase 6 — Data recovery patterns

A binary protects, constructs, validates, or exfiltrates a value. Find the logic, read or reconstruct it. The target artifact is either:
- **Literal in the binary** — `search_strings` (Ghidra) / `bin_strings` (static-triage) / `strings` (CLI) will surface it
- **Constructed at runtime** (stack string, XOR, RC4, base64, custom cipher) — `pe_floss` often catches it; if not, decompile and reimplement
- **Hidden in exfiltrated or embedded data** — decrypt using recovered keys, then analyze the output

**For practitioner-grade write-ups beyond what's distilled here** (PE-bear / pe-sieve internals, in-memory unpacking, dump fixup, runtime API resolution), the index of hasherezade's blog is mirrored at `references/external/hasherezade/blog-index.md`; fetch specific posts on demand. OALabs research index: `references/external/oalabs/research-index.md`.

### Comparison-site dump via emulation

For PE binaries that validate input against a protected value, the value usually ends up as an argument to a string-compare function at validation time. Break on that API and dump the expected-value parameter. The pattern (~15 lines of Python + Qiling) is in `references/qiling-emulation.md` under "dump-at-API."

### Derived-input recovery via symbolic execution

When the validation is `f(input) == constant` and `f` is non-trivial to reimplement (custom XOR chain, byte-wise transform, checksum derivation), the symbolic-execution path is shorter than reading the logic: mark the input symbolic, let z3 solve. Templates for find/avoid, SimProcedure hook-and-dump, explicit-address find, stdin input, and the "when to stop" gotchas live in `references/symbolic-execution.md`.

**Decision rule:** stored value at a compare site? Qiling dump-at-API. Derived value or path-find under non-trivial constraints? angr. Both struggle? Decompile and read.

### Crypto pattern recovery

| Pattern | Identification | Recovery |
|---|---|---|
| Single-byte XOR | Repeating byte in ciphertext, `xor reg, imm8` | `bytes([b ^ key for b in data])` |
| Multi-byte XOR | `mod` instruction computing `i % key_len` | Repeating-key XOR with recovered key |
| XOR + ADD layers | Multiple loops over same buffer with different ops | Apply inverse operations in reverse order |
| RC4 | KSA (256-iteration swap loop) + PRGA stream | `from Crypto.Cipher import ARC4` |
| AES-ECB/CBC | S-box constants (`0x63, 0x7c, 0x77...`), 10/12/14 round loops | `from Crypto.Cipher import AES` |
| Base64 chain | Alphabet table in `.rdata`, 3→4 byte expansion | `base64.b64decode()` |
| Custom substitution | Lookup table in data section | Invert the table |

Code templates for each (XOR/RC4/AES/Base64/TEA/substitution) + hash-algorithm-identification constants in `references/common-crypto-patterns.md`. For XOR brute-forcing with frequency analysis or known-plaintext recovery: `references/scripts/xor_brute.py`.

### VM / interpreter reversing

When the binary contains a custom bytecode interpreter (common in CTF, malware obfuscation, license validation), the target artifact is often the correct *program* that produces the expected output.

Recognizing a VM:
- Large `switch` statement or dispatch table in `main`
- Loop reading bytes from a buffer and branching on each value
- Helper functions for stack ops, register manipulation, modular arithmetic
- Input is treated as "code" rather than "data"

Approach:
1. Decompile the dispatch function — this is the VM's CPU. Each `case` is an opcode.
2. Map every opcode to a human-readable operation (add, sub, push, pop, jump, compare, halt). Rename registers/state variables in the decompiler as you identify them.
3. Identify state model: what registers, what memory/stacks, what's the program counter?
4. Understand validation: final register == expected constant? Output buffer == expected hash?
5. Write the program that satisfies the postcondition.

Tips: test with trivially short inputs (`"r"`, `"cr"`, `"dr"`) to enumerate opcodes; if the VM implements a known algorithm (GCD, sorting, primality), recognize the pattern; correct CTF programs are usually short (< 30 chars) so brute-force is sometimes viable.

## Phase 7 — Multi-stage payloads

Many binaries have multiple stages: outer → unpacks/decrypts → inner; inner → C2 → second stage; second stage → encrypts/exfiltrates → target hidden in data or protocol.

Treat each layer as a separate triage-and-analyze cycle. Track keys and algorithms at each layer so you can decrypt end-to-end.

### Identify the data source
- **Pcap file** — extract TCP streams (Python `dpkt`, or `tshark -q -z follow,tcp,raw,N`)
- **Embedded resource** — `bin_bytes_at` or `objcopy --dump-section`
- **Carve a dropper / firmware blob** — `binwalk -e <target>` recursively
  extracts embedded files; pair with `bin_yara` on the extracted set to
  triage what came out
- **Downloaded payload** — identify URL/protocol from strings and decompilation

### Recover keys from the binary
Decompile crypto functions. Look for:
- Hardcoded keys (pushed to stack, stored in `.data`/`.rdata`)
- Key derivation (challenge-response, HMAC, PBKDF)
- Runtime patching (main binary modifies payload before execution)

### Decrypt layer by layer
Apply each decryption in reverse order of encryption.

### Analyze the decrypted artifact
- **PNG/JPEG** → save, open visually, run OCR (`tesseract <image> stdout`)
- **PE/ELF** → triage as a new binary (recurse)
- **Archive** → extract and examine
- **Shellcode** → disassemble with capstone, identify purpose (`references/shellcode-patterns.md`)
- **Structured config** → parse as JSON/XML/protobuf, extract C2 addresses

## Phase 8 — Binary / patch diffing

When you have **two builds of the same target** — pre-patch vs. post-patch (1-day
vuln research) or two samples of a malware family (variant tracking) — diff them
at function granularity instead of re-reversing from scratch. The **changed set is
the patch / the variant delta**, and it becomes the prioritized queue for the
validated-annotation loop (Phase 5).

```
import_binary binary_path=<baseline>                       # if not preloaded
import_binary binary_path=<patched>
list_project_binaries                                      # confirm both basenames
diff_binaries primary=<baseline> secondary=<patched>       # function-level partition
```

`diff_binaries` returns `summary` (`unchanged` / `changed` / `added` / `removed`
counts) plus the `changed` / `added` / `removed` function lists. `changed` entries
carry a 0..1 `similarity` (sorted most-changed first) and `matched_by` provenance
(`exact` is filtered out as unchanged; `symbol-name` and `structural` are the
edited pairs). It is **DB-free** and works on stripped binaries: exact-instruction
matching finds unchanged functions, and a control-flow-structure hash recovers
changed ones even with no symbols.

Then read each interesting change and work it through the loop:

```
diff_function primary=<baseline> secondary=<patched> \
  primary_name_or_address=<changed.primary_address> \
  secondary_name_or_address=<changed.secondary_address>   # side-by-side C + unified diff
```

For each `changed` function on the path to the vulnerability/behavior, run the
Phase 5 annotate-and-verify loop (the diff already told you *where* to look — now
establish *what* changed and why). `added` functions in the patched build are new
code (new check, new feature, new capability); `removed` functions are deleted
paths. Map findings to ATT&CK/MBC and carry them into the report.

**Cross-binary / corpus similarity (library ID, family clustering, denoise).**
Build a local BSim signature corpus once, then match against it:

```
bsim_build_database binaries=[<known-good or reference builds>] database=<name>
bsim_overview binary_name=<unknown> database=<name>                  # drop library/known fns from the queue
bsim_query_function binary_name=<unknown> name_or_address=<fn> database=<name>   # fuzzy Tier-1 ID of one function
```

BSim is the *fuzzy* complement to `function_fid_hash` (exact): it identifies
recompiled / cross-compiler / variant library code that exact hashing misses,
and `bsim_overview` denoises the annotation queue so reasoning budget goes to
genuinely novel functions. Embedded H2, no server, under the cache root. Design +
rationale (composition over fork, pass cascade, BSim lifecycle): see the module
header in `mcp/ghidra_mcp.py`.

## Sanity check

Verify the recovered artifact makes sense in context:
- Does it match the expected format for the task? (key, config, URL, credential, flag)
- If the binary validates input against a value, does the recovered value pass the check?
- If encrypted data, does decryption produce valid structure?
- If garbled, you likely used the wrong key, wrong byte order, or need to analyze the output as a non-text format.

## References index

### Local short-form

| File | When to load |
|---|---|
| `references/INDEX.md` | Topic → file map across local + external. Read this first when looking something up. |
| `references/SOURCES.md` | Attribution, license posture, and snapshot dates for the external mirror. |
| `references/validated-annotation.md` | The validated-annotation loop: attend→hypothesize→validate→commit, the Tier 0–3 validation ladder, function-class routing, label-state model, naming conventions. Load when you start renaming/annotating functions (Phase 5–6). |
| `references/packer-signatures.md` | Quick-ID for packers / protectors (section names, entropy, imports). Per-packer detail lives in `external/unprotect/`. |
| `references/windows-anti-debug.md` | Local short-form: PEB / NtGlobalFlag / heap / timing / environment-check tables. Full per-technique catalog entries in `external/unprotect/`; canonical per-category coverage at [anti-debug.checkpoint.com](https://anti-debug.checkpoint.com/) (fetch on demand). |
| `references/linux-anti-debug.md` | Per-technique Linux anti-debug bypass (ptrace, /proc, signal-based, timing). |
| `references/pe-format-quick-ref.md` | PE header/section/import layout. Canonical Microsoft spec at `external/formats/ms-pe-format.md`. |
| `references/shellcode-patterns.md` | PEB walks, API hashing (ROR13/CRC32/djb2 with known hash tables), XOR decode loops, stack strings. |
| `references/common-crypto-patterns.md` | XOR / RC4 / AES / Base64 / TEA / substitution recovery templates, hash-algorithm-ID constants. |
| `references/qiling-emulation.md` | Qiling Python patterns: `install_antidebug_bypass`, `install_api_logger`, `install_dump_at_api`, end-to-end `emulate()`, per-arch rootfs guide. |
| `references/symbolic-execution.md` | angr patterns: find/avoid for input recovery, SimProcedure hook-and-dump (the non-symbolic side of a compare is the expected value), explicit-address find, stdin-driven recovery, state-explosion mitigation. |
| `references/scripts/capstone_disasm.py` | Shellcode disassembly with XOR / stack-string / API-hash detection. |
| `references/scripts/xor_brute.py` | XOR brute-force with frequency analysis and known-plaintext recovery. |

### External mirror (grep `references/external/`)

| Path | Source | Use for |
|---|---|---|
| `external/unprotect/` (70 files) | Unprotect Project | Per-technique catalog entries with MITRE ATT&CK / MBC IDs, featured APIs, external links. Covers anti-debug + packers + anti-VM. |
| `external/formats/ms-pe-format.md` | Microsoft Learn | Authoritative PE/COFF spec — every header field, data directory, characteristic, certificate format. |
| `external/formats/apple-macho.md` | Apple ABI ref (aidansteele mirror) | Mach-O load commands, segments, section flags, symbol/string tables. |
| `external/formats/elf-man5.md` | Linux `elf(5)` | ELF header / sections / dynamic / symbol structures. |
| `external/formats/corkami-binary-readme.md` | Corkami | Visual format-poster index (PE101/ELF101/Mach-O101). |
| `external/hasherezade/blog-index.md` | hasherezade blog | Post index for PE-bear / pe-sieve / libpeconv author research. Fetch specific posts on demand. |
| `external/objective-see/blog-index.md` | Objective-See blog | macOS reverse-engineering post index. Fetch specific posts on demand. |
| `external/oalabs/research-index.md` | OALabs research | Index of OALabs blog/research. |
