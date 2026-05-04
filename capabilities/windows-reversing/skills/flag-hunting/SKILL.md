---
name: flag-hunting
description: Locate the flag in an HTB/CTF-style Windows crackme by working backwards from the string-compare that validates user input, using static decompilation when the flag is a constant and emulation when it is constructed at runtime.
---

# Flag Hunting

## Philosophy
A crackme checks input against an expected value. Find the check,
read the expected value. The value is either:

- **Literal in the binary** — `ghidra_strings` / `pe_strings` will
  find it.
- **Constructed at runtime** (stack string, xor, RC4, base64 chain) —
  `pe_floss` often finds it; if not, break on the comparison and dump
  memory.

## Fast Path (literal flag, 2 minutes)

```
pe_strings --min_length=8                    # grep for `HTB{`, `flag{`, `CTF{`
pe_floss --enable_stack --enable_decoded     # if pe_strings was empty
```

If a plausible flag shows up, validate by looking at what code
references that string:

```
ghidra_analyze path=<pe>
ghidra_strings path=<pe> pattern="HTB{"      # then look at the <- xrefs
ghidra_decompile path=<pe> target=<caller>
```

If the decompiled function passes the string to strcmp / wcscmp /
memcmp against user input, you have it.

## Standard Path (compare-site dump)

### 1. Find the comparison
```
ghidra_list_functions                  # filter for plausible names
pe_capa --summary_only                 # look for "compare strings" tags
```

Interesting callers are typically named `main`, `wmain`, `WinMain`,
`check`, `validate`, `verify`, or a thread proc. The compare API is
one of: `strcmp`, `wcscmp`, `lstrcmpA`, `lstrcmpW`, `memcmp`, or an
inlined byte-by-byte loop.

### 2. Dump the expected argument
```
qiling_dump_at_api \
  path=<pe> \
  api=strcmp \
  param_index=1 \
  length=128 \
  bypass_antidebug=true
```
- `param_index=0` on x86 cdecl → first argument (usually user input).
- `param_index=1` → second argument (usually expected flag). Try
  both; whichever is not your input is the flag.
- For wide strings, decode the hex as UTF-16LE.
- For inlined compares, set a hook on the function that contains the
  compare loop and dump at entry.

### 3. Handle input-dependent paths
If the binary reads stdin before running, pass input via Qiling's
stdin. For now the MCP does not expose a stdin parameter — workaround:
modify the binary to hardcode the input, or add a helper script that
monkeypatches `ReadFile` on the stdin handle.

## Constructed-Flag Path

If the flag is xor'd or RC4'd, `pe_floss --enable_decoded` often
recovers it because FLOSS looks for decoder-then-use patterns. If
FLOSS misses it:

1. `ghidra_decompile` the function that builds the expected value.
2. Port the algorithm to ~10 lines of Python.
3. Run it on the constant key/buffer pulled with `pe_bytes_at`.

This is faster than instrumenting the emulator for all but the most
obfuscated schemes.

## Sanity Check
Every HTB flag matches the regex `HTB\{[^}]+\}`. If your candidate
doesn't, you probably dumped the wrong side of the compare or the
wrong buffer size — try the opposite `param_index` or increase
`length`.
