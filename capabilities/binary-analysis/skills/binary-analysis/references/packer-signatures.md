# Packer Signatures Reference

**This file is the short-form identification corpus** (section names, entropy ranges, suspicious import patterns). For per-packer unpacking detail — Themida / VMProtect / MPRESS / PECompact / Enigma / ASProtect / Petite / FSG / Obsidium and modern crypter families — grep the external mirror:

```bash
grep -rln "<packer-name>" ../external/unprotect/
# Per-packer files live at ../external/unprotect/<packer>.md (e.g. themida.md, vmprotect.md, mpress.md, asprotect.md, petite.md, fsg.md, obsidium.md, upx-ultimate-packer-for-executables.md, plus modern: hxor-packer.md, cryptone.md, easycrypter.md, purecrypter.md, limecrypter.md, cloudeyedarkeye.md, pyarmor.md, milfuscator.md, niximports.md, alienyze.md, alternate-exe-packer.md, bobsoft-mini-delphi-packer.md, net-anti-decompiler.md, net-reactor.md, theark.md, truecrypt.md)
```

Identification patterns for common packers and protectors across PE and ELF binaries.

## PE Packers

### UPX (Ultimate Packer for eXecutables)
**Section names:** `UPX0` (empty, virtual-only), `UPX1` (compressed data), `UPX2` (optional)
**Import table:** Minimal — typically `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`, `ExitProcess`
**Entry point:** Inside `UPX1`, jumps to decompression stub
**Magic bytes:** `UPX!` marker in binary
**Entropy:** `UPX1` section > 7.0
**Unpacking:** `upx -d <packed> -o <unpacked>` (built-in, reliable)
**Modified UPX:** Altered section names or `UPX!` magic → `upx -d` fails. Fix: restore original names/magic, or dump at OEP.

### ASPack
**Section names:** `.aspack`, `.adata`
**Import table:** Very small, kernel32 only
**Entry point:** In `.aspack` section
**Entropy:** `.aspack` > 7.0, `.adata` moderate
**Unpacking:** No official unpacker. Dump at OEP via Qiling/debugger.

### Themida / WinLicense
**Section names:** `.themida`, or custom names like `.xxx0`–`.xxx3`
**Import table:** Heavily virtualized — may show only 1–2 imports
**Characteristics:** Large virtual sections, anti-debug + anti-VM layers
**Entropy:** Mixed — code sections may have moderate entropy due to VM bytecode
**Unpacking:** Very difficult. Look for logic weaknesses rather than full unpack.

### VMProtect
**Section names:** `.vmp0`, `.vmp1`, `.vmp2`
**Import table:** Minimal or fully virtualized
**Characteristics:** Converts x86 to custom VM bytecode. Massive code expansion.
**Entropy:** VM bytecode sections > 6.5
**Unpacking:** Not feasible in general. Analyze VM dispatcher for specific functions of interest.

### MPRESS
**Section names:** `.MPRESS1`, `.MPRESS2`
**Import table:** Small — `LoadLibraryA`, `GetProcAddress`
**Entry point:** In `.MPRESS2`
**Entropy:** `.MPRESS1` > 7.0
**Unpacking:** Dump at OEP. Sometimes `upx -d` works (similar compression).

### PECompact
**Section names:** `.pec`, `.pec2`
**Import table:** Minimal
**Entry point:** In packer section
**Unpacking:** Dump at OEP.

### Enigma Protector
**Section names:** `.enigma1`, `.enigma2`
**Characteristics:** Anti-debug, anti-dump, license system
**Unpacking:** Dedicated unpackers exist for older versions.

### .NET Obfuscators (ConfuserEx, Eazfuscator, SmartAssembly)
**Indicators:** CLR header present (DataDirectory[14]), but strings/methods are encrypted
**Section:** `.text` contains IL bytecode + obfuscated metadata
**Detection:** `bin_capa` may flag .NET obfuscation; dnSpy/ILSpy for decompilation
**Unpacking:** de4dot, ConfuserEx-unpacker, or manual string decryption

## ELF Packers

### UPX (ELF variant)
**Indicators:** `UPX!` magic in binary, single LOAD segment with high entropy
**Section table:** Often stripped entirely
**Unpacking:** `upx -d <packed> -o <unpacked>`

### Custom ELF packers
**Indicators:**
- Single LOAD segment covering nearly entire file
- No symbol table, stripped
- `mmap` + `mprotect` + `memcpy` pattern in minimal stub
- Entry point in unusual location (not near standard `_start`)

**Unpacking strategy:**
```bash
# Trace unpacking syscalls
strace -f -e trace=mmap,mprotect,write ./packed_binary

# Break at transition to unpacked code
gdb -batch -ex "catch syscall mprotect" -ex run -ex bt ./packed_binary
```

## Quick Detection Table

| Indicator | Packer Family |
|-----------|--------------|
| `UPX0`/`UPX1` sections | UPX |
| `UPX!` magic bytes | UPX (PE or ELF) |
| `.aspack`/`.adata` sections | ASPack |
| `.themida` section | Themida |
| `.vmp0`–`.vmp2` sections | VMProtect |
| `.MPRESS1`/`.MPRESS2` sections | MPRESS |
| `.pec`/`.pec2` sections | PECompact |
| `.enigma1`/`.enigma2` sections | Enigma Protector |
| Only `LoadLibraryA` + `GetProcAddress` imports | Generic packer |
| Code section entropy > 7.0 | Likely packed/encrypted |
| Very small import table (< 5 functions) | Likely packed |
| Large discrepancy between `VirtualSize` and `SizeOfRawData` | UPX-style (decompresses in memory) |

## Entropy Profiles

| Packer | Code Section | Data Section | Overall |
|--------|-------------|--------------|---------|
| UPX | 7.2–7.9 | N/A | 7.0+ |
| ASPack | 7.0–7.8 | 4.0–6.0 | 6.5+ |
| Themida | 5.5–7.0 (VM bytecode) | 3.0–5.0 | 5.0–6.5 |
| VMProtect | 6.0–7.5 | 3.0–5.0 | 5.5–7.0 |
| MPRESS | 7.5–7.9 | N/A | 7.0+ |
| Normal (unpacked) | 5.0–6.5 | 1.0–4.0 | 4.0–5.5 |
| Encrypted section | 7.9–8.0 | — | — |
