# PE Format Quick Reference

Condensed reference for reverse engineering PE (Portable Executable) files — the fields, sections, and structures most relevant during binary analysis.

**Canonical specs**: the authoritative Microsoft PE/COFF specification is mirrored at `../external/formats/ms-pe-format.md` (every header field, data directory, characteristic, certificate format). Visual layout posters: `../external/formats/corkami-binary-readme.md` (PE101 / PE102 by Ange Albertini). PEB internals walkthrough and a hand-written PE-header parser are at [ired.team / exploring-the-peb](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block) and [ired.team / pe-file-header-parser-in-c++](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++) — fetch on demand.

## DOS Header (offset 0x00)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 2 | `e_magic` | `MZ` (0x5A4D) |
| 0x3C | 4 | `e_lfanew` | Offset to PE signature |

## PE Signature + COFF Header

At offset `e_lfanew`:

| Offset | Size | Field | Key Values |
|--------|------|-------|------------|
| +0x00 | 4 | Signature | `PE\0\0` (0x00004550) |
| +0x04 | 2 | Machine | 0x014C = i386, 0x8664 = AMD64, 0x01C4 = ARM |
| +0x06 | 2 | NumberOfSections | |
| +0x08 | 4 | TimeDateStamp | Unix epoch — often faked |
| +0x14 | 2 | SizeOfOptionalHeader | |
| +0x16 | 2 | Characteristics | 0x0002 = EXECUTABLE, 0x2000 = DLL |

## Optional Header (immediately after COFF header)

| Offset | Field | Notes |
|--------|-------|-------|
| +0x00 | Magic | 0x10B = PE32, 0x20B = PE32+ (64-bit) |
| +0x10 | AddressOfEntryPoint | RVA of entry — packers redirect this |
| +0x1C | ImageBase | Default load address (usually 0x00400000 for exe) |
| +0x20 | SectionAlignment | Typically 0x1000 |
| +0x24 | FileAlignment | Typically 0x200 |
| +0x50 | SizeOfImage | |
| +0x60 | DataDirectory[0] | Export table RVA + size |
| +0x68 | DataDirectory[1] | Import table RVA + size |
| +0x78 | DataDirectory[4] | Security (Authenticode) |
| +0x80 | DataDirectory[5] | Base relocation table |
| +0xC0 | DataDirectory[14] | CLR header (.NET) |

## Section Table

Each entry is 40 bytes:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 8 | Name | ASCII, null-padded |
| +0x08 | 4 | VirtualSize | Size in memory |
| +0x0C | 4 | VirtualAddress | RVA when loaded |
| +0x10 | 4 | SizeOfRawData | Size on disk |
| +0x14 | 4 | PointerToRawData | File offset |
| +0x24 | 4 | Characteristics | Flags (see below) |

**Section characteristics flags:**
| Flag | Meaning |
|------|---------|
| 0x00000020 | Contains code |
| 0x00000040 | Contains initialized data |
| 0x00000080 | Contains uninitialized data |
| 0x20000000 | Executable |
| 0x40000000 | Readable |
| 0x80000000 | Writable |
| 0xE0000000 | RWX — suspicious (packer, shellcode) |

## Common Section Names

| Name | Purpose | Packer indicator? |
|------|---------|-------------------|
| `.text` | Code | Normal |
| `.rdata` | Read-only data, import names, strings | Normal |
| `.data` | Initialized global/static data | Normal |
| `.bss` | Uninitialized data | Normal |
| `.rsrc` | Resources (icons, manifests, embedded files) | Normal |
| `.reloc` | Base relocations | Normal |
| `UPX0` / `UPX1` | UPX packed sections | **Yes — UPX** |
| `.aspack` | ASPack | **Yes — ASPack** |
| `.themida` | Themida | **Yes — Themida** |
| `.vmp0`–`.vmp2` | VMProtect | **Yes — VMProtect** |
| `.ndata` | NSIS installer data | Installer |
| `.tls` | Thread-local storage (sometimes abused for anti-debug TLS callbacks) | Watch |

## Import Table (IAT)

The import table lists DLLs and functions the binary uses. Key analysis points:

**Suspicious import combinations:**
| Imports | Likely purpose |
|---------|---------------|
| `VirtualAlloc` + `VirtualProtect(PAGE_EXECUTE_READWRITE)` | Runtime code generation / unpacking |
| `CreateRemoteThread` + `VirtualAllocEx` + `WriteProcessMemory` | Process injection |
| `IsDebuggerPresent` / `NtQueryInformationProcess` | Anti-debug |
| `LoadLibraryA` + `GetProcAddress` only | Dynamic API resolution (packed/shellcode) |
| `InternetOpenA` + `InternetReadFile` | HTTP download |
| `CryptEncrypt` / `CryptDecrypt` | CryptoAPI usage |
| `RegOpenKeyExA` + `RegSetValueExA` | Registry persistence |

**Minimal import table (2–5 imports, all from kernel32)** → almost certainly packed.

## .data / .rdata — Where Keys and Config Live

Hardcoded encryption keys, C2 URLs, and configuration data are typically found in:

1. **`.rdata`** — read-only initialized data (string literals, const arrays)
2. **`.data`** — read-write initialized data (global variables, mutable config)
3. **Resources (`.rsrc`)** — embedded files, encrypted blobs, config blocks

**Finding keys with bin_bytes_at:**
```
# After identifying a key reference in decompilation (e.g., at virtual address 0x00404010):
# Convert VA to file offset: file_offset = VA - section_VA + section_PointerToRawData
bin_bytes_at path=<binary> offset=<file_offset> length=32
```

## Entropy Reference

| Entropy | Meaning |
|---------|---------|
| 0.0 | Uniform (all same byte) |
| 3.0–5.0 | Normal code/data |
| 5.0–6.5 | Compressed or structured data |
| 6.5–7.5 | Likely compressed |
| 7.5–8.0 | Encrypted or packed (high randomness) |

Per-section entropy > 7.0 on the main code section is a strong packer indicator.
