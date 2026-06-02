# Shellcode Patterns

Quick-reference for identifying and analyzing common shellcode constructs found in malware payloads, exploits, and extracted binary blobs.

**For PEB internals** (offsets, LDR walk, module list structure), see [ired.team / exploring-the-peb](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block) — fetch on demand. **For canonical PE header layout** referenced during reflective loaders, see `../external/formats/ms-pe-format.md`.

## PEB Walk (Windows API Resolution)

Shellcode can't use import tables — it resolves APIs at runtime by walking kernel32.dll exports via the PEB.

**Identification:**
```asm
; x86 — classic PEB walk
mov eax, fs:[0x30]       ; PEB
mov eax, [eax+0x0C]      ; PEB->Ldr (PEB_LDR_DATA)
mov eax, [eax+0x14]      ; InMemoryOrderModuleList
; ... walk linked list to find kernel32.dll base
```

```asm
; x64 — same concept, different offsets
mov rax, gs:[0x60]       ; PEB (x64)
mov rax, [rax+0x18]      ; PEB->Ldr
mov rax, [rax+0x20]      ; InMemoryOrderModuleList
```

**Key offsets (x86):**
| Segment Register | Offset | Field |
|-----------------|--------|-------|
| `fs:[0x30]` | — | PEB |
| PEB + 0x0C | — | PEB_LDR_DATA |
| LDR + 0x14 | — | InMemoryOrderModuleList |
| LDR + 0x1C | — | InInitializationOrderModuleList |

## API Hashing

Shellcode identifies API functions by hash rather than name string to avoid detection.

**Common hash algorithms and known values:**

### ROR13 (most common — used by Metasploit)
```python
def ror13_hash(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
```

| Hash | API |
|------|-----|
| `0x0726774C` | `kernel32.dll!LoadLibraryA` |
| `0x7C0DFCAA` | `kernel32.dll!GetProcAddress` |
| `0x006B8029` | `kernel32.dll!WinExec` |
| `0xE8AFE98` | `kernel32.dll!VirtualAlloc` |
| `0x56A2B5F0` | `kernel32.dll!ExitProcess` |
| `0x5FC8D902` | `ws2_32.dll!WSAStartup` |
| `0x6737DBC2` | `ws2_32.dll!connect` |
| `0xE0DF0FEA` | `ws2_32.dll!WSASocketA` |

### CRC32-based
Some shellcode uses CRC32 of the function name. Identify by presence of CRC32 lookup table (256 × 4 bytes starting with `0x00000000, 0x77073096, 0xEE0E612C...`).

### djb2
```python
def djb2_hash(name: str) -> int:
    h = 5381
    for c in name:
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF
    return h
```

**Brute-force hash lookup:**
```python
# Build a table of known API hashes for identification
import itertools
KNOWN_APIS = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
              "CreateThread", "WinExec", "ExitProcess", "WSAStartup", "connect",
              "send", "recv", "socket", "CreateFileA", "WriteFile", "ReadFile"]

def build_hash_table(hash_func):
    return {hash_func(api): api for api in KNOWN_APIS}
```

## XOR Decode Loops

The most common shellcode obfuscation — decode a payload with XOR before execution.

**Identification in disassembly:**
```asm
; Single-byte XOR decode
mov ecx, <length>
mov esi, <encoded_payload>
xor_loop:
    xor byte [esi], <key>
    inc esi
    loop xor_loop
    jmp <decoded_payload>
```

```asm
; Multi-byte XOR with counter
mov ecx, <length>
xor edx, edx           ; index into key
xor_loop:
    mov al, [key + edx]
    xor [buf + edx_outer], al
    inc edx
    cmp edx, <key_len>
    jb no_reset
    xor edx, edx
no_reset:
    ...
```

**Capstone pattern detection:**
```python
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

xor_sites = []
for insn in md.disasm(code, base_addr):
    if insn.mnemonic == 'xor':
        # Skip register self-XOR (zeroing pattern)
        ops = insn.operands
        if len(ops) == 2 and not (ops[0].type == ops[1].type == 1 and ops[0].reg == ops[1].reg):
            xor_sites.append((insn.address, insn.op_str))
```

## Stack Strings

Shellcode builds strings on the stack to avoid them appearing in static analysis.

**Identification:**
```asm
; Push string in reverse (x86, little-endian)
push 0x00636578       ; "xec\0"
push 0x456E6957       ; "WinE"
; ESP now points to "WinExec\0"
```

**Extraction:**
```python
import struct

def extract_push_string(push_values: list[int]) -> str:
    """Reconstruct string from reversed push immediates."""
    raw = b""
    for val in reversed(push_values):
        raw += struct.pack("<I", val)
    return raw.rstrip(b"\x00").decode("ascii", errors="replace")

# Example: push_values = [0x00636578, 0x456E6957]
# → "WinExec"
```

## Common Shellcode Structures

### Reverse TCP shell
1. `WSAStartup` → `WSASocketA` → `connect(ip, port)` → loop `recv` into `VirtualAlloc` buffer → `CreateThread` or direct `jmp`

### Download-and-execute
1. `LoadLibraryA("urlmon.dll")` → `GetProcAddress("URLDownloadToFileA")` → download to temp → `WinExec`

### Reflective DLL injection
1. Resolve `VirtualAlloc` → allocate RWX region → copy PE headers + sections → fix relocations → resolve imports → call DllMain

**Key indicators:**
| Pattern | Likely purpose |
|---------|---------------|
| `VirtualAlloc` + `RWX` (0x40) | Preparing executable memory |
| `VirtualProtect` changing to `PAGE_EXECUTE_READ` | Making decoded payload executable |
| Loop copying data then `jmp`/`call` to it | Unpacking + execution |
| `fs:[0x30]` or `gs:[0x60]` access | PEB walk for API resolution |
| Sequence of `push imm32` before API call | Stack string construction |
| `0x9E3779B9` constant | TEA/XTEA encryption in shellcode |
