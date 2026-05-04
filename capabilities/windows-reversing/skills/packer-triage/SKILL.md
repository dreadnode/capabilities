---
name: packer-triage
description: Identify whether a PE is packed, recognize the packer, and extract the unpacked payload for further static analysis — using emulation to run to the OEP when needed.
---

# Packer Triage

Maps to **MITRE ATT&CK [T1027.002 Software Packing](https://attack.mitre.org/techniques/T1027/002/)** and **[T1140 Deobfuscate/Decode Files](https://attack.mitre.org/techniques/T1140/)**. capa emits these IDs natively under the `obfuscation/packer` rule family (and the corresponding **MBC [F0001 Packer](https://github.com/MBCProject/mbc-markdown/blob/master/anti-static-analysis/executable-packing.md)** classifiers) — pass them through to the report.

## When to Use
- `pe_info` shows a single code section with entropy > 7.0.
- Import table is suspiciously small (often just `kernel32!LoadLibraryA`
  + `GetProcAddress`).
- Section names like `UPX0`, `UPX1`, `.aspack`, `.themida`, `.vmp0`.
- `pe_strings` returns almost nothing recognizable.

## Identify the Packer

### Quick hints
| Signal                                     | Likely packer        |
|--------------------------------------------|----------------------|
| Sections `UPX0` / `UPX1`                   | UPX                  |
| Section `.aspack`                          | ASPack               |
| Imports only `kernel32!LoadLibraryA`, `GetProcAddress` | UPX / custom |
| Section `.themida` / `.vmp0..vmp2`         | Themida / VMProtect (hard) |
| Huge section, low import count, IAT built at runtime | Custom loader |

### Automated
```
pe_capa --summary_only
```
Look for tags under the "anti-analysis" / "packer" families.

## Unpacking Approaches

### UPX (the easy case)
UPX ships a compatible `upx -d` unpacker. This capability does not
bundle UPX — if available on PATH, run it directly:
```
upx -d -o <unpacked>.exe <packed>.exe
pe_info <unpacked>.exe   # now has a normal import table
```

### Custom loader — dump at OEP
The pattern is: the packed binary runs a stub that decrypts the real
code, rebuilds the IAT, then jumps to the Original Entry Point (OEP).
`qiling_api_trace` can catch that jump.

1. Run with a long timeout and log IAT-build APIs:
   ```
   qiling_api_trace path=<packed> \
     apis=["LoadLibraryA","LoadLibraryW","GetProcAddress","VirtualAlloc","VirtualProtect"] \
     bypass_antidebug=true
   ```
2. The **last** `VirtualProtect` call before the stub stops calling
   `GetProcAddress` is typically on the freshly-reconstructed code
   section. The address and size of that region is your unpacked
   payload.
3. Use `qiling_dump_at_api` on that `VirtualProtect` (param index 0 =
   lpAddress, 1 = dwSize) to capture the memory.
4. Carve the MZ/PE header out of the dump and re-run static triage
   against it.

### Themida / VMProtect / custom VM
Out of scope for a first-pass emulation approach. Note that it's
heavy VM-based obfuscation and move on — these challenges usually
want a side-channel solve (weakness in the checker, not the VM).

## Hand Off
Once you have the unpacked payload:
- Re-run `pe_info` — the import table should now be normal.
- Re-run `pe_strings` and `pe_capa` — expect new hits.
- Send to `ghidra_analyze` for decompilation.
