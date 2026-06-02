# Reference Index

`references/` is split into two layers:

- **Local short-form** (this directory) — fast-lookup distillations + working code: `windows-anti-debug.md`, `linux-anti-debug.md`, `packer-signatures.md`, `pe-format-quick-ref.md`, `shellcode-patterns.md`, `common-crypto-patterns.md`, `qiling-emulation.md`. Read these for the **how**.
- **External mirrors** (`external/`) — point-in-time snapshots of authoritative sources. ~22,000 lines across 90 files. Grep these for the **detail**. See `SOURCES.md` for attribution + license per source.

## How to look something up

```bash
# Always start with grep across the whole mirror. The agent should
# search across all reference content rather than guess which file
# might have it.
grep -rln "<term>" references/external/

# When you know the topic, narrow to a directory:
grep -rln "NtSetInformationThread" references/external/unprotect/
grep -rln "PEB.BeingDebugged"       references/external/unprotect/
grep -rln "UPX"                     references/external/unprotect/

# For struct layouts / offset tables, the Microsoft and Apple specs
# are the canonical word:
grep -n "Optional Header"    references/external/formats/ms-pe-format.md
grep -n "load_command"       references/external/formats/apple-macho.md
grep -n "Elf64_Ehdr"         references/external/formats/elf-man5.md
```

For sources cited by URL (Check Point Anti-Debug Encyclopedia, ired.team, al-khaser source), fetch the page on demand — these are not mirrored in-tree. See `SOURCES.md` for the full attribution + access policy per source.

## Topic → where to look first

### Windows anti-debug — API calls

Each row's primary is the local Unprotect mirror; fall back to the Check Point Anti-Debug Encyclopedia category at [anti-debug.checkpoint.com](https://anti-debug.checkpoint.com/) (fetch on demand) when Unprotect doesn't have it.

| Search term | Primary (mirrored) | Check Point category (fetch) |
|---|---|---|
| `IsDebuggerPresent` | `external/unprotect/isdebuggerpresent.md` | debug-flags |
| `CheckRemoteDebuggerPresent` | `external/unprotect/checkremotedebuggerpresent.md` | debug-flags |
| `NtQueryInformationProcess` / `ZwQueryInformationProcess` | `external/unprotect/ntqueryinformationprocess.md` | debug-flags |
| `NtSetInformationThread` (HideFromDebugger) | `external/unprotect/ntsetinformationthread.md` | debug-flags |
| `NtQuerySystemInformation` | — | debug-flags |
| `NtSetDebugFilterState` | `external/unprotect/ntsetdebugfilterstate.md` | — |
| `RtlQueryProcessHeapInformation` / `RtlQueryProcessDebugInformation` | — | debug-flags |
| `OutputDebugString` (anti-debug variant) | — | misc |
| `NtClose` / `CloseHandle` invalid-handle trick | `external/unprotect/closehandle-ntclose.md` | object-handles |
| `NtQueryObject` (DebugObject) | `external/unprotect/ntqueryobject.md` | object-handles |
| `CsrGetProcessId` | `external/unprotect/csrgetprocessid.md` | object-handles |
| `SuspendThread` | `external/unprotect/suspendthread.md` | — |
| `NtDelayExecution` / `Sleep` | `external/unprotect/ntdelayexecution.md` | — |

### Windows anti-debug — PEB / KUSER_SHARED_DATA / heap

| Search term | Where |
|---|---|
| `PEB.BeingDebugged` (offset +2) | `external/unprotect/isdebugged-flag.md`; Check Point debug-flags (fetch) |
| `NtGlobalFlag` (PEB+0x68 / +0xBC) | `external/unprotect/ntglobalflag.md`; Check Point debug-flags (fetch) |
| Heap Flags / ForceFlags | `external/unprotect/heap-flag.md`; Check Point debug-flags (fetch) |
| `KUSER_SHARED_DATA` (0x7ffe0000) | Check Point debug-flags (fetch) |
| PEB structure walk (LDR / Modules) | [ired.team / exploring-the-peb](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block) (fetch) |

### Windows anti-debug — exceptions / hardware / timing

| Search term | Where |
|---|---|
| `INT 2D` | `external/unprotect/interrupts.md`; Check Point assembly (fetch) |
| `INT 3` (0xCC) scanning | `external/unprotect/int3-instruction-scanning.md`; Check Point process-memory (fetch) |
| Trap Flag (TF) | `external/unprotect/trap-flag.md`; Check Point assembly (fetch) |
| `ICE 0xF1` instruction | `external/unprotect/ice-0xf1.md` |
| ICE / single-step trap | Check Point assembly (fetch) |
| Hardware breakpoints / DR0–DR3 | `external/unprotect/debug-registers-hardware-breakpoints.md`; Check Point process-memory (fetch) |
| VEH / `AddVectoredExceptionHandler` | `external/unprotect/addvectoredexceptionhandler.md`; Check Point exceptions (fetch) |
| `UnhandledExceptionFilter` | `external/unprotect/unhandled-exception-filter.md`; Check Point exceptions (fetch) |
| `RDTSC` | `external/unprotect/rdtsc.md`; Check Point timing (fetch) |
| `GetTickCount` / `QueryPerformanceCounter` / `timeGetTime` | `external/unprotect/getlocaltime-getsystemtime-timegettime-ntqueryperformancecounter.md`; Check Point timing (fetch) |
| TLS callbacks | `external/unprotect/tls-callback.md`; Check Point misc (fetch) |
| Guard pages | `external/unprotect/guard-pages.md`; Check Point process-memory (fetch) |
| `LocalSize 0` heap trick | `external/unprotect/localsize0.md` |
| Self code-checksum | Check Point process-memory (fetch) |

### Windows anti-debug — environment / interactive

| Search term | Where |
|---|---|
| Process enumeration (`Process32First/Next`, `EnumProcesses`) | `external/unprotect/detecting-running-process-enumprocess-api.md`; Check Point interactive (fetch) |
| Window enumeration (`FindWindow`) | `external/unprotect/detecting-window-with-findwindow-api.md`; Check Point interactive (fetch) |
| Hostname / username heuristics | `external/unprotect/detecting-hostname-username.md` |
| Mouse activity | `external/unprotect/checking-mouse-activity.md` |

### Linux / macOS anti-debug

| Search term | Where |
|---|---|
| `ptrace(PTRACE_TRACEME)` | `linux-anti-debug.md` (local), `external/unprotect/` (grep) |
| `/proc/self/status` TracerPid | `linux-anti-debug.md` (local) |
| `kernel-flag-inspection-via-sysctl` (macOS `P_TRACED`) | `external/unprotect/kernel-flag-inspection-via-sysctl.md` |
| `manipulating-debug-logs` | `external/unprotect/manipulating-debug-logs.md` |
| macOS technique writeups | `external/objective-see/blog-index.md` (post titles → URLs) |

### Anti-VM / anti-sandbox

| Search term | Where |
|---|---|
| `CPUID` hypervisor bit / brand | `external/unprotect/cpuid.md` |
| `SIDT` (Red Pill) | `external/unprotect/sidt-red-pill.md` |
| `SMSW` | `external/unprotect/smsw.md` |
| `VPCEXT` | `external/unprotect/vpcext.md` |
| Thermal zone temperature | `external/unprotect/thermal-zone-temperature.md` |
| VM artifact files / processes | `external/unprotect/detecting-virtual-environment-{files,process,artefacts}.md` |

### Packers (identification + unpacking)

| Packer | Where |
|---|---|
| UPX | `packer-signatures.md` (local; UPX unpacks with `upx -d`), `external/unprotect/upx-ultimate-packer-for-executables.md` |
| ASProtect | `external/unprotect/asprotect.md` |
| Themida / WinLicense | `external/unprotect/themida.md` |
| VMProtect | `external/unprotect/vmprotect.md` |
| MPRESS | `external/unprotect/mpress.md` |
| Petite | `external/unprotect/petite.md` |
| Obsidium | `external/unprotect/obsidium.md` |
| FSG | `external/unprotect/fsg.md` |
| PECompact | `packer-signatures.md` (local) |
| Enigma Protector | `packer-signatures.md` (local) |
| .NET (ConfuserEx / Eazfuscator / SmartAssembly) | `packer-signatures.md` (local), `external/unprotect/net-anti-decompiler.md`, `external/unprotect/net-reactor.md` |
| Generic anti-decompilation (.NET) | `external/unprotect/niximports.md`, `external/unprotect/milfuscator.md` |
| Modern packers (HxOR, CryptOne, EasyCrypter, PureCrypter, LimeCrypter, Cloudeyedarkeye) | `external/unprotect/{hxor-packer,cryptone,easycrypter,purecrypter,limecrypter,cloudeyedarkeye}.md` |
| PyArmor / .NET obfuscation | `external/unprotect/pyarmor.md` |
| FLIRT signature evasion | `external/unprotect/flirt-signatures-evasion.md` |

### Binary formats — canonical specs

| Format | Local (quick) | External (canonical) |
|---|---|---|
| PE / PE32+ | `pe-format-quick-ref.md` | `external/formats/ms-pe-format.md` (Microsoft) |
| ELF | (use canonical) | `external/formats/elf-man5.md` (Linux man), `external/formats/elf-gabi-toc.md` (Linux Foundation gABI ToC) |
| Mach-O | (none — Qiling gap noted in SKILL) | `external/formats/apple-macho.md` (Apple ABI ref) |
| Visual format posters | — | `external/formats/corkami-binary-readme.md` (Corkami PE/ELF/Mach-O 101) |

### Shellcode / API hashing / PEB walk

- `shellcode-patterns.md` (local) — PEB walk offsets per arch, ROR13 known-hash table, Capstone XOR-site detection, stack-string reconstruction.
- [ired.team / exploring-the-peb](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block) — PEB internals walkthrough (fetch on demand).
- [ired.team / pe-file-header-parser-in-c++](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++) — PE-header parser in C++ (fetch on demand).

### Crypto pattern recovery

- `common-crypto-patterns.md` (local) — working decoders: XOR (single / multi / layered), RC4, AES (ECB / CBC), Base64, custom substitution, TEA/XTEA. Hash-init constant table for algorithm identification.
- `scripts/xor_brute.py` — single + multi-byte XOR with known-plaintext support.

### Qiling emulation

- `qiling-emulation.md` (local) — `install_antidebug_bypass`, `install_api_logger`, `install_dump_at_api`, end-to-end `emulate()`, per-arch rootfs guide, common errors.

### Symbolic execution (angr)

- `symbolic-execution.md` (local) — find/avoid for input recovery, SimProcedure `hook_symbol` dump-at-compare, explicit-address find, stdin-driven recovery, state-explosion mitigation, Qiling-vs-angr decision rule. Templates verified against angr 9.2.x.

### Comparison-site analysis (license / password / flag checkers)

- [ired.team / reversing-a-password-protected-application](https://www.ired.team/miscellaneous-reversing-forensics/reversing-c-c++-binaries-with-radare2/reversing-a-password-protected-application) — worked example of reversing a password-check routine (fetch on demand).

### Practitioner reading / research

- `external/hasherezade/blog-index.md` — PE-bear, pe-sieve, libpeconv author. Index of posts on PE internals, unpacking, in-memory injection.
- `external/oalabs/research-index.md` — OALabs research index.
- `external/objective-see/blog-index.md` — Patrick Wardle's macOS reverse-engineering posts (index).

### MITRE ATT&CK / MBC IDs

Each Unprotect technique page lists ATT&CK `T####` and MBC `B####` identifiers — grep for them directly:

```bash
grep -rln "T1622" references/external/    # Debugger Evasion
grep -rln "T1027.002" references/external/ # Software Packing
grep -rln "T1497" references/external/    # Virtualization/Sandbox Evasion
grep -rln "B0001" references/external/    # Anti-debug (MBC family)
```
