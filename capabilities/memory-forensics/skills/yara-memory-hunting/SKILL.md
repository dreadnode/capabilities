---
name: yara-memory-hunting
description: Use YARA against memory images to locate known malware, C2 frameworks, and custom IoCs. Covers rule selection, scoping (process vs whole image), false-positive control, and pivoting hits into structured findings.
---

# YARA Memory Hunting

Maps to [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter) and [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information) when classifying samples. For rule sources see Elastic [protections-artifacts](https://github.com/elastic/protections-artifacts), [YARA-Forge](https://yarahq.github.io/), and vendor reports.

## When to Use
- You have IoCs (strings, byte patterns, config layouts) and want to confirm / scope
- Triage surfaced a suspect process and you want to classify the family
- Sweeping an image for commodity C2 frameworks (Cobalt Strike, Sliver, Brute Ratel, Metasploit, etc.)

## Scoping Decisions First

| Goal | Scope | Rule style |
|---|---|---|
| "Is *this* process X?" | Single PID via `pid=N` | Specific, tight strings |
| "Where in the image does X live?" | Whole image | Broader, paired-condition rules |
| "Is there anything bad here at all?" | Whole image | Curated commodity-framework pack |

Whole-image scans are slow and noisy. Use them when you don't yet have a suspect, then narrow to PIDs.

## Workflow

### 1. Pick the rule set
For commodity C2 and known malware, start with community-maintained packs:
- Elastic Protections Artifacts (`protections-artifacts/yara/rules/`)
- YARA-Forge aggregate
- Vendor-published rules attached to report writeups (Mandiant, Volexity, CrowdStrike blogs)

For custom IoCs derived from triage, **write the rule inline** — don't manage a file for a one-shot.

### 2. Run the scan
```
volatility_yara_scan(image, rules_file="/path/to/rules.yar", pid=None)
```
or
```
volatility_yara_scan(image, rules_inline="""
rule MyCustom { strings: $a = "CONFIG:" condition: $a }
""", pid=1234)
```

Exactly one of `rules_file` / `rules_inline`. The `pid` filter dramatically speeds up scans when you have a suspect.

### 3. Interpret hits
Each hit gives you: rule name, PID, process, virtual address, matching string(s). Triage each:
- **High specificity rule (tight strings, multi-condition)** — trust the verdict, move to analysis
- **Generic rule (single common string)** — corroborate before acting
- **Hit on a `csrss`, `services`, `svchost`** — elevated priority; system processes don't normally contain arbitrary strings
- **Hit on a user-mode browser / IDE / chat app** — often benign (strings in page cache, clipboard, logs)

### 4. Pivot
For each confirmed hit:
- `volatility_malfind --pid N` to see if the hit sits inside an injected region
- `volatility_dll_list --pid N` to see what module the offset maps into (if any)
- `volatility_dump_process --pid N --mode vad` and carve around the hit offset for offline triage
- Derive new IoCs (neighboring strings, config blobs, mutex names) and re-scan

## Rule Patterns That Work Well Against Memory

### Config-block pattern (Cobalt Strike / Sliver style)
```yara
rule CS_Beacon_Config {
  strings:
    $magic = { 2E 2E 2E 2E ?? ?? 2E 2E 2E 2E }   // XOR-key surrounded config
    $sleep = "Beacon_mask" ascii wide
    $post  = "post-ex" ascii wide
  condition:
    2 of them
}
```

### Decoded-in-memory string pattern
Decrypted strings appear in memory even if encrypted on disk. Target what only shows up after unpacking:
```yara
rule FamilyX_Runtime_Strings {
  strings:
    $cmd1 = "!@#run_payload@#!" ascii wide
    $cmd2 = "!@#beacon_check@#!" ascii wide
    $err  = "FamX: failed to allocate" ascii wide
  condition:
    any of them
}
```

### API-resolution pattern
Malware that dynamically resolves APIs leaves the names in memory:
```yara
rule Injector_API_Resolution {
  strings:
    $a1 = "NtAllocateVirtualMemory"
    $a2 = "NtWriteVirtualMemory"
    $a3 = "NtCreateThreadEx"
    $a4 = "RtlAdjustPrivilege"
  condition:
    3 of them
}
```
Benign software rarely stores these as plaintext strings (they're in import tables, not data).

### Mutex / named-pipe pattern
```yara
rule Beacon_NamedPipe {
  strings:
    $p1 = "\\\\.\\pipe\\msagent_" ascii wide
    $p2 = "\\\\.\\pipe\\postex_" ascii wide
    $p3 = "\\\\.\\pipe\\status_" ascii wide
  condition:
    any of them
}
```

## False-Positive Control
- Never rely on single-string rules unless the string is a hash / GUID / long unique phrase
- Pair "would appear in malware" strings with "would *not* appear in benign software" strings
- Scope by process type: system processes (`lsass`, `services`, `svchost`) have a tiny legitimate string set; hits there are almost always real
- Every hit in a browser, email client, or IDE needs corroboration — those processes scrape the internet into memory and will match almost anything

## Timeouts and Budgets
Whole-image YARA is slow. The MCP defaults to 600s; raise `timeout` for larger images or heavy rule packs. When iterating rules, scope to `pid=N` first to get fast feedback, then widen.

## Common Pitfalls
- Rules with only wide strings miss ASCII-compiled binaries; use `ascii wide` liberally
- Very long strings may not match if the memory range they land in is paged out — prefer shorter signatures with stronger condition logic
- Vol3 yarascan wants a **compiled or source `.yar` file**, not a compiled `.yarc` — pass source
