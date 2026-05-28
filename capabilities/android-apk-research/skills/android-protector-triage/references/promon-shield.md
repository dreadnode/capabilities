# Promon Shield triage reference (research preview)

Grounding: like DexProtector, Promon Shield sits under OWASP MASVS-RESILIENCE (<https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/>); MASTG-TEST-0089 *Testing Resiliency Against Reverse Engineering* covers the RASP / shield-binding controls Promon implements (<https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0089/>).

**Status: research-grade — not wired into the protector-triage skill workflow.** `protector_detect.py` flags Promon Shield from APKiD + native-library + ELF-section signals, but the static recovery scripts under `scripts/research/promon/promon_*` are first-pass evaluators that have not been validated across enough samples to recommend in the routine flow. Treat output as exploratory adjacency analysis; do not promote Promon-shielded findings to `strong_static_chain` based on these artifacts alone.

This file captures public Promon Shield reversing references and the experimental recovery pipeline. The agent should not invoke it unless the user explicitly asks for the Promon research path.

Primary sources:

- Promon product page: <https://promon.io/products/shield-mobile>
- APKiD ELF rules for Promon Shield: <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/elf/packers.yara>
- APKiD issue referencing Promon use in German banking apps / 34C3 talk: <https://github.com/rednaga/APKiD/issues/72>
- 34C3 talk, *Die fabelhafte Welt des Mobilebankings*: <https://media.ccc.de/v/34c3-8805-die_fabelhafte_welt_des_mobilebankings>
- DIMVA 2018 paper, *Honey, I Shrunk Your App Security: The State of Android App Hardening*: <https://obfuscator.re/nomorp-paper-dimva2018.pdf> / <https://link.springer.com/chapter/10.1007/978-3-319-93411-2_4>
- Public reversing repo: <https://github.com/KiFilterFiberContext/promon-reversal>
- Public string-deobfuscator repo: <https://github.com/RevealedSoulEven/promon-string-deobfuscator>

## Research findings

## Implemented static workflow

Current capability-native scripts:

| Stage | Script | Status | Output |
| --- | --- | --- | --- |
| Detect/routing | `scripts/protector_detect.py` | Implemented for APKiD inventory hits, Promon native library names, `.ncu/.ncc/.ncd` ELF section pairs, and historical assets. | `protector.json` |
| Smali string recovery | `scripts/research/promon/promon_string_recover.py` | Implemented first-pass evaluator for inline char-array/`String.intern()` and helper methods returning `[C`. Does not rebuild APKs by default. | `strings.jsonl`, optional patched smali, summary markdown |
| Java/smali integration triage | `scripts/research/promon/promon_java_triage.py` | Implemented mapper for native method declarations, native callsites, load-library callsites, framework hints, and string-recovery coverage hints. | `java-triage.json`, `native-methods.jsonl`, `native-call-sites.jsonl`, `load-library-sites.jsonl`, summary markdown |
| Binding callsite map | `scripts/research/promon/promon_binding_triage.py` | Implemented focused extraction of native string/class binding IDs and immediate sink context. | `promon-bindings.jsonl`, `promon-bindings.json`, summary markdown |
| Native ELF triage | `scripts/research/promon/promon_elf_triage.py` | Implemented static APK/ELF profiler: candidate extraction, section/segment metadata, entropy, `.init_array`, visible imports, RASP strings, AArch64 `SVC #0` sites. | `elf-triage.json`, `elf-sections.jsonl`, `syscall-sites.jsonl`, `native-imports.txt`, summary markdown |
| Orchestration | `scripts/research/promon/promon_recover.py` | Implemented wrapper for detection, optional apktool decode, string recovery, ELF triage, and a roll-up summary. | `RECOVERY_SUMMARY.md` plus all above artifacts |

Preferred command for a full static pass:

```bash
python3 scripts/research/promon/promon_recover.py path/to.apk -o findings/<pkg>/promon
```

If apktool is unavailable or you only want native triage:

```bash
python3 scripts/research/promon/promon_recover.py path/to.apk -o findings/<pkg>/promon --skip-apktool
```

Manual pipeline equivalent:

```bash
# 1. Detect/routing
python3 scripts/protector_detect.py path/to.apk \
  -o findings/<pkg>/promon/protector.json

# 2. Decode smali
apktool d -f path/to.apk \
  -o findings/<pkg>/promon/smali-raw

# 3. Recover Promon-style string constants
python3 scripts/research/promon/promon_string_recover.py \
  findings/<pkg>/promon/smali-raw \
  -o findings/<pkg>/promon/strings.jsonl \
  --patched-out findings/<pkg>/promon/smali-strings-recovered \
  --summary findings/<pkg>/promon/string-recovery-summary.md

# 4. Map Java/native integration and Promon binding IDs
python3 scripts/research/promon/promon_java_triage.py \
  findings/<pkg>/promon/smali-raw \
  -o findings/<pkg>/promon/java-triage.json \
  --native-methods-out findings/<pkg>/promon/native-methods.jsonl \
  --native-calls-out findings/<pkg>/promon/native-call-sites.jsonl \
  --load-sites-out findings/<pkg>/promon/load-library-sites.jsonl \
  --summary findings/<pkg>/promon/promon-java-summary.md

python3 scripts/research/promon/promon_binding_triage.py \
  findings/<pkg>/promon/smali-raw \
  -o findings/<pkg>/promon/promon-bindings.jsonl \
  --json findings/<pkg>/promon/promon-bindings.json \
  --summary findings/<pkg>/promon/promon-binding-summary.md

# 5. Profile native shield library/libraries
python3 scripts/research/promon/promon_elf_triage.py path/to.apk \
  -o findings/<pkg>/promon
```

Expected artifact layout:

```text
findings/<pkg>/promon/
  protector.json
  smali-raw/                         # when apktool decode is run
  smali-strings-recovered/           # optional patched smali for analysis
  strings.jsonl
  string-recovery-summary.md
  java-triage.json
  native-methods.jsonl
  native-call-sites.jsonl
  load-library-sites.jsonl
  promon-java-summary.md
  promon-bindings.jsonl
  promon-bindings.json
  promon-binding-summary.md
  elf-triage.json
  elf-sections.jsonl
  syscall-sites.jsonl
  native-imports.txt
  promon-elf-summary.md
  RECOVERY_SUMMARY.md
  libs/<abi>/<candidate>.so           # extracted Promon candidates from APK
```

Current implemented limitations:

- `promon_string_recover.py` expects apktool-decoded smali. It does not invoke apktool itself.
- String recovery supports a conservative subset of integer/char operations and does not execute arbitrary generated code.
- Patched smali is for analysis/decompilation assistance; it is not guaranteed rebuild-valid in every control-flow context.
- `promon_binding_triage.py` maps IDs and sink context but does not recover plaintext values.
- `promon_elf_triage.py` does not decrypt/unpack protected native sections.
- AArch64 syscall labels are heuristic and only resolve simple nearby `movz/movn w8, #imm` patterns.
- Direct real-sample APK validation is pending restoration of the local `in.org.npci.upiapp` APK; current local anchor has inventory/APKiD metadata.

### What Promon is, operationally

Promon Shield is primarily a **post-compile native app-shielding / RASP** target, not a DexProtector-style “most DEX is hidden in `assets/classes.dex.dat`” target.

Promon's own product page describes:

- post-compile integration;
- protection against tampering, reverse engineering, malware, rooted / jailbroken devices, debuggers, hooking, repackaging, screenshots, overlays, and keyloggers;
- app / Shield binding, so protection cannot be disabled by simply removing the shield component;
- response modes including reporting, blocking, and exiting.

Practical consequence: JADX may still preserve significant app code. The first-class missing artifacts are usually **runtime strings, protected class / field bindings, native shield internals, policy/config, and native RASP decisions**, not necessarily all first-party DEX.

### Public prior art

| Source | What it contributes | Capability implications |
| --- | --- | --- |
| APKiD ELF rules | High-confidence IoCs: `libshield.so` or random `lib[a-z]{10,12}.so`; at least two of `.ncu`, `.ncc`, `.ncd`. APKiD comments describe `.ncc` as code, `.ncd` as data, `.ncu` as another protected segment. | Implement Promon branch in `scripts/protector_detect.py` by scanning native libraries and parsing ELF section names. |
| DIMVA 2018 paper / Springer abstract | Describes an in-depth Promon Shield case study. Springer page states the authors demonstrate two attacks: one removes the protection scheme statically, the other disables security measures dynamically at runtime. Search/PDF snippets describe encryption of `.rodata`, `.text`, and `.ncd` with three version-specific keys, plus encrypted assets `config-encrypt.txt`, `mappings.bin`, and `pbi.bin`. | The full recovery goal is not just bypassing checks. We need: section unpack, config recovery, mapping reversal, and Java/native binding removal or modeling. |
| 34C3 talk | Nomorp was used to automatically disable central security/hardening measures in 31 mobile banking apps; German financial apps were heavily represented. APKiD issue #72 was opened from this talk. | Treat banking samples as likely Promon candidates and compare against Nomorp/DIMVA flow. |
| KiFilterFiberContext/promon-reversal | Modern public reversal against Supercell/Brawl Stars. Confirms unobfuscated Dalvik with Promon string/class indirection; native shield packed via `.init_array`; direct `SVC #0` syscalls; dynamic imports; anti-debug ptrace/fork/prctl flow; JDWP interference; APK signing-block parsing via `openat`; checksum of shield library; root/emulator property and filesystem checks; anti-hook checks for Frida, Xposed, Substrate; memory-page integrity. Includes PoC code with sample-specific offsets for `openat` syscall stub replacement and many hook/log points. | Good map of runtime checks and dynamic observability points, but not a generic unpacker. Offset-dependent bypass code should be mined for signatures/check classes, not copied directly as a generic solution. |
| RevealedSoulEven/promon-string-deobfuscator | APKTool/smali pipeline that recognizes Promon-style char-array / `String.intern()` string obfuscation and replaces encrypted constants. Handles methods returning `[C` and dynamic integer-driven string patterns. | First static recovery script should be a clean, non-rebuilding variant that emits JSONL patches and optionally writes deobfuscated smali/JADX-adjacent sources. |

## Identification (Tier 1)

Promon is primarily a **native app-shielding / RASP** target rather than a DexProtector-style DEX asset packer. JADX may still show meaningful Java/Kotlin code. The native shield library is the first-class target.

| Surface | Signal | Source / confidence |
| --- | --- | --- |
| `apkid.json` | `packer: Promon Shield` on a native library | High when APKiD hits. |
| `lib/<abi>/` | `libshield.so` | High if section signals also match. |
| `lib/<abi>/` | Random-looking `lib[a-z]{10,12}.so` with Promon sections | Medium by name alone; high if section signals match. Our corpus sample is `libnamfidcmogmm.so`. |
| ELF sections | At least two of `.ncu`, `.ncc`, `.ncd` | High; this is APKiD's main Promon rule. |
| `assets/` | `config-encrypt.txt`, `mappings.bin`, `pbi.bin` | Medium; described in older Promon integration flows. Newer builds may move config into ELF sections or rename assets. |
| Java/smali | native string method like `static native String a(int)` plus native class-init method like `static native void a(Class,int)` | Medium; from public reversal. Needs app-specific naming normalization. |
| Java/smali | XOR-built library name passed to `System.loadLibrary(new String(char[]).intern())` | Medium-high when it resolves to the Promon native library. |

### Current corpus anchor

Observed in this repo's AndroZoo-84 inventory:

| Package | APK | Artifact | Evidence |
| --- | --- | --- | --- |
| `in.org.npci.upiapp` | `corpus/androzoo/apks-84/in.org.npci.upiapp_203000102_1A643C45E6BA.apk` | `findings/androzoo-84/inventory/apks/1a643c45e6ba07d60be1bfcdb899950dbab6f9b7fb2dfb4492f022527774650c/` | APKiD flags `lib/arm64-v8a/libnamfidcmogmm.so` as `Promon Shield`. |

APKiD also flagged the exposed `classes.dex` with `Debug.isDebuggerConnected()` and multiple `Build.*` VM checks. Treat these as app/stub-adjacent anti-analysis hints, not proof that all checks belong to Promon.

## Expected protection shape

Working model synthesized from APKiD, DIMVA, and public reversal:

```text
App launch / class initialization
  -> Java glue builds or references random shield library name
  -> System.loadLibrary(<libshield/random name>)
  -> shield library constructor in .init_array runs before JNI_OnLoad
  -> constructor dynamically resolves imports and unpacks/decrypts protected native sections
  -> Java string/class/field indirection binds app code to native shield
  -> shield parses installed base.apk and APK signing block, verifies shield checksum / app binding
  -> policy/config is decrypted/evaluated
  -> runtime integrity, anti-debug, anti-hook, root/emulator, repackaging checks run
  -> configured response: report, block, exit, or degrade behavior
```

Promon's public material emphasizes app binding, runtime threat response, and post-compile integration. The public reversal confirms this is implemented with a large native runtime using dynamic imports, direct syscalls, and runtime integrity checks.

Key expectation for triage: **do not assume JADX is empty or mostly missing**. This is closer to “native shield and string/class binding around an otherwise analyzable app” than “encrypted first-party DEX hidden in assets”. The unprotection flow should therefore recover Java strings and shield policy/config, then map/neutralize/model native checks before escalating to dynamic validation.

## Initial static triage workflow

For a candidate APK:

```bash
python3 scripts/protector_detect.py path/to.apk -o findings/<pkg>/protector.json
apkid path/to.apk -j > findings/<pkg>/apkid.json
unzip -l path/to.apk > findings/<pkg>/ziplisting.txt
```

Then extract the Promon candidate library:

```bash
mkdir -p findings/<pkg>/promon
unzip -p path/to.apk lib/arm64-v8a/<candidate>.so > findings/<pkg>/promon/<candidate>.so
readelf -S findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/readelf-sections.txt
readelf -l findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/readelf-program-headers.txt
readelf -d findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/readelf-dynamic.txt
readelf -r findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/readelf-relocs.txt
readelf -W -x .init_array findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/init-array.hex 2>/dev/null || true
strings -a findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/strings.txt
sha256sum findings/<pkg>/promon/<candidate>.so > findings/<pkg>/promon/sha256.txt
```

Minimum evidence to capture:

- Which ABI(s) contain a Promon-like library.
- Exact library names and SHA-256 hashes.
- Presence / absence of `.ncu`, `.ncc`, `.ncd` sections.
- Section sizes, entropy, file offsets, virtual addresses, and flags for Promon sections.
- Init-array entries and whether `JNI_OnLoad` / ELF entry are packed or unhelpful.
- Assets that look like shield config (`config-encrypt.txt`, `mappings.bin`, `pbi.bin`, or renamed high-entropy equivalents).
- Java/Kotlin/smali load site: xrefs to `System.loadLibrary`, XOR-char-array library-name builders, native string/class indirection methods.
- Whether app code remains analyzable in JADX before string recovery.

## Full recovery flow design

### Stage 0 — Corpus and ground truth

1. Start with an APKiD-positive APK and inventory artifacts.
2. Prefer arm64-v8a samples because the public reversal and current corpus anchor are arm64.
3. Save a stable working layout:

```text
findings/<pkg>/promon/
  protector.json
  apkid.json
  ziplisting.txt
  libs/<abi>/<candidate>.so
  elf/<candidate>.sections.json
  smali-raw/
  smali-strings-recovered/
  native-unpacked/
  config/
  dynamic/        # only if authorized
```

### Stage 1 — Native detector and ELF section parser

Implement Promon support in `scripts/protector_detect.py`:

- scan `lib/<abi>/*.so` names for `libshield.so` and `/lib[a-z]{10,12}\.so/`;
- parse ELF section table directly from zipped bytes;
- mark high confidence when any library has at least two of `.ncu`, `.ncc`, `.ncd`;
- optionally ingest APKiD JSON if present;
- record ABI, library path, section names, section offsets/sizes/flags, and section entropy;
- record historical assets: `config-encrypt.txt`, `mappings.bin`, `pbi.bin`.

Suggested normalized output:

```json
{
  "protector": "promon_shield",
  "triage_strategy": "protector_aware_native_rasp",
  "signals": {
    "native_libs": {"arm64-v8a": ["libnamfidcmogmm.so"]},
    "elf_sections": {
      "lib/arm64-v8a/libnamfidcmogmm.so": [".ncc", ".ncd", ".ncu"]
    },
    "promon_assets": []
  },
  "artifacts": {
    "promon_recovery_supported": "research",
    "java_string_recovery_supported": true,
    "static_native_unpack_supported": false
  }
}
```

### Stage 2 — Java/smali recovery before native unpack

This is the highest-value first recovery step because Promon often leaves Dalvik structure intact but externalizes strings and class metadata.

1. Decode with apktool, not just JADX:

```bash
apktool d -f path/to.apk -o findings/<pkg>/promon/smali-raw
```

2. Port the public `promon-string-deobfuscator` into a capability script that:
   - does **not** require rebuilding the APK by default;
   - scans all `smali*` directories;
   - identifies char-array + XOR + `String.intern()` patterns;
   - identifies helper methods returning `[C` and call sites passing integer IDs;
   - writes `strings.jsonl` with file, method, line range, ciphertext pattern, plaintext, and confidence;
   - optionally writes patched smali into `smali-strings-recovered/`.

3. Feed recovered strings back into JADX/ripgrep triage:
   - native library names;
   - URLs/hosts/API paths;
   - class names / reflection targets;
   - anti-analysis strings;
   - deep-link and WebView-relevant constants.

Expected output:

```text
findings/<pkg>/promon/strings.jsonl
findings/<pkg>/promon/smali-strings-recovered/
findings/<pkg>/promon/string-recovery-summary.md
```

### Stage 3 — Shield bootstrap map

From smali/JADX and ELF metadata, build a launch map:

- Java load site and deobfuscated library name.
- Native methods registered by the shield (`RegisterNatives` table if recoverable after unpack; otherwise Java declarations).
- `.init_array` function addresses and their file offsets.
- Imported and dynamically resolved functions; known Promon runtime list from public reversal includes `dlsym`, `dlopen`, `dl_iterate_phdr`, `prctl`, `fork`, `ptrace`, `inotify_*`, `__system_property_get`, direct `openat/read/write/close/mmap/kill/getpid/exit_group/sigaction` syscalls.
- Direct syscall stubs (`SVC #0` on ARM64) with nearby syscall-number materialization.

Expected output:

```text
findings/<pkg>/promon/bootstrap-map.json
findings/<pkg>/promon/syscall-sites.jsonl
findings/<pkg>/promon/native-imports.txt
```

### Stage 4 — Static native section unpack research

Goal: produce a synthetic normalized shared object or memory map with decrypted `.text` / `.rodata` / `.ncd` / `.ncc` / `.ncu` content, analogous in spirit to `scripts/dexprotector_unpack.py` but with a very different target.

Research path:

1. Parse ELF and locate `.init_array` entry. Public reversal says constructor code runs before normal JNI entry and unpacks the binary.
2. Compare protected sections:
   - file bytes / entropy;
   - segment permissions;
   - relocation coverage;
   - whether `.ncc/.ncd/.ncu` are mapped into executable/loadable segments.
3. Identify decrypt/unpack primitive:
   - xrefs from init-array function into section ranges;
   - `mprotect`/cache-flush/syscall sites changing section permissions;
   - loops writing into `.text`, `.rodata`, `.ncd`, `.ncc`, or anonymous mappings;
   - constants/keys near init routine. DIMVA snippets indicate three version-specific keys for `.rodata`, `.text`, and `.ncd` in older builds.
4. Build an emulator harness only for the constructor/decrypt routine when static lifting is understood enough to provide imports/memory. Do not execute the app or arbitrary shield response code as the first step.
5. Emit either:
   - `native-unpacked/<lib>.decrypted.so` if sections can be written back; or
   - `native-unpacked/<lib>.memory-map/` with section dumps and address metadata if the runtime layout is not ELF-compatible.

Expected output contract:

```text
findings/<pkg>/promon/native-unpacked/<candidate>.sections.json
findings/<pkg>/promon/native-unpacked/<candidate>.decrypted.so      # if possible
findings/<pkg>/promon/native-unpacked/<candidate>.memory.json       # otherwise
findings/<pkg>/promon/native-unpacked/strings.txt
```

Current confidence: **medium** that this is feasible per-version; **low** that it will be one-shot generic across modern Promon versions without version classifiers.

### Stage 5 — Config and policy recovery

Older public material names encrypted assets:

- `assets/config-encrypt.txt` — shield policy/config;
- `assets/mappings.bin` — Java/native binding or mapping metadata;
- `assets/pbi.bin` — protected binding/integrity metadata.

Modern samples may move or rename these. Recovery strategy:

1. Inventory assets and entropy; identify small high-entropy blobs loaded by shield.
2. Search recovered native strings and syscall/open hooks for asset names.
3. If static keys/routines are recovered, write decryptor for the config assets.
4. If dynamic validation is authorized, hook **after config decryption and before config evaluation** to dump plaintext config. DIMVA describes disabling Promon dynamically by rewriting config values after decryption but before evaluation; for our workflow, first dump and model the config rather than modifying it.
5. Normalize config into feature toggles:
   - anti-debug / ptrace;
   - anti-hook / Frida / Xposed / Substrate;
   - root/emulator checks;
   - APK signature / repackaging;
   - shield self-checksum;
   - response action.

Expected output:

```text
findings/<pkg>/promon/config/plain-config.*
findings/<pkg>/promon/config/policy.json
findings/<pkg>/promon/config/mappings.json
```

### Stage 6 — Binding removal or modeling

The DIMVA paper reports a static removal attack; public reversal notes that app code is bound to shield through native string and class/field initialization methods. A safe research workflow should first **model** bindings before trying to rewrite APKs.

Static modeling tasks:

- Resolve native string IDs to plaintext strings from Stage 2 or native string tables.
- Resolve native class/field initialization calls like `initializeClassByID(Class,int)` where possible.
- Produce a binding map from Java call sites to recovered constants/fields.
- Identify code that will fail if shield native methods are removed.

Optional rewrite tasks for owned/authorized samples:

- Replace string native calls with `const-string` / Java constants.
- Replace class/field initialization native calls with direct field assignments if mappings are recovered.
- Remove or stub `System.loadLibrary` only after all dependent native calls are eliminated or stubbed.
- Rebuild and sign a research APK, then compare behavior to original in a clean environment.

### Stage 7 — Dynamic validation, only when explicitly authorized

Promon is designed to detect instrumentation and environmental tampering. Do not lead with Frida hooks against the shield library.

Baseline-first plan:

1. Clean emulator/device image; no Frida server/gadget; no root artifacts if avoidable.
2. Install original APK and record:
   - logcat;
   - process lifetime;
   - `/proc/<pid>/maps` snapshots where permitted;
   - loaded libraries;
   - baseline network/process behavior.
3. Introduce the least-invasive observability:
   - loader/linker maps;
   - syscall tracing if allowed by environment;
   - JVMTI/JDWP only after baseline confirms it does not trigger immediate response.
4. If bypassing or dumping is authorized, prefer narrowly scoped hooks based on the static map:
   - config-decrypt output dump;
   - asset open/read for config files;
   - `openat` path redirection only for controlled repackaging experiments;
   - detection check return values only after policy is understood.

The public PoC hooks many libc/dynamic-linker functions and uses sample-specific offsets for an `openat` syscall stub. Treat it as a research map and validation aid, not a generic capability script.

## What remains valid before full unshielding

Even before native section/config recovery:

- Manifest attack surface: exported components, BROWSABLE filters, schemes/hosts, permissions.
- JADX semantic triage over preserved first-party code, with a caveat that strings may be missing until Stage 2.
- Java-level anti-analysis and environment checks.
- Native library supply-chain/fingerprint analysis: library name, hash, section layout, APKiD rule, Promon version clusters.
- Recovered strings from smali char-array patterns.

Scanner-gap label: findings in preserved Java code are not necessarily scanner gaps, but any logic hidden behind Promon native config/string/class binding should be marked `scanner_gap = adjacent` or `not found` depending on whether scanners saw the source/sink after string recovery.

## Unprotection-flow hypotheses

| Goal | Starting point | Difficulty | Notes |
| --- | --- | --- | --- |
| Detect Promon reliably | APKiD ELF rule: library name + `.ncu/.ncc/.ncd` section pairs | Low | Add this to `protector_detect.py`; scan native libs directly, not just ZIP names. |
| Recover Java strings | Smali char-array / XOR / `String.intern()` patterns and helper methods returning `[C` | Low-medium | Public tool exists; port into a non-rebuilding JSONL-emitting script. |
| Map shield bootstrap | Java xrefs to `System.loadLibrary` + native `.init_array` | Medium | Identify whether app loads random Promon library directly or via wrapper. |
| Recover section decrypt / unpack | `.init_array`, `.ncc/.ncd/.ncu`, mprotect/syscall/write loops | Medium-high | Likely version-dependent. Compare on-disk sections to memory only with authorization. |
| Recover policy/config | `config-encrypt.txt`, `mappings.bin`, `pbi.bin`, or modern ELF-embedded config | Medium-high | DIMVA dynamic config rewrite suggests a plaintext config exists after decrypt; first dump/model it. |
| Neutralize anti-analysis | ptrace/prctl/fork, JDWP patching, `/proc` scans, direct syscalls, Frida/Xposed/Substrate checks | High | Static mapping first; dynamic hooks may trigger response paths. |
| Static shield removal | recovered strings + mappings + native-call stubs | High | Reported by DIMVA, but requires mappings and careful bytecode rewrite. |

## Detector implementation notes

Implemented in `scripts/protector_detect.py`:

- ZIP-name scan for `lib/<abi>/libshield.so`.
- Random `lib[a-z]{10,12}.so` handling only when APKiD or Promon section evidence exists, to avoid false positives like React Native `libjscexecutor.so`.
- ELF section parser for `.ncu`, `.ncc`, `.ncd` pairs.
- APKiD JSON ingest if an inventory directory has `apkid.json`.
- Asset-name scan for historical config assets.
- Confidence model:
  - high: APKiD hit OR ELF section pair match.
  - medium: `libshield.so` OR random lib name plus suspicious section/entropy.
  - low: historical asset names only.

Suggested normalized output is in Stage 1 above.

## Implementation backlog

1. Run `scripts/research/promon/promon_recover.py` against the corpus anchor once the APK is available locally or restored from AndroZoo.
2. Compare at least two current Promon samples to classify section layouts and avoid hardcoding one vendor/customer version.
3. Improve `scripts/research/promon/promon_string_recover.py` with additional smali opcode patterns observed in real samples.
4. Add a Java/native binding-map script for native string/class initialization methods that are not recoverable by smali-only char-array evaluation.
5. Defer any `promon_unpack_sections` work until native layout comparison indicates a stable static path; this script is not implemented in the released capability.
6. If explicitly authorized for a target sample, create `scripts/research/promon/promon_dynamic_dump.md` / harness notes for clean-device config dumps and memory-map comparison.

## Open questions for the next research pass

1. Are `.ncc/.ncd/.ncu` encrypted on disk in our `in.org.npci.upiapp` sample, or are they nonstandard protected/runtime sections?
2. Does the sample ship older Promon assets (`config-encrypt.txt`, `mappings.bin`, `pbi.bin`) or a newer config layout?
3. Does JADX preserve the app's first-party code, and how much improves after smali string recovery?
4. Can we recover native string/class binding tables statically, or do they require config/native section unpack first?
5. What exact anti-Frida / anti-debug checks trigger under attach vs spawn on a clean test device?
6. Can a static ELF transform produce a normalized library with decrypted sections, or is the first practical native recovery output a memory-map dump?
