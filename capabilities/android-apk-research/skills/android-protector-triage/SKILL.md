---
name: android-protector-triage
description: "Use when an Android APK is packed by a commercial protector — detect with apkid + protector_detect, structurally unpack DexProtector (arm64) where supported, and triage what survives in JADX. Routes between detection, optional unpack, and protector-aware adjacency analysis."
allowed-tools:
  - detect_protector
  - dexprotector_unpack
  - bash
  - read
  - grep
  - glob
  - web_search
  - web_extract
  - report
license: MIT
---

# Android protector-aware triage

Grounding:
- OWASP MASVS-RESILIENCE (Resilience Against Reverse Engineering and Tampering): https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/
- MASTG-TECH-0019 Reverse Engineering — Android dynamic analysis pre-flight: https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/
- MASTG-TEST-0089 Testing Resiliency Against Reverse Engineering: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0089/

Trigger: the regular targeted-assessment / semantic-vuln-hunting flow runs into one or more of these symptoms:

- `apkid.json` flags a known commercial protector
- `lib/<abi>/libdpboot.so` + `libdexprotector.so`, or analogous protector libs, are present
- `assets/` contains opaque high-entropy `.dat` files (`se.dat`, `classes.dex.dat`, `mm.dat`, `dp.mp3`, …)
- JADX decompiles a `Protected<suffix>` Application class that immediately `System.loadLibrary` a small native blob
- `classes.dex` is conspicuously small relative to the app's apparent complexity

When any of these fire, **stop the regular workflow** and run this skill first. Continuing without protector-awareness produces false negatives (scanners see no exposed code) and false confidence (scanner baselines look clean because most code is encrypted).

**Scope as shipped:** DexProtector is the only protector with a structural unpack path. Promon Shield static recovery exists in `scripts/research/promon/promon_*` but is research-grade and not wired into this skill — see `references/promon-shield.md` for the standalone runbook. Other protectors (AppSealing, BoxedApp, AppGuard, Jiagu/360, …) are detected only as adjacency signals; triage them as black boxes per §3.

## 0. Identify the protector

```python
detect_protector(target="path/to.apk", out="findings/<pkg>/protector.json")
```

Read the returned dict (also written to `out`). Key fields:

- `protector` — `dexprotector` (structural unpack supported) or `promon_shield` (detection only; static recovery is research-grade, see `references/promon-shield.md`); other names fall through to adjacency analysis
- `confidence` (`high` / `medium` / `low`)
- `signals.native_libs`, `signals.protected_assets`, `signals.dplf` — concrete evidence
- `triage_strategy` (`protector_aware` vs `default`)
- `artifacts.dexprotector_unpack_supported` (true when arm64-v8a libdexprotector is present)
- `notes` — strategy hints

If the detector returns `protector: unknown` but the user has strong contextual evidence of a different protector, file the gap in `references/` and proceed with **only the regular targeted-assessment workflow**, treating the encrypted assets as black boxes.

## 1. Structural unpack — DexProtector

Only run this if `detect_protector` reported `protector: dexprotector` AND `artifacts.dexprotector_unpack_supported: true`.

```python
dexprotector_unpack(apk="path/to.apk", out="findings/<pkg>/libdp.so")
```

This emulates the bootstrap chain (libdexprotector.so → libdp.so) without an Android device. It does **not** execute libdp.so; everything is static + Unicorn. It does **not** trigger the master-key corruption that the Romain Thomas writeup describes (see `references/sources.md`), because libdp.so itself is never hooked.

The produced `libdp.so` is a synthetic AArch64 ET_DYN ELF; pass it directly to Ghidra / radare2 / Binary Ninja for the next step. Strings include the BoringSSL algorithm table, NDK AssetManager imports, and RASP plumbing — see `references/dexprotector.md`.

Limitations: arm64-v8a only today. For 32-bit-only ABI variants, port the offsets table at the top of `scripts/dexprotector_unpack.py` (the DPLF watermark is the anchor).

## 2. Protector-aware decompile

Decompile the APK **with the expectation that 60–95% of first-party code is missing**:

```bash
JAVA_OPTS="-Xmx2g" jadx --show-bad-code --no-debug-info \
  -d findings/<pkg>/sources path/to.apk
```

What survives in JADX output:

- `Protected<suffix>` bootstrap class and its small set of native entry points
- public manifest-declared components (intents/activities are still readable)
- third-party libraries the app vendored *before* protection (these are usually `<classEncryption>`-excluded; AppCloner-injected code has been observed surviving in protected samples)
- string-encryption call sites: `ProtectedFoo.s("\uXXXX")` shims

What does NOT survive:

- the bulk of first-party code (packed inside `assets/classes.dex.dat`)
- string literals (replaced by `s(...)` calls keyed on `assets/se.dat`)
- field/method references (replaced by an indirection table — the `ha.i(int, ...)` / `Lib<AppName>.i(int, ...)` pattern documented in the Romain Thomas DexProtector writeup; see `references/sources.md`)

ripgrep / Semgrep over JADX output is therefore **adjacency analysis only** — it can find the bootstrap, native entry points, manifest-anchored components, and the protector-injected call site patterns. It cannot find first-party logic bugs the way it would on an unprotected app.

## 3. What you can still report (without unpacking the DEX)

Even before recovering plaintext DEX, you can build evidence-backed findings on:

- **Cryptographic posture of the unprotected layer.** DexProtector's `<classEncryption>` filters routinely exclude vendored third-party crypto utility classes; weak primitives (DES/ECB, MD5, hardcoded keys, plain-HTTP base URLs) shipped in those excluded classes are visible in JADX output and worth flagging. The Romain Thomas writeup (see `references/sources.md`) documents one ~10M-installs sample (`com.flashget.parentalcontrol`) where this exact shape applied.
- **Manifest-level attack surface.** Exported components, BROWSABLE intent filters, schemes/hosts, dangerous permissions — DexProtector does not rewrite the manifest beyond injecting the bootstrap class.
- **Network config.** `network_security_config.xml`, `usesCleartextTraffic`, certificate pinning configuration — all outside the protector.
- **Protected-asset fingerprint.** Hashes of `assets/*.dat` files are stable across runs and give a per-version identifier; useful for diffing across versions or comparing apps to detect shared keystores.

## 4. Static asset RE — what to attempt next

The unpacked `libdp.so` is the entry point to all of these. They are not yet wired in this capability:

| Goal | Where in libdp.so | Difficulty |
| --- | --- | --- |
| Master-key derivation | functions that read the APK's v1/v2 signature block + iterate `classes.dex` + reference embedded config | high (post documents inputs but not the KDF) |
| `assets/classes.dex.dat` unpack | the EVP_aead_* call chain reachable from `AAssetManager_open` hooks; the trailer at the end of the file describes anti-dump unmap windows | medium-high |
| `assets/se.dat` string decrypt | string-decrypt native shim reachable from `s(String)` JNI entrypoint | medium (the post specifies the inputs: index + calling class hash code) |
| Generic asset decrypt | the vtable-hook entry point for `android::_FileAsset::*` | medium |

For each, plan the work in `references/dexprotector.md` and add a script under `scripts/`.

## 5. Dynamic validation — only if explicitly authorized

The post's key insight is that the DexProtector key derivation is bound to APK signature + unprotected DEX + libdp.so itself, AND that hooking libdp.so corrupts the master key. Consequences:

- **frida hooks against libdp.so are detected at start-up** and silently corrupt the asset-decryption path. Do not attempt dynamic instrumentation as a first-pass discovery technique.
- **frida-server's `rtld_db_dlactivity` trampoline is persistent**: a device that has *ever* run frida-server keeps the trampoline overlay on `rtld_db_dlactivity`. DexProtector incorporates the first 4 bytes of that function into its payload key. Consequence: on a frida-tainted device the unpacker hardcoded into libdexprotector.so will decrypt the payload incorrectly and the app will appear broken in ways that look unrelated to instrumentation. Use a clean device or our static unpacker.
- For validation, prefer environments where you have not previously installed frida; or use a fresh emulator image; or use the static unpacker output as ground truth.

## 6. Hand-off back to the standard workflow

Once you've labelled what's reachable statically and recovered any classes.dex.dat / asset content you can, hand back to `android-targeted-assessment` (or `android-semantic-vuln-hunting` for scaled-out work) with:

- `findings/<pkg>/protector.json`
- `findings/<pkg>/libdp.so` (and Ghidra / IDA project files)
- `findings/<pkg>/decrypted/<asset>` for every asset you've successfully decrypted
- a list of `<classEncryption>`-protected packages you've recovered DEX for

Then run the regular rg / Semgrep / Joern pipeline on the **union** of (JADX sources, decrypted DEX disassembly). Mark every hypothesis `scanner_gap = adjacent` or `not found` — by construction scanners had no access to the protected code, so they cannot have an `exact` finding inside it.

## Reference material

- `../../references/sources.md` — capability-root citation registry (Romain Thomas DexProtector writeup, APKiD rules, Promon community RE, 34C3 talk, DIMVA 2018 paper).
- `references/dexprotector.md` — IoCs, file glossary, RE notes against the LiveNet sample, recovered key, payload format.
- `references/promon-shield.md` — research-grade Promon Shield recovery runbook (not wired into this skill workflow).
- `references/appsealing-doverunner.md`, `references/jiagu-360.md` — adjacency notes for other commercial protectors; detection only, no in-tree recovery.
