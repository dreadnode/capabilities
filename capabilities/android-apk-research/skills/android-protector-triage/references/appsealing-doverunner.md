# AppSealing / DoveRunner triage reference

Status: early triage scaffold. This is the starting point for adding AppSealing detection and later building an unprotection flow when we source a representative sample.

Primary sources to read first:

- DoveRunner / AppSealing Android app security page: <https://doverunner.com/mobile-app-security/android-application-security/>
- AppSealing Android obfuscation page, currently redirecting in some environments: <https://www.appsealing.com/android-app-obfuscation/>
- APKiD APK rules for AppSealing: <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/apk/packers.yara>
- APKiD ELF rules for AppSealing core version strings: <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/elf/packers.yara>

## Identification (Tier 1)

AppSealing / DoveRunner is a commercial **app wrapping / sealing / RASP** target. Vendor material describes a post-build flow: upload application, apply security features, download sealed app, publish. Expect added native libraries, sealed DEX/assets, and runtime checks.

| Surface | Signal | Source / confidence |
| --- | --- | --- |
| `apkid.json` | `packer: AppSealing` | High when APKiD hits. |
| `lib/<abi>/` | `libcovault.so` | High; APKiD APK rule. |
| `lib/<abi>/` | `libcovault-appsec.so` | High; APKiD APK rule. |
| `assets/` | `assets/appsealing.dex` | High; APKiD APK rule. |
| `assets/` | `assets/sealed1.dex` | High; APKiD APK rule. |
| `assets/` | `assets/AppSealing/*` with multiple entries | High; APKiD alternate rule. |
| ELF strings | `APPSEALING-CORE-VERSION_2.10.10` or similar | Medium-high; APKiD ELF rule for a known version. |

### Current corpus status

No AppSealing hit was observed in the current local APKiD corpus slice during early ranking. That means this file is detection/research prep first; we still need a representative sample before reproducing an unprotection flow.

Useful sample acquisition criteria:

- APKiD hit for `AppSealing`.
- At least one `arm64-v8a` protected native library.
- Presence of `assets/appsealing.dex` and `assets/sealed1.dex`, or an `assets/AppSealing/` directory.
- Prefer a benign/free app or test/demo artifact that can be redistributed internally as a fixture.

## Expected protection shape

Working hypothesis from APKiD rules and vendor material:

```
Original APK
  -> AppSealing post-build wrapper adds native covault/appsec libraries
  -> wrapper adds appsealing.dex / sealed*.dex / AppSealing asset bundle
  -> launch path initializes AppSealing runtime
  -> runtime performs code protection, integrity checks, anti-debug, root/emulator, memory access, network sniffing, and cheat-tool checks
  -> sealed code/assets are loaded or mediated by the wrapper
```

Vendor page claims code protection via obfuscation and encryption, binary/resource integrity protection, anti-debugging, memory access detection, emulator blocking, rooting detection, and network packet sniffing detection.

Key expectation for triage: AppSealing may sit between DexProtector-style DEX packing and Promon-style native RASP. Do not assume all first-party DEX is encrypted until the sample proves it. The `sealed1.dex` / `appsealing.dex` split should be mapped first.

## Initial static triage workflow

For a candidate APK:

```bash
python3 scripts/protector_detect.py path/to.apk -o findings/<pkg>/protector.json
apkid path/to.apk -j > findings/<pkg>/apkid.json
unzip -l path/to.apk > findings/<pkg>/ziplisting.txt
```

Extract AppSealing artifacts:

```bash
mkdir -p findings/<pkg>/appsealing
unzip -p path/to.apk assets/appsealing.dex > findings/<pkg>/appsealing/appsealing.dex 2>/dev/null || true
unzip -p path/to.apk assets/sealed1.dex > findings/<pkg>/appsealing/sealed1.dex 2>/dev/null || true
unzip -p path/to.apk lib/arm64-v8a/libcovault.so > findings/<pkg>/appsealing/libcovault-arm64.so 2>/dev/null || true
unzip -p path/to.apk lib/arm64-v8a/libcovault-appsec.so > findings/<pkg>/appsealing/libcovault-appsec-arm64.so 2>/dev/null || true
```

Minimum evidence to capture:

- Which APKiD AppSealing rule fired (`appsealing`, `appsealing_a`, or ELF core version).
- Exact native library names and ABI coverage.
- Whether `assets/appsealing.dex`, `assets/sealed1.dex`, or `assets/AppSealing/*` are present.
- Sizes/entropy of sealed DEX and AppSealing assets.
- Whether `sealed1.dex` begins with `dex\n` or is encrypted/encoded.
- Manifest/Application changes and Java stub entrypoints.
- Native load sites and classloader usage.

## Unprotection-flow hypotheses

| Goal | Starting point | Difficulty | Notes |
| --- | --- | --- | --- |
| Detect AppSealing reliably | APKiD APK rules: covault libs + appsealing/sealed DEX assets | Low | Add direct ZIP-name support to `protector_detect.py`. |
| Map wrapper bootstrap | Manifest Application + `appsealing.dex` decompile | Medium | Determine how control transfers to original app. |
| Classify `sealed1.dex` | Header/entropy/checksum and JADX/dexdump behavior | Low-medium | It may be a real DEX, encrypted DEX, or wrapper metadata depending on version. |
| Recover original app code | AppSealing loader xrefs to sealed assets / classloader / native decrypt | Medium-high | Need sample-specific RE; compare with DexProtector asset-load methodology. |
| Recover policy/config | `assets/AppSealing/*`, native strings, appsealing.dex constants | Medium | Build an asset glossary once a sample is available. |
| Neutralize runtime checks | Native covault/appsec checks and Java stubs | Medium-high | RASP checks may be independent from DEX recovery. |

## Dynamic validation cautions

Only do this with explicit authorization for the target sample.

- Expect anti-debugging, emulator, root, memory access, and packet-sniffing checks; these are vendor-advertised features.
- Establish a clean baseline launch before adding instrumentation.
- Test whether repackaging to add debug flags invalidates integrity checks.
- If dynamic DEX dumping is attempted, first determine whether sealed code is loaded through standard classloaders or native runtime mapping.

## Detector implementation notes

Add an AppSealing branch to `scripts/protector_detect.py` with:

- ZIP-name scan for:
  - `lib/<abi>/libcovault.so`
  - `lib/<abi>/libcovault-appsec.so`
  - `assets/appsealing.dex`
  - `assets/sealed1.dex`
  - `assets/AppSealing/*`
- ELF string scan for:
  - `APPSEALING-CORE-VERSION_`
- Confidence model:
  - high: covault libs plus appsealing/sealed DEX, or APKiD hit.
  - medium: `assets/AppSealing/` with several entries, or ELF core version string.
  - low: only marketing-ish names without covault/sealed artifacts.

Suggested normalized output:

```json
{
  "protector": "appsealing_doverunner",
  "triage_strategy": "protector_aware_app_wrapping",
  "signals": {
    "native_libs": {"arm64-v8a": ["libcovault.so", "libcovault-appsec.so"]},
    "protected_assets": ["assets/appsealing.dex", "assets/sealed1.dex"]
  }
}
```

## Open questions for the first research pass

1. Can we source a current benign AppSealing-protected APK with `arm64-v8a` support?
2. Does `sealed1.dex` contain a valid DEX header in current builds, or is it encrypted until runtime?
3. Is the original application class named in manifest metadata, an AppSealing config asset, or a native table?
4. Which runtime checks are Java-level vs native-level?
5. Is a static asset decryptor plausible, or is the first useful flow a dynamic loader trace + DEX dump/repair pipeline?
