# 360 Jiagu / Qihoo 360 triage reference

Status: early triage scaffold. This is the starting point for reproducing prior Jiagu unpacking research and turning it into capability-native detection / unprotection flows.

Primary sources to read first:

- 360 Jiagu official site: <https://jiagu.360.com/>
- APKiD APK rules for Jiagu / Qihoo 360: <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/apk/packers.yara>
- APKiD ELF rules for Jiagu native: <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/elf/packers.yara>
- 2025 packer prevalence paper, *To Unpack or Not to Unpack: Living with Packers to Enable Dynamic Analysis of Android Apps*: <https://arxiv.org/html/2509.16340v1>
- Public unpacker baseline: <https://github.com/SafaSafari/jiagu_unpacker>
- Older public RE artifacts: <https://github.com/maiyao1988/360reverse>

## Identification (Tier 1)

Jiagu is a classic **APK packer / reinforcement** target. Expect an exposed stub DEX and a native loader that recovers the real application code at runtime.

| Surface | Signal | Source / confidence |
| --- | --- | --- |
| `apkid.json` | `packer: Jiagu` | High when APKiD hits. |
| `lib/<abi>/` or `assets/` | `libjiagu.so`, `libjiagu_art.so` | High; APKiD APK rule. |
| `assets/` | `libjiagu_a64.so`, `libjiagu_x64.so`, `libjiagu_x86.so` | High in our corpus sample; native libs are shipped as assets instead of normal `lib/<abi>/`. |
| `lib/<abi>/` | `libprotectClass.so` | Qihoo 360 rule in APKiD; treat as Jiagu-family / Qihoo reinforcement. |
| Native strings | `JIAGU_APP_NAME`, `JIAGU_SO_BASE_NAME`, `JIAGU_ENCRYPTED_DEX_NAME`, `JIAGU_HASH_FILE_NAME` | High if found in ELF; APKiD `jiagu_native` rule. |
| Native behavior | direct syscalls / anti-hook patterns | Medium by itself; raises confidence when co-located with Jiagu libs. |

### Current corpus anchor

Observed in this repo's AndroZoo-84 inventory:

| Package | APK | Artifact | Evidence |
| --- | --- | --- | --- |
| `com.kbzbank.kpaycustomer` | `corpus/androzoo/apks-84/com.kbzbank.kpaycustomer_novc_A9209A1A7D8B.apk` | `findings/androzoo-84/inventory/apks/a9209a1a7d8bfdb3e60d00fbcb01b3d32bf1c0cac787ed8b04dd38c933d5691c/` | APKiD flags APK and `assets/libjiagu*.so` as `Jiagu`; `assets/libjiagu_a64.so` also has `anti_hook: syscalls`. |

APKiD also flags `classes.dex` as `dexlib 2.x` and `BlackObfuscator`. Treat this as a stub / app-adjacent obfuscation signal until decompiled.

## Expected protection shape

Working hypothesis from APKiD rules, public unpackers, and prior writeups:

```
classes.dex stub
  -> loads / extracts Jiagu native library from assets or lib/<abi>/
  -> native loader validates environment and APK integrity
  -> native loader locates encrypted DEX / app payload
  -> decrypts and maps the real DEX at runtime
  -> transfers control to original Application / entrypoint
```

The 2025 prevalence paper maps APKiD's `Jiagu` label to 360 and notes regional packer naming / alias issues. It also found packing is far more common in Chinese app-market datasets than non-Chinese APKPure-style datasets. For our capability, normalize `Jiagu`, `Qihoo 360`, and `360 reinforcement` under one triage family unless evidence indicates a distinct implementation.

## Initial static triage workflow

For a candidate APK:

```bash
python3 scripts/protector_detect.py path/to.apk -o findings/<pkg>/protector.json
apkid path/to.apk -j > findings/<pkg>/apkid.json
unzip -l path/to.apk > findings/<pkg>/ziplisting.txt
```

Extract all Jiagu-like native blobs, including assets:

```bash
mkdir -p findings/<pkg>/jiagu/libs
python3 - path/to.apk findings/<pkg>/jiagu/libs <<'PY'
import zipfile, pathlib, re, sys
apk = sys.argv[1]
out = pathlib.Path(sys.argv[2])
pat = re.compile(r'(^|/)(libjiagu.*\.so|libprotectClass\.so|libjgbibc.*\.so)$', re.I)
with zipfile.ZipFile(apk) as z:
    for n in z.namelist():
        if pat.search(n):
            dest = out / n.replace('/', '__')
            dest.write_bytes(z.read(n))
            print(n, '->', dest)
PY
```

Minimum evidence to capture:

- Whether Jiagu libraries live under `assets/` or `lib/<abi>/`.
- Exact library names, ABI mapping, SHA-256, section table, and entropy.
- Exposed `classes.dex` size and decompiled stub classes.
- All `System.loadLibrary`, `Runtime.load`, `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader`, and reflection call sites in the stub.
- Any encrypted payload candidates in `assets/`, `res/raw/`, or nonstandard ZIP entries.

## Unprotection-flow hypotheses

| Goal | Starting point | Difficulty | Notes |
| --- | --- | --- | --- |
| Detect Jiagu reliably | APK / asset names plus native strings | Low | Add `assets/libjiagu*.so` support; APKiD already caught this layout. |
| Locate stub entrypoint | JADX decompile of exposed `classes.dex` | Low-medium | Find Application subclass / attachBaseContext / loadLibrary path. |
| Locate encrypted DEX payload | Native strings `JIAGU_ENCRYPTED_DEX_NAME`, asset xrefs, ZIP entry names, file reads | Medium | Do not assume normal `classes*.dex` are real app code. |
| Recover runtime DEX | Dynamic memory dump or native decrypt routine emulation | Medium-high | Public unpackers may help identify expected memory layout / DEX repair steps. |
| Repair dumped DEX | Header/map/string/type/method table repair after memory extraction | Medium | Compare with public `jiagu_unpacker` and `360reverse` notes. |
| Static native decrypt port | Native function tracing from libjiagu init / decrypt routines | High | Target if dynamic dump is unreliable or blocked by anti-debug. |

## Dynamic validation cautions

Only do this with explicit authorization for the target sample.

- Expect anti-debug and anti-hook logic; our corpus sample has APKiD `anti_hook: syscalls` on `assets/libjiagu_a64.so`.
- Start with baseline launch on a clean emulator/device and collect logcat / process maps.
- If using Frida, test attach and spawn separately. Record whether the app exits, crashes, or silently corrupts output.
- Prefer a minimal DEX-dump observation before modifying control flow. Hooking the wrong native routine may change unpacker behavior.

## Detector implementation notes

Add a Jiagu branch to `scripts/protector_detect.py` with:

- ZIP-name scan for:
  - `lib/<abi>/libjiagu.so`
  - `lib/<abi>/libjiagu_art.so`
  - `lib/<abi>/libprotectClass.so`
  - `assets/libjiagu*.so`
  - `assets/libjgbibc*.so`
- ELF string scan for:
  - `JIAGU_APP_NAME`
  - `JIAGU_SO_BASE_NAME`
  - `JIAGU_ENCRYPTED_DEX_NAME`
  - `JIAGU_HASH_FILE_NAME`
  - `libjiagu`
- Confidence model:
  - high: APKiD hit OR `libjiagu*` native blob found.
  - medium: Qihoo `libprotectClass.so` or native string cluster.
  - low: exposed stub-only indicators without native proof.

Suggested normalized output:

```json
{
  "protector": "jiagu_360",
  "triage_strategy": "protector_aware_dex_unpack",
  "signals": {
    "native_libs": {"assets": ["libjiagu.so", "libjiagu_a64.so"]},
    "anti_hook": ["syscalls"]
  }
}
```

## Open questions for the first research pass

1. Where does `com.kbzbank.kpaycustomer` store the encrypted real DEX: inside a Jiagu asset library, another asset, appended data, or a ZIP entry?
2. Does `assets/libjiagu_a64.so` contain the native string constants from APKiD's `jiagu_native` rule?
3. Does a public Jiagu unpacker work on this sample as-is? If not, what assumption breaks?
4. What DEX repair steps are needed after memory extraction on current Android runtime versions?
5. Is a static emulator/unicorn-style path practical for the decrypt routine, or is the first useful capability a controlled dynamic dump + repair pipeline?
