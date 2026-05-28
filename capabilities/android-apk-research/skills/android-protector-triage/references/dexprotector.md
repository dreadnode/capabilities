# DexProtector triage reference

Source: Romain Thomas, *A Glimpse Into DexProtector*, 2026-01-04.
<https://www.romainthomas.fr/post/26-01-dexprotector/>

Grounding: this work sits under OWASP MASVS-RESILIENCE (<https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/>); see also MASTG-TEST-0089 *Testing Resiliency Against Reverse Engineering* (<https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0089/>) — DexProtector is a vendor implementation of the RASP / packing controls MASVS-RESILIENCE describes.

This page is the IoC + RE notes the in-tree DexProtector detector + unpacker (`scripts/protector_detect.py`, `scripts/dexprotector_unpack.py`) are built from. It is **not** a copy of the blog post — it captures the facts we needed to make the workflow reproducible inside the capability, including offsets and routines we verified by re-doing the RE in Ghidra against LiveNet `com.playnet.androidtv.ads-5.0.1` (`sha256:810634a3…`) and the envchecks sample (`com.dexprotector.detector.envchecks-2.1`).

## Identification (Tier 1)

Any of these is enough on its own; combinations raise confidence.

| Surface | Signal |
| --- | --- |
| `AndroidManifest.xml` | `<application android:name="Protected<suffix>">` — DexProtector injects a bootstrap subclass of the original `Application`. |
| `lib/<abi>/` | `libdpboot.so` AND `libdexprotector.so` (or `libdexprotector_h.so`) shipped per ABI. |
| `libdexprotector.so` body | `DPLF` (`44 50 4c 46`) magic. In modern builds this is the *first 4 bytes* of the encrypted payload inside the last `PT_LOAD` (file offset `0x3ac0` in the LiveNet arm64 build). Older builds may place the payload at the end of the file outside a segment. |
| `assets/` | Any of: `se.dat`, `classes.dex.dat`, `mm.dat`, `dp.mp3`, `resources.dat`, `ic.dat`, `ct.dat`, `rcdb.dat`, `ict.dat`, `dp.arm-v7.so.dat`. |

## Asset file glossary

| File | Role |
| --- | --- |
| `assets/classes.dex.dat` | Encrypted + compressed concatenation of all protected `classes<N>.dex` files plus a footer header describing offsets and the **anti-dump unmap windows** (regions to `munmap` after the DEX is mapped into memory). |
| `assets/se.dat` | String-encryption lookup table. Maps a 16-bit index (passed to the native `ProtectedFoo.s(String)` shim as a `\uXXXX` literal) into a file offset + length pair that the native decryptor consumes. The crypto is keyed by the index AND the calling class's hash code. |
| `assets/resources.dat` | Encrypted resources covered by `<resourceEncryption><res>` filters. Decoded on the fly via vtable hooks on `android::_FileAsset::*` inside `libandroidfw.so` and on `StringBlock.nativeGetString` / `AssetManager.nativeGetResourceIdentifier`. |
| `assets/mm.dat`, `assets/dp.mp3`, `assets/ic.dat`, `assets/ct.dat`, `assets/rcdb.dat` | Other DexProtector-managed blobs (config, runtime checks, integrity tables). The post does not enumerate the exact role of each; their presence is itself a high-confidence IoC. |
| `assets/dp.arm-*.so.dat` | Per-ABI stub used by `libdpboot.so` to locate the unpacker binary. |
| `assets/<noise>.dat` (e.g. `zpoasosdi.dat`, `regtbeonuev.dat`, `btylusqrepu.dat` in LiveNet) | Per-app encrypted assets covered by `<resourceEncryption>`. In LiveNet these are serialized BouncyCastle keystores used to authenticate to the IPTV backend. |

## Bootstrap chain (verified)

```
Protected<suffix>.attachBaseContext()              [Java]
  -> integrity check (JNI native)
  -> System.loadLibrary("dpboot")                  [-> libdpboot.so JNI_OnLoad]
  -> JNI native -> System.loadLibrary("dexprotector")
                                                   [-> libdexprotector.so _INIT_0 + JNI_OnLoad]
       -> custom ELF loader: decrypt + map payload (= libdp.so) into a fresh mmap region
       -> jump into libdp.so's DT_FINI_ARRAY entry
```

## libdexprotector.so internals — arm64 (LiveNet 5.0.1)

All offsets are file offsets into the arm64 `libdexprotector.so` (Ghidra base 0x100000 → subtract for file).

| Routine | Address | Notes |
| --- | --- | --- |
| `_INIT_0` | `0x29d4` | walks program headers, locates the PT_LOAD that starts with `DPLF`, calls the driver |
| `_resolve_dlactivity` (was `FUN_001021ac`) | `0x21ac` | opens `/proc/self/exe`, reads its ELF, walks section/program headers for the dynamic table, parses `DT_DEBUG` (tag 0x15) → caches `r_debug*` at `.data+0x698` |
| `_dlactivity_getter` (was `FUN_001021a0`) | `0x21a0` | thin getter returning that cached `r_debug*` |
| `_KDF` (was `FUN_00100790`) | `0x00790` | obfuscated stack-machine VM over a 16 KB bytecode at file offset `0x8122`. Writes 32 bytes into the buffer passed in `x0`. At one specific state, calls the getter and **XORs bytes 0/4/8/12 of the key with 4 bytes read from `rtld_db_dlactivity`** (with a `+4` skip if a BTI landing pad is detected — pattern `5F 24 03 D5`). This is the frida-server-persistence detector documented in the Romain Thomas writeup (see `../../../references/sources.md`). |
| `_cipher` (was `FUN_00100c2c`) | `0x00c2c` | 32-round Feistel keystream cipher. State: u32 counter at +0xc, u64 key-mixing accumulator at +8, 8 round constants (the 32-byte key) at +0x18, 16-byte keystream block at +0x10. Output is XORed byte-by-byte against the ciphertext. |
| `_cipher_static` (was `FUN_001028d0`) | `0x028d0` | same round function as `_cipher`, but operates on `(key,ct)` blobs embedded in `.rodata` for short static strings (`/proc/self/exe`, the `r_debug` lookup, etc.). Useful for decoding the small in-binary constants without emulation. |
| `_lz4` (was `FUN_00101b58`) | `0x01b58` | LZ4 block decompression. Standard token>>4 literal length, `0xff` extension byte counting, 2-byte LE match offset, 4-byte minmatch — drop-in compatible with `lz4.block.decompress`. |
| `_unpack` (was `FUN_0010114c`) | `0x0114c` | top-level: KDF -> cipher init -> decrypt 0x24-byte super-header -> per segment (≤4) decrypt 0x18-byte descriptor table -> decrypt + LZ4-decompress segment bytes into a mmap'd image, validating each segment's 16-bit rolling hash |
| `_relocate` (was `FUN_001018e8` + `FUN_0010171c`) | `0x018e8`, `0x0171c` | apply ELF-style relocations on the custom dynamic table, then zero the dynamic table to defeat post-load memory dumps. Recognised tags map roughly to `DT_*`: 2=`STRSZ`, 5/6/7/8/10=`STRTAB`/`SYMTAB`/`RELA`/`RELASZ`/`RELAENT`-ish, 0x17/0x23/0x24/0x25=Android packed-RELA, INIT_ARRAY, INIT_ARRAYSZ, etc. |

## Payload format

```
[+0x00] 'D' 'P' 'L' 'F'                         u32 magic
[+0x04] watermark32 (rendered as 5 ASCII hex bytes into .data+0x690)
[+0x08] 0x24 bytes of ciphertext = encrypted super-header
        struct {
            u32 page_size;        // local_a0
            u32 vaddr_min_neg;    // local_9c (used as -delta)
            u32 vaddr_high;       // local_90
            u32 second_range_off; // uStack_8c
            u32 second_range_sz;  // local_88
            u32 nseg;             // local_80  (1..4)
            // 3 more u32 of housekeeping
        };
[+0x2c] for i in 0..nseg-1:
            0x18 bytes of ciphertext = encrypted segment descriptor
            struct {
                u32 vaddr;     // local_78
                u32 vsize_pad; // uStack_74
                u32 csize;     // local_64
                u32 plain_len; // local_70  (LZ4 decompressed length)
                u32 flags;     // local_6c  (PT_LOAD flags, low 3 bits)
                u32 hash16;    // local_68  (rolling 16-bit hash, validated)
            };
            csize bytes of ciphertext, LZ4-decompressed into mmap+vaddr
```

After all segments are mapped, `libdexprotector.so` applies relocations on the in-memory image then zeroes the dynamic/relocation regions described by `DT_ANDROID_RELA` etc. before transferring control to the unpacked `libdp.so`'s `DT_FINI_ARRAY[0]`.

## Recovered key (LiveNet arm64)

```
b0 b1 4a 07  c4 dc 4a dd  ed 85 8d 03  0a 6b b1 61
e1 54 ae f2  4c a8 2d 24  b6 a6 d5 91  61 2e 4f 31
```

Bytes 0/4/8/12 are XORed with `c0 03 5f d6` (= `ret`). Any frida-server trampoline overlaying `rtld_db_dlactivity` at start-up corrupts these 4 positions and the cipher diverges immediately, which is the persistence quirk called out in the Romain Thomas writeup (see `../../../references/sources.md`).

## What libdp.so contains

Confirmed from the unpacked image (Tier-2 output of `scripts/dexprotector_unpack.py`):

- **BoringSSL** statically linked: full algorithm string table — AES-{128,192,256}-{ECB,CBC,CTR,GCM,KW,KWP}, ChaCha20, ChaCha20-Poly1305, RSASSA-PSS, RSA-OAEP, SHA-{1,224,256,384,512}, SHA-3 family, all standard EC curves including `brainpoolP{256,512}r1`, `secp256k1`.
- **NDK Asset Manager** function imports — `AAssetManager_fromJava`, `AAssetManager_open`, `AAssetManager_openDir`, `AAssetDir_getNextFileName`, `AAsset_close`, `AAsset_getBuffer`, `AAsset_getLength` — used by the vtable-hook path in `libandroidfw.so`.
- **Linker / property / RASP plumbing** — `__system_property_get`, `pthread_atfork`, `getauxval`, `sigaction`, `fts_open`, `arc4random_buf`.

This is consistent with the post's "RASP detections, the engine to load encrypted classes, the logic to load protected assets" characterization.

## Tier-2 unpacker contract

`scripts/dexprotector_unpack.py` accepts an APK or a bare arm64 `libdexprotector.so` and writes a synthetic ET_DYN AArch64 ELF wrapping the recovered segments. The output is byte-identical across runs on the same input (validated against LiveNet 5.0.1 and the envchecks 2.1 sample).

What it currently solves:

- ✅ arm64-v8a libdexprotector → libdp.so end-to-end without an Android device
- ✅ no instrumentation of libdp.so itself; the master-key corruption mechanism never triggers

Not yet:

- ⌛ armeabi-v7a / x86 / x86_64 — same payload layout, different function addresses (a small port)
- ⌛ libdp.so master-key derivation (needs follow-on RE on the unpacked libdp.so)
- ⌛ per-asset subkey derivation + decryption (`se.dat`, `classes.dex.dat`, custom `*.dat`)
- ⌛ classes.dex.dat anti-dump unmap-window reconstruction

These are the next pieces of the post that the capability should reproduce. The unpacked `libdp.so` produced today is the input to all of them.

## Workflow integration

| Task | Use |
| --- | --- |
| Is this APK protected? | `scripts/protector_detect.py <apk>` → `protector.json` |
| I want libdp.so | `scripts/dexprotector_unpack.py <apk_or_libdexprotector.so> -o libdp.so` |
| I want to RE the asset crypto | Import the recovered `libdp.so` into Ghidra; start from `AAssetManager_open` xrefs (the vtable hooks) and the BoringSSL `EVP_aead_*` symbols. |

## Known applications shipping DexProtector

Verified via APKiD + manifest signals; sample list compiled from the Romain Thomas writeup (see `../../../references/sources.md`).

| App | Version |
| --- | --- |
| `com.revolut.revolut` | 10.109.1 |
| `istark.vpn.starkreloaded` | 7.1-rc |
| `com.dexprotector.detector.envchecks` | 2.1 |
| `ar.tvplayer.tv` | 5.2.0 |
| `org.unhcr.zakat` | 2.1.54 |
| `com.Hyatt.hyt` | 6.16.0 |
| `com.kms.free` (Kaspersky) | 11.129.4.14969 |
| `com.flashget.parentalcontrol` | 1.3.6.0 |
| `com.belongtail.ai` | 2.8.4 |
| `com.kidoprotect.app` | 11.1 |
| `com.playnet.androidtv.ads` (LiveNet) | 5.0.1 |
