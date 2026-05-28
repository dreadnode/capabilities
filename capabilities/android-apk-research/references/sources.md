# Sources

Citation registry for the `android-apk-research` capability. Every external claim in the skills and per-skill references should be traceable from here. Inline links in the references point to canonical sources; this file is the consolidated index a future agent can read to ground every methodology decision.

When extending the references with a new pattern, citation, or empirical observation, add the source here.

---

## Industry standards & frameworks

The capability grounds its methodology in OWASP's mobile security work and Android's first-party security guidance.

- **OWASP MASVS** — Mobile Application Security Verification Standard, current revision v2.1.0 (2024-01). <https://mas.owasp.org/MASVS/>
- **OWASP MASTG** — Mobile Application Security Testing Guide, current revision v1.7.0 (2024-10). <https://mas.owasp.org/MASTG/>
  - MASTG-TECH-0025 — Static analysis caveats (scanners are noisy, require review). <https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0025/>
  - MASTG-TECH-0019 — Dynamic analysis pre-flight. <https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0019/>
  - MASTG-TEST-0028 — Deep link testing. <https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/>
  - MASTG-TEST-0089 — Testing Resiliency Against Reverse Engineering. <https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0089/>
- **OWASP MASWE** — Mobile Application Security Weakness Enumeration (beta). The capability uses MASWE-0058 (Insecure Deep Links), MASWE-0064 (Insecure Content Providers), MASWE-0066 (Insecure Intents), MASWE-0068 (JavaScript Bridges in WebViews) as the four PLATFORM anchors. Where no current MASWE cleanly maps a bug class, the normalizer omits the field rather than asserting an unrelated ID. <https://mas.owasp.org/MASWE/>
- **CWE** — MITRE Common Weakness Enumeration. <https://cwe.mitre.org/>
- **Android developer — risks/guidance** (Google):
  - Deep link risks: <https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks>
  - Intent redirection risk: <https://developer.android.com/privacy-and-security/risks/intent-redirection>
  - Unsafe URI loading into WebView: <https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading>
  - WebView native bridges: <https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges>
  - Untrustworthy ContentProvider-provided filename: <https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename>
- **CodeQL Android query help** — Java/Kotlin Android queries: <https://codeql.github.com/codeql-query-help/java/>
  - Intent redirection: <https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/>
  - Unsafe WebView fetch: <https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/>

---

## Public security research drawn on by this capability

Named CVEs, advisories, and writeups whose shape the skills reproduce as detection patterns. When a pattern in `references/bug-classes.md`, `references/leaked-host-triage.md`, or `references/historical-patterns-2023-2026.md` cites one of these, the URL here is the canonical source.

### Deep links / intent redirection / WebView

- **Home Assistant Android arbitrary WebView URL** — GHSL-2023-142 / CVE-2023-41898. <https://securitylab.github.com/advisories/GHSL-2023-142_Home_Assistant_Companion_for_Android/>
- **Rakuten Ichiba custom URL scheme** — JVN56648919 / CVE-2024-41918. <https://jvn.jp/en/jp/JVN56648919/>
- **Element Android intent redirection** — Shielder, *Never Take Intents from Strangers*; CVE-2024-26131, CVE-2024-26132. <https://www.shielder.com/blog/2024/04/element-android-cve-2024-26131-cve-2024-26132-never-take-intents-from-strangers/>
- **Oversecured — Android deep-link account takeover patterns.** <https://oversecured.com/blog/android-deep-link-vulnerabilities>

### Content providers / file/share targets

- **Microsoft Dirty Stream** — *Dirty Stream Attack: discovering and mitigating a common vulnerability pattern in Android apps*, 2024-05-01. <https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/>
- **ownCloud Android — provider SQLi / path validation** — GHSL-2022-059, GHSL-2022-060; CVE-2023-24804, CVE-2023-23948. <https://securitylab.github.com/advisories/GHSL-2022-059_GHSL-2022-060_Owncloud_Android_app/>

### Commercial protector reverse engineering

- **Romain Thomas — *A Glimpse Into DexProtector***, 2026-01-04. <https://www.romainthomas.fr/post/26-01-dexprotector/> — the source for the in-tree DexProtector detector and `scripts/dexprotector_unpack.py` AArch64 layout. Companion artifact pairs: <https://github.com/romainthomas/dexprotector>
- **APKiD ELF rules for Promon Shield** — <https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/rules/elf/packers.yara>
- **APKiD issue #72** — Promon use in German banking apps, refers to 34C3 talk. <https://github.com/rednaga/APKiD/issues/72>
- **34C3 — *Die fabelhafte Welt des Mobilebankings***, Vincent Haupert. <https://media.ccc.de/v/34c3-8805-die_fabelhafte_welt_des_mobilebankings>
- **DIMVA 2018 — *Honey, I Shrunk Your App Security: The State of Android App Hardening***. <https://obfuscator.re/nomorp-paper-dimva2018.pdf> · <https://link.springer.com/chapter/10.1007/978-3-319-93411-2_4>
- **KiFilterFiberContext — promon-reversal** (community RE notes). <https://github.com/KiFilterFiberContext/promon-reversal>
- **RevealedSoulEven — promon-string-deobfuscator.** <https://github.com/RevealedSoulEven/promon-string-deobfuscator>

---

## Tool documentation

Capabilities the skills assume the operator can run. Install/usage is each tool's own responsibility; the skills wrap orchestration.

- **JADX** — DEX-to-Java decompiler. <https://github.com/skylot/jadx>
- **Androguard** — APK parsing / manifest decoding. <https://androguard.readthedocs.io/en/latest/intro/gettingstarted.html>
- **APKiD** — packer / protector / obfuscator detection. <https://github.com/rednaga/APKiD>
- **Semgrep** rule packs used as scanner baseline: `p/security-audit`, `p/mobsfscan`, `r/java`. <https://semgrep.dev/>
- **MobSF** / `mobsfscan` — Mobile Security Framework, scanner alternative. <https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- **APKHunt** — OWASP-aligned static scanner. <https://github.com/Cyber-Buddy/APKHunt>
- **Joern** — Code Property Graph for call/data context. Docs: <https://docs.joern.io/code-property-graph/> · <https://docs.joern.io/quickstart/>
- **CodeQL** — path-precise queries. Android query packs cited above.
- **FlowDroid** — lifecycle-aware taint. <https://blogs.uni-paderborn.de/sse/tools/flowdroid/> · <https://github.com/secure-software-engineering/FlowDroid>
- **hbctool** — Hermes bytecode disassembler for React Native bundles. <https://github.com/bongtrop/hbctool>
- **blutter** — Flutter / Dart AOT reverse engineering. <https://github.com/worawit/blutter>
- **gplaydl** — anonymous Google Play APK downloader. <https://pypi.org/project/gplaydl/>
- **Aurora Store** — public token dispenser used by `gplaydl` for anonymous Play auth. <https://auroraoss.com/>
- **AndroZoo** — academic APK corpus. <https://androzoo.uni.lu/>

---

## Internal research provenance

Some empirical observations in the references derive from **internal corpus research conducted on publicly available APK samples** downloaded from AndroZoo / Google Play and analyzed statically with the same scripts and tools this capability ships. The patterns documented from that work — Dagger compile-time environment pinning, bootstrap-initializer environment override, R8 + Kotlin Metadata dead-string retention, server-flippable feature-flag CDN swap, deep-link to account-state-change without WebView, MethodChannel routing in Flutter, Hermes bytecode bundle adoption in wallet RN apps — are presented as **pattern shapes** an agent can detect and reproduce, not as advisories about specific applications.

Where references name a specific public app as an illustrative example of a pattern (Trust Wallet at 27k classes for JADX heap sizing, MetaMask using Hermes, the Hermes-adoption set across wallets, the leaked-host gate sub-patterns observed in finance/retail/media apps), the empirical claim is **static-analysis observation from corpus research**, not vendor-confirmed exploitability:

- Static-analysis findings have not been validated against live backends or production accounts.
- Build-pinned and feature-flag-gated chains are reported as latent shapes, not as exploitable issues in the released artifact.
- Where private corpus identifiers (`corpus-N`, pass numbers, P-tier counts) appeared in earlier iterations of these references, they have been generalized — the empirics survive; the internal bookkeeping does not.

A future agent picking up this capability with no prior context should:

1. Use the public sources above to ground the methodology in canonical research.
2. Treat illustrative app names as pattern anchors for recognition, not as a vulnerability roster.
3. Reproduce the empirical observations by running this capability's scripts (`extract_corpus_components.py`, `rank_components.py`, the per-class `run_class_rg.sh` profiles, `extract_api_map.py`) against any AndroZoo or Play corpus of comparable size — the patterns are robust across re-runs because they're shape-based, not name-based.
4. For responsible-disclosure handling of any finding produced against a specific shipped app, follow the relevant vendor's security policy or coordinated-disclosure process before publishing.

---

## Adding a new source

When extending the references with a new claim:

1. If the claim is grounded in a public CVE, paper, blog, or vendor doc, add the URL under the matching section above.
2. If the claim is an internal empirical observation, attribute as "observed in internal corpus research" inline, and (optionally) add a one-line note here describing the pattern shape and the corpus size.
3. Use the existing reference files for inline cross-links; this file is the canonical index, not a replacement for prose.
