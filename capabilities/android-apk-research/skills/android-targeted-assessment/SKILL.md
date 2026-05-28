---
name: android-targeted-assessment
description: "Use when assessing one Android APK deeply — inventory, decompile, ripgrep + Semgrep triage, Joern/CodeQL/FlowDroid escalation where warranted, hypothesis report, authorized validation plan."
allowed-tools:
  - inventory_status
  - run_corpus_inventory
  - detect_runtime_kind
  - extract_api_map
  - normalize_semantic_findings
  - bash
  - read
  - grep
  - glob
  - web_search
  - web_extract
  - report
license: MIT
---

# Android targeted APK assessment

Use this skill when the user provides one APK (or a very small set) and wants depth over breadth. Output is a concise, evidence-backed report with semantic findings, scanner-gap labelling, and tiered validation plans.

This skill rides the same pipeline as `android-semantic-vuln-hunting`, just compressed to one target. `android-semantic-vuln-hunting` is the canonical methodology — when the pipeline shape changes (new MCP tool, heap-tier update, new bug class), update both skills in the same commit. Read that skill first if you need methodology; this one is the recipe.

## First: discover the available utilities

If you are unsure which APK research flow applies, read the utility index first:

```bash
cat ../android-semantic-vuln-hunting/references/agent-utility-index.md
```

For a single APK, the key optional branches are:

- commercial protector detected → load `android-protector-triage`
- React Native / Flutter / hybrid runtime → JS/Dart route-map validation before grading
- rich backend client signs → run `scripts/extract_api_map.py` and use `backend-rich-apk-workflows.md`
- feature flags / request signing / workflow verbs / native bridges → use the matching references before writing hypotheses
## 0. Scope + tooling sanity

Confirm with the user:

- the APK path and authorization
- whether dynamic validation (ADB / emulator / device / test account / backend) is in scope

Then verify tools (no custom tool needed):

```bash
for t in jadx apktool aapt aapt2 adb androguard apkid semgrep joern codeql; do
  printf '%-12s ' "$t"; command -v "$t" || echo MISSING
done
```

## 1. Inventory the APK

Even for one APK, `run_corpus_inventory` gives a clean per-SHA artifact tree with Androguard-decoded manifest facts and APKiD packer detection — much faster than reading the binary manifest yourself.

```bash
run_corpus_inventory(paths=["path/to.apk"], out_dir="findings/<pkg>", include_apkid=true)
```

Read the produced `findings/<pkg>/apks/<sha>/androguard.json` first. Look for:

- `package`, `version_name`, `target_sdk`
- `browsable_components` — these are the externally-reachable entrypoints
- `components[*].exported`, `permission`, `intent_filters` — full attack surface
- `schemes`, `hosts` — deep link URI shapes
- `permissions` — what the app is allowed to do (dangerous perms suggest sensitive flows)

Read `apkid.json` for packer/protector/obfuscator signal. Heavy obfuscation changes the strategy: deeper Joern reliance, less faith in `rg`, prefer dynamic validation.

If APKiD flags a commercial protector OR `lib/<abi>/libdpboot.so` / `libdexprotector.so` is present OR `assets/` contains opaque `.dat` blobs (`se.dat`, `classes.dex.dat`, `mm.dat`, `dp.mp3`, `resources.dat`, `ic.dat`, `ct.dat`, `rcdb.dat`), **stop here and load the `android-protector-triage` skill**. JADX output, ripgrep over decompiled sources, and Semgrep baselines are all incomplete under commercial protection; running them as if the APK were unprotected produces false confidence. The protector-triage skill includes detection, structural unpack (DexProtector → libdp.so today), and the protector-aware decompile/triage decisions.

## 2. Detect runtime kind, then decompile

A 1-second probe drives both the JADX heap setting **and** whether you need a JS-bundle or Dart-AOT trace later. Doing this before JADX saves a wasted OOM run.

```python
# MCP tool — returns dict with `runtime_kind` in
# {native, react_native_js, react_native_hermes, flutter_aot,
#  capacitor, cordova, unity, xamarin, maui}.
detect_runtime_kind(apk="path/to.apk")
```

For `react_native_*` and `flutter_aot`, default Java-side hypotheses to `confidence_tier=needs_route_map_validation` (see §4.5 / §4.6 below).

```bash
SRC=findings/<pkg>/sources
# Heap tier by DEX class count (read from androguard.json, or `apkanalyzer dex packages`)
#   <15k  classes  ->  -Xmx2g  (most apps)
#   15-30k classes  ->  -Xmx6g  (wallets, messengers, large banking)
#   >30k  classes  ->  -Xmx8g
JAVA_OPTS="-Xmx6g" jadx --show-bad-code --no-debug-info -d "$SRC" "$APK"
```

Empirical (corpus observation): a wallet-class APK at ~27k classes / 83 MB (Trust Wallet) OOMs at `-Xmx2g` and runs clean at `-Xmx6g`; a smaller wallet at ~13k classes (MetaMask) is fine at `-Xmx2g`. **Start at the right heap; one retry burns 3-5 minutes.**

The first-party tree usually lives under `$SRC/sources/<reverse-dns-package>`. Use that path for the rest of the work.

## 3. ripgrep the focused source/sink set on first-party code

If the APK has a known impact class (assigned by `android-corpus-prep`, e.g. `C_wallet`), run the per-class profile first — it captures patterns unique to that app type and is usually 3× faster to triage than the universal set:

```bash
bash scripts/run_class_rg.sh <CLASS> "$APP" findings/<pkg>/
```

Profiles for all 10 classes live in `../android-semantic-vuln-hunting/references/impact-class-rg-profiles.md`.

### Universal source/sink set

```bash
APP=$SRC/sources/$(echo <package> | tr . /)
rg -n \
  -e 'getIntent\(' -e 'getData\(' -e 'getStringExtra\(' \
  -e 'getParcelableExtra\(' -e 'getSerializableExtra\(' \
  -e 'Intent\.parseUri\(' -e 'Uri\.parse\(' -e 'getQueryParameter\(' \
  -e 'startActivity\(' -e 'startService\(' -e 'sendBroadcast\(' \
  -e 'WebView' -e 'loadUrl\(' -e 'postUrl\(' \
  -e 'addJavascriptInterface\(' -e 'setJavaScriptEnabled\s*\(\s*true' \
  -e 'shouldOverrideUrlLoading' -e 'CookieManager' \
  -e 'Authorization' -e 'Bearer ' \
  -e 'SharedPreferences' -e 'isLoggedIn' \
  -e 'FLAG_GRANT_READ_URI_PERMISSION' -e 'FileProvider' \
  "$APP" > findings/<pkg>/rg.txt
```

Read only the files that show **multiple** categories — especially `getIntent`/`getQueryParameter` together with `loadUrl`/`addJavascriptInterface` or with `startActivity`. Cross-reference against `androguard.json` exported/BROWSABLE components.

### Backend-rich API map pass

If the target appears to be a rich backend client (Retrofit/Apollo/gRPC/WebSocket/Firebase, request signing, feature flags, tenant/account/device/payment/order IDs), extract an API map before writing backend hypotheses:

```python
extract_api_map(
    src="$SRC",
    out="findings/<pkg>/api_map.jsonl",
    summary="findings/<pkg>/backend_richness.json",
    dedupe=True,
)
```

Use `../android-semantic-vuln-hunting/references/backend-rich-apk-workflows.md` for APK→API validation planning. Static endpoint/DTO evidence is normally `needs_backend_validation`; do not probe live backend actions without explicit scope.
## 4. Semgrep scanner baseline + scanner_gap

```bash
semgrep --config p/security-audit \
        --config p/mobsfscan \
        --config r/java \
        --metrics=off \
        --json --output findings/<pkg>/semgrep.json "$SRC"
```

When writing each hypothesis, attach `scanner_gap` (exact / adjacent / generic / not found). See `../android-semantic-vuln-hunting/references/scanners.md` for label definitions and other scanner options (MobSF, APKHunt, `mobsfscan`).

## 4.5 React Native / hybrid: read the JS bundle before grading findings

If the runtime probe in §2 reported `react_native_js` or `react_native_hermes`, the JS bundle owns the routing decision. Plain JS — prettier + rg. Hermes — `hbctool disasm` first (string table is the high-signal target):

```bash
# Plain JS
BUNDLE=$SRC/resources/assets/index.bundle
mkdir -p findings/<pkg>/js-analysis
npx --yes prettier@3.3.3 --parser babel --print-width 120 "$BUNDLE" \
  > findings/<pkg>/js-analysis/index.pretty.js
JSDIR=findings/<pkg>/js-analysis

# Hermes bytecode (file reports `data`, magic c6 1f bc 03 per facebook/hermes BCVersion.h)
pipx install hbctool 2>/dev/null
hbctool disasm $SRC/resources/assets/index.android.bundle findings/<pkg>/js-analysis/hbc
JSDIR=findings/<pkg>/js-analysis/hbc

rg -n -e 'addEventListener\(.url.' -e 'Linking\.' -e 'emitNewIntentReceived' \
       -e '_PATHS_TO_SCREENS_MAP' -e 'DEEP_LINK' -e 'ALLOWED_HOSTS' "$JSDIR"
```

Trace each Java-side bridge symbol backwards from its callers to the URL/host/path validators in JS. A strict allowlist downgrades Java findings to `hardening_only`. A `contains`/`startsWith` or no check is a real bug. Pre-bundle gradings should default to `needs_route_map_validation`, not `strong_static_chain`.

Full recipe and grading rules: `../android-semantic-vuln-hunting/SKILL.md` § Step 7.5.

## 4.6 Flutter / Dart AOT: read libapp.so before grading findings

If the runtime probe reported `flutter_aot`, the Dart code in `lib/<abi>/libapp.so` owns routing. Java/Kotlin side is a MethodChannel relay; pre-bundle Java findings default to `needs_route_map_validation`.

```bash
# Recover Dart classes / strings / route keys with blutter
# https://github.com/worawit/blutter
blutter $SRC/resources/lib/arm64-v8a/ findings/<pkg>/dart-analysis/

# Match Java MethodChannel names against Dart-side handlers
rg -n 'new MethodChannel\|new C6\.o\|new EventChannel' $SRC \
   | rg -o '"[^"]+"' | sort -u  > findings/<pkg>/method-channels.txt
rg -nN -f findings/<pkg>/method-channels.txt findings/<pkg>/dart-analysis/
```

Dart-side strict allowlist on URL/host -> `hardening_only`. Loose check or no check -> real bug. Without blutter, fall back to `strings -a libapp.so` filtered by route-key patterns; surfaces literals but loses structure.

Full recipe: `../android-semantic-vuln-hunting/SKILL.md` § Step 7.6.

## 5. Joern for call/data context — only on shortlisted methods

For each surviving hypothesis where you need to know "who calls this", "where does this value come from", or "what does the bridge expose":

```bash
joern --script <(cat <<EOF
importCode(inputPath = "$SRC", projectName = "<pkg>")
EOF
)
```

Recipes for the queries you'll actually use (exported activities reading intents, deep-link source → WebView sink, JavaScript bridge surface) are in `../android-semantic-vuln-hunting/references/joern-recipes.md`.

Stop using Joern as soon as the chain is clear. It is not the report; the hypothesis is.

## 6. Optional CodeQL — when path-precise evidence matters

If the finding needs path-precise evidence for an external report (MASVS-mapped or otherwise), build a CodeQL DB from the JADX source and run the relevant Android query packs ([java-android-intent-redirection](https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/), [java-android-unsafe-android-webview-fetch](https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/), [full list](https://codeql.github.com/codeql-query-help/java/)).

Recipes: `../android-semantic-vuln-hunting/references/codeql-recipes.md`.

## 7. Optional FlowDroid — lifecycle-aware taint

Only for chains where impact justifies cost. Reference: [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/).

## 8. Write hypotheses, normalize, validate

Use the schema in `../android-semantic-vuln-hunting/references/output-schema.md`. Then:

```python
normalize_semantic_findings(
    inputs=["findings/<pkg>/hypotheses.jsonl"],
    output_format="markdown",
    out="findings/<pkg>/report.md",
)
```

Build the ADB validation plan from `androguard.json` (decoded schemes/hosts/components):

```bash
# Browsable deep link probe — non-destructive, local device only.
adb shell am start -a android.intent.action.VIEW \
  -d '<scheme>://<host>/<path>?dn_probe=1' \
  <package>
adb logcat -d | rg -i '<package>|deep|webview'
```

For nested-Intent / Parcelable redirection, plan a tiny helper APK instead of trying `am start` payloads; record what it would do rather than building it unless authorized.

## Depth-first review priorities

For a single target, spend more time on:

- exported + BROWSABLE activities and their `onCreate`/router methods
- internal deep-link dispatcher implementation (often a `*Router`, `*DeepLink*`, `*Navigator` class)
- WebView setup (`setJavaScriptEnabled`, `addJavascriptInterface`, `shouldOverrideUrlLoading`)
- auth/session/account-state checks (`SharedPreferences`, `isLoggedIn`, `access_token`, `Bearer`)
- password reset / invite / OAuth / magic link / payment flows
- exported `ContentProvider`s and `FileProvider` paths

## Evidence standard

A targeted report should not contain generic warnings. Each finding requires:

- manifest or code entrypoint evidence
- attacker-controlled source
- specific trust-boundary mistake
- sensitive sink
- plausible impact
- a validation plan with an explicit authorization tier

If impact depends on backend behaviour, set `confidence_tier=needs_backend_validation` and describe the test account/scope required. Do not claim exploitability from local bypass alone.

## Report shape

1. Scope and artifact identifiers (path, package, version, SHA256, JADX/scanner versions).
2. Decoded manifest summary (component counts, exported/BROWSABLE, schemes, hosts, dangerous permissions).
3. Top semantic findings, each with the full schema.
4. Scanner baseline summary and `scanner_gap` table.
5. Validation queue grouped by tier (`tier0_static_only` → `tier3_explicit_production_authorization`).
6. Appendix with normalized JSONL hypotheses.
