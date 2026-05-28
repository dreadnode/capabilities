---
name: android-semantic-vuln-hunting
description: Use when hunting Android APK logic bugs at scale — deep links, intent redirection, WebView trust, exported components, auth/session/client-state bypasses that scanners miss or flatten to generic warnings.
allowed-tools:
  - inventory_status
  - run_corpus_inventory
  - extract_components
  - rank_components
  - detect_runtime_kind
  - extract_api_map
  - rank_backend_richness
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

# Android semantic vulnerability hunting

Work only on APKs the user is authorized to analyze. Default to static analysis and authorized read-only validation; do not patch APKs, automate exploitation, attack production backends, or test live accounts without explicit scope.

This skill is methodology + CLI. The `android-research` MCP wraps the orchestration layer (inventory, component ranking, runtime detection, protector triage, API map extraction, finding normalization); JADX, ripgrep, Semgrep, Joern, CodeQL, FlowDroid, hbctool, blutter, and adb run as bash because the heap-tier table, rule-pack ensemble, and query recipe *are* the methodology. See `references/workflow.md` § "Why bash, not MCP" for the per-tool rationale.

This skill rides the same pipeline as `android-targeted-assessment` (one-APK depth mode). When the pipeline shape changes here (new MCP tool, heap-tier update, new bug class), update both skills in the same commit.

Ground findings in OWASP MASVS ([MASVS](https://mas.owasp.org/MASVS/)) and MASTG procedures ([MASTG](https://mas.owasp.org/MASTG/)), with weakness mapping to CWE ([cwe.mitre.org](https://cwe.mitre.org/)) and MASWE ([MAS Weakness Enumeration](https://mas.owasp.org/MASWE/)). The `normalize_semantic_findings` MCP tool auto-fills these from the `class` slug per `references/output-schema.md`. OWASP notes automated static analysis is useful but noisy and requires careful review ([MASTG-TECH-0025](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0025/)); here scanners are baseline evidence, not the discovery driver.

## First: discover the available flows

Before choosing commands from memory, read the local utility index when you need orientation:

```bash
cat references/agent-utility-index.md
```

Use it to route the session:

- **manifest/component surface** → `run_corpus_inventory`, `extract_components`, `rank_components` (all MCP tools)
- **runtime/decompile routing** → `detect_runtime_kind` (MCP tool), then JADX with the right heap
- **impact-class source triage** → `run_class_rg.sh` plus the universal source/sink set
- **backend-rich APK/API map** → `extract_api_map.py`, then `rank_backend_richness.py` for corpus inboxes
- **feature flags / request signing / workflow state machines / hybrid bridge-to-backend** → the matching references under `references/`
- **scanner gap / normalization** → Semgrep baseline, then `normalize_semantic_findings`

If the user asks “what can we try next?” or “what utilities do we have?”, summarize this index instead of improvising.
## Pick the mode before picking the tools

Three intent shapes; pick one explicitly. Do not default to "per-class top-3".

### Mode A — single APK (the user named one)

The user said "look at `com.example`" or handed you an APK. **Skip the broad scan entirely.** Jump to Step 3 (decompile) with the right heap, then Step 4 (rg) on the first-party tree. The other ~85 APKs in the corpus are not your problem this session. Use the sibling skill `android-targeted-assessment` if you've got it.

### Mode B — broad corpus pass (the user wants coverage)

"What's interesting across these 86 APKs?" "Find me low-hanging deep-link bugs." "We've got 8 hours and 7 unstarted classes."

Use a **funnel**, not a depth-first per-class crawl:

1. **Tier A — component-level ranking, no decompile.** Run `extract_corpus_components.py` over the inventory directory and `rank_components.py` over the output. ~30 minutes wall to cover the whole corpus. Emits a ranked-component inbox of maybe 100–200 entries (out of ~15k components in an 86-APK corpus) at score >= 4.
2. **Tier B — decompile only APKs that own a top component.** Usually 15–30 APKs out of the corpus. JADX in a single parallel batch, `-Xmx` chosen by class count.
3. **Tier C — 5-minute reading pass per top component.** Outcome is one of `escalate` / `hardening_only` / `not_a_chain`. Strict per-component budget; queue overflow for later. Half the components dismiss in under a minute.
4. **Tier D — depth + Semgrep only on `escalate` candidates.** This is where per-target hypothesis + tier1 validation happens. Realistically 5–15 candidates from the whole corpus.

Tier A scripts live at `scripts/extract_corpus_components.py` and `scripts/rank_components.py`; see "Step 2.5" below.

### Mode C — single impact class (the user picked one)

"Do `D_secret` next." Roughly halfway between A and B. Run the per-class rg profile (Step 4) and target the top 3 by `semantic_priority`, *but* cross-reference with the Tier A `components_ranked.md` view if it exists — sometimes a class's #4 or #5 APK has a higher-scoring component than the #1. Don't decompile #1 if its top component scored 3 and #4's top component scored 9.

## The pipeline (Mode B/C view)

```
corpus → run_corpus_inventory (Androguard + APKiD, parallel, resumable)
       → extract_corpus_components + rank_components → components_ranked.md
       → jadx -d for APKs owning top-N ranked components
       → rg the focused source/sink set on first-party code
       → semgrep p/android for scanner baseline + scanner_gap labelling
       → joern for call/data context on shortlisted methods
       → optional codeql for precise Java/Kotlin path evidence (MASVS-grade)
       → optional FlowDroid for lifecycle-aware taint when stakes warrant it
       → finding hypotheses → normalize_semantic_findings
       → authorized validation with adb
```

Each step is a deliberate escalation. Most APKs stop after the component rank; only chains with real impact reach Joern/CodeQL/FlowDroid.

## Step 1 — inventory the corpus (parallel, resumable)

```bash
# Tool — call from the agent.
run_corpus_inventory(paths=["corpus/apks"], out_dir="findings/run", jobs=8, include_apkid=true)
```

Each APK becomes `findings/run/apks/<sha256>/` with:

- `inventory.json` — package, schemes/hosts, browsable/exported components, embedded URLs/domains, library hints
- `androguard.json` — authoritative manifest facts via Androguard ([Androguard](https://androguard.readthedocs.io/en/latest/intro/gettingstarted.html))
- `apkid.json` — packer/protector/obfuscator signal ([APKiD](https://github.com/rednaga/APKiD))
- `status.json` — per-stage status

Aggregate JSONLs live at the run root: `attack_surface.jsonl` and `status.jsonl`.

## Step 2 — rank with jq, not a custom tool

```bash
RUN=findings/run

# Highest semantic-priority APKs.
jq -c 'select(.semantic_priority.score>=10)' $RUN/attack_surface.jsonl \
  | jq -s 'sort_by(-.semantic_priority.score) | .[:25]' > $RUN/top25.json

# Just the file paths for the next step.
jq -r '.[] | .apk' $RUN/top25.json > $RUN/top25.paths

# Externally reachable BROWSABLE deep-link surfaces, by package.
jq -r '. as $r | $r.browsable_components[]? | "\($r.package)\t\(. )"' \
  $RUN/attack_surface.jsonl | sort -u
```

Selection bias: finance, identity, wallet, retail, travel, payments, OAuth, WebView-heavy hybrid apps, big component/scheme/host counts, packed/protected apps de-prioritised unless they are the target.

## Step 2.5 — component-level ranking (Mode B/C only)

`semantic_priority` ranks APKs; the actually-interesting things are **components**. An APK with 7 boring exported activities and 1 wildcard-host SSO callback ranks the same as one with 8 boring activities. The Tier A tools fix that by emitting one row per component and scoring it.

```python
# MCP tools — call from the agent.
extract_components(
    inventory_dir=f"{RUN}/apks",
    triage_manifest=f"{RUN}/triage/manifest.jsonl",   # optional join
    runtime_kind=f"{RUN}/inventory/runtime_kind.jsonl",  # optional join
    out=f"{RUN}/triage/components.jsonl",
)
rank_components(
    components=f"{RUN}/triage/components.jsonl",
    out_jsonl=f"{RUN}/triage/components_ranked.jsonl",
    out_md=f"{RUN}/triage/components_ranked.md",
    top_md=150, min_score=4,
)
```

`extract_components` reads every `androguard.json` under `$RUN/apks/<sha>/`, falls back to `aapt2 dump xmltree` for APKs where Androguard errored (empirically: multi-dex APKs with ≥22 `classes*.dex` files break Androguard 4.1.3), and emits one JSONL row per `(apk, type, name)` carrying exported/permission/scheme/host/path/action facts plus APK-level joins (`apkid_tier`, `impact_class`, `runtime_kind`).

`rank_components` applies risk priors. The full table is in `scripts/rank_components.py`; in short:

- **+5** exported BROWSABLE with no permission
- **+3** host wildcard; high-risk path/action/scheme (`join`, `accept`, `invite`, `redirect`, `callback`, `sso`, `oauth`, `transfer`, `recover`, `magic`, `intent`, `router`, `proxy`, `import`, `share`, `IMPORT_`, `EXPORT_`, `otpauth`, `smsto`, etc.); exported/no-perm share/import targets (`SEND`, `SEND_MULTIPLE`, `GET_CONTENT`, `OPEN_DOCUMENT`, `PICK`)
- **+2** exported AutofillService / AccessibilityService / CredentialProviderService; exported ContentProvider with `grantUriPermissions`; exported receiver with custom action and no perm; broad MIME share/import target (`*/*`, `image/*`, `application/octet-stream`)
- **+1** App-Link (http/https) surface with non-wildcard host
- **−5** permission with `protectionLevel=signature`; **−3** `medium` packer; **−12** `heavy` packer

`read_budget` field: `5m` if score ≥ 7, `1m` if 3–6, `skip` if below 3. Use that as the per-component time cap in Tier C.

Empirics from a representative 86-APK corpus (~15.8k components):

- 14,810 components scored 0 → not worth a glance
- ~190 components scored ≥ 4 → the actual inbox
- Top hits at score 11–12 in internal corpus runs surfaced shapes like: a 7-auth-scheme LaunchActivity in an enterprise authenticator app (Azure Authenticator), a `DeepLinkRouterActivity` with 12 paths in a 2FA app (Duo Mobile), an SMS-MMS multi-scheme entry point in a lightweight email client (Microsoft Outlook Lite), and a wildcard-host SSO in a password-manager class (Proton Pass). Provenance framing in `references/sources.md`.

The markdown view groups the top entries by `impact_class` first, then a full ranked list by package. Read it as your inbox: top of the page = next decompile candidate; bottom = "skim only if time".

## Step 3 — decompile only what you'll actually read

Before JADX, identify the **app runtime kind** with a 1-second probe. This determines (a) whether you need to budget for a JS-bundle or Dart-AOT trace after the Java pass and (b) how high to raise the JADX heap.

```python
# Single APK — MCP tool returns dict with runtime_kind in
# {native, react_native_js, react_native_hermes, flutter_aot,
#  capacitor, cordova, unity, xamarin, maui}.
detect_runtime_kind(apk="path/to.apk")
```

```bash
# Corpus sweep (one second per APK; output is JSONL keyed by apk path)
for a in corpus/apks/*.apk; do
  bash scripts/detect_runtime_kind.sh --jsonl "$a"
done > findings/run/runtime_kind.jsonl
```

The probe uses `unzip -l` only — it does not extract the APK — and reads the Hermes magic bytes (`c6 1f bc 03`, per facebook/hermes `BCVersion.h`) to distinguish Hermes from plain JS without unpacking the bundle.

Corpus-2 sweep (86 APKs, mostly C_wallet/G_messenger/D_secret): 76 native, 6 react_native_hermes, 4 flutter_aot. **C_wallet alone:** 5 of 7 targets are non-native. The 7.5/7.6 bundle trace is the dominant workload for that class, not an optional escalation.

Decompile, capping the JADX heap by **DEX class count** (from `androguard.json` or `apkanalyzer dex packages`). JADX is unbounded by default; a banking APK can grow a single JVM to 6-8 GB.

```bash
# Heap tier table — pick by class count, fall back to APK size
# <15k classes  (<50 MB APK)   : -Xmx2g
# 15-30k classes (50-100 MB)   : -Xmx6g   <-- many wallet/messenger apps
# >30k classes  (>100 MB)      : -Xmx8g
JAVA_OPTS="-Xmx6g" jadx --show-bad-code --no-debug-info -d findings/decompiled/<pkg> path/to.apk
```

**Empirical (corpus observation):** a wallet-class APK at ~83 MB / 27k classes (Trust Wallet) OOMs at `-Xmx2g` partway through decompile and succeeds clean at `-Xmx6g`; a smaller wallet at ~13k classes (MetaMask) and most fintech apps finish at `-Xmx2g`. Always check the class count before choosing parallelism.

**>150 MB / >60k-class APK hang.** JADX 1.5.x has been observed to write the full source tree to disk and then hang at 99% on the shutdown phase rather than exit cleanly. Corpus observation: a banking-class APK at ~200 MB / 74k classes (Chase Mobile) at `-Xmx8g` finished output but the JVM never returned. The decompiled sources are fully usable while the JVM is hung; if the log shows the progress line stuck at the penultimate count for several minutes, kill the JVM (`ps -ef | grep jadx`; `kill -9 <pid>`) and continue. Do not wait for clean shutdown on banking-class APKs.

Use the `--source-dir` output (`findings/decompiled/<pkg>/sources`) as the search root for the rest of the pipeline. Do not decompile the whole corpus.

**Memory budgeting.** JADX is the heaviest tool in the pipeline. Multiply expected resident set by parallelism:

| Stage | Per-worker RSS | Safe `jobs=` on 32 GB host |
|---|---|---|
| `run_corpus_inventory` | ~150 MB (streamed) | 8 |
| `jadx` <15k classes (`-Xmx2g`) | ~2.5 GB | 2–3 |
| `jadx` 15-30k classes (`-Xmx6g`) | ~6.5 GB | 1–2 |
| `jadx` >30k classes (`-Xmx8g`) | ~8.5 GB | 1 |
| `semgrep` (large tree) | ~1–2 GB | 2 |
| `joern` import | ~6–10 GB | 1 |
| `codeql database create` | ~4–8 GB | 1 |

Run decompile + scanner stages serially when in doubt; Joern and CodeQL must be single-process on most laptops. **At scale (>20 APKs):** sort the queue by class count ascending and run the cheap APKs first — failure of one heavy APK doesn't burn the small ones queued behind it.

## Step 4 — ripgrep the focused source/sink set on first-party code

If the corpus has an `impact_class` per APK (the `android-corpus-prep` skill assigns these — `A_ingress`, `B_remote`, `C_wallet`, `D_secret`, `E_file_cloud`, `F_family`, `G_messenger`, `H_email`, `I_browser`, `J_iot`), run the per-class profile **in addition to** the universal source/sink set:

```bash
bash scripts/run_class_rg.sh <CLASS> "$SRC" findings/<pkg>/
```

The per-class profiles capture the bug patterns unique to each app type — WalletConnect for wallets, AutofillService for password managers, MIME parsing for email, mDNS for IoT — and are documented in `references/impact-class-rg-profiles.md`. Reading the class-specific hits first is usually 3× faster than reading the universal set.

### Universal source/sink set

Limit search to the app package and adjacent first-party classes (`com.<vendor>.…`, `<package>.…`). Skip `androidx.`, `kotlin.`, `kotlinx.`, `com.google.`, `com.facebook.react.`, etc.

```bash
SRC=findings/decompiled/<pkg>/sources/<package>  # narrow to first-party
rg -n -e 'getIntent\(' -e 'getData\(' -e 'getStringExtra\(' \
       -e 'getParcelableExtra\(' -e 'getSerializableExtra\(' \
       -e 'Intent\.parseUri\(' -e 'Uri\.parse\(' -e 'getQueryParameter\(' \
       -e 'startActivity\(' -e 'startService\(' -e 'sendBroadcast\(' \
       -e 'WebView' -e 'loadUrl\(' -e 'postUrl\(' \
       -e 'addJavascriptInterface\(' -e 'setJavaScriptEnabled\s*\(\s*true' \
       -e 'shouldOverrideUrlLoading' \
       -e 'CookieManager' -e 'Authorization' -e 'Bearer ' \
       -e 'SharedPreferences' -e 'isLoggedIn' \
       -e 'FLAG_GRANT_READ_URI_PERMISSION' -e 'FileProvider' \
       -e 'ACTION_SEND|ACTION_SEND_MULTIPLE|EXTRA_STREAM|EXTRA_TEXT|EXTRA_TITLE|ClipData' \
       -e 'OpenableColumns\.DISPLAY_NAME|MediaStore\.MediaColumns\.DISPLAY_NAME' \
       -e 'ContentResolver\.query|openInputStream|openOutputStream|openFileDescriptor' \
       -e 'FileOutputStream|Files\.copy|copyTo|openFileOutput|new File\(' \
       -e 'getCacheDir|getFilesDir|canonicalPath|getCanonicalPath|normalize|createTempFile' \
       -e 'rawQuery|execSQL|SQLiteQueryBuilder|selection|projection|sortOrder|setStrict|setProjectionMap' \
       -e 'https?://|/api/|/v[0-9]+/|/graphql|/grpc|/rpc|/gateway|/mobile|/internal' \
       -e 'Retrofit|OkHttpClient|Request\.Builder|HttpUrl|ApolloClient|GraphQL|operationName|persistedQuery' \
       -e 'io\.grpc|ManagedChannel|MethodDescriptor|GeneratedMessageLite|protobuf|WebSocket|Socket\.IO|SignalR|EventSource|MQTT|FirebaseFirestore' \
       -e 'X-Api-Key|apiKey|x-device|deviceId|installationId|sessionId|refreshToken' \
       -e 'Hmac|Mac\.getInstance|signature|signRequest|nonce|timestamp|canonical|attestation|SafetyNet|PlayIntegrity' \
       -e 'tenantId|orgId|accountId|userId|ownerId|familyId|childId|vaultId|orderId|paymentId|roomId|messageId' \
       -e 'role|isAdmin|verified|entitlement|premium|subscription|scope|permissions|status|state|price|amount|discount' \
       -e 'accept|approve|complete|activate|claim|redeem|recover|reset|verify|bind|pair|link|migrate|transfer' \
       -e 'callback|redirect_uri|returnUrl|webhook|avatarUrl|imageUrl|preview|unfurl|importUrl|sourceUrl' \
       "$SRC" > findings/triage/<pkg>.rg.txt
```

Sort by file, then read the **handful** of files that show source+sink categories together. Prefer files implementing components that came back from `androguard.json` with `exported=true` and a BROWSABLE intent filter. For rich-backend apps, also group hits by API client / DTO / operation family; APK-discovered backend issues usually need endpoint + auth/header mechanics + object/workflow model before they are useful hypotheses.

**R8 + Kotlin Metadata caveat.** Public Kotlin top-level objects (`object Foo { val BAR = "https://..." }`) survive R8 minification because the `@Metadata` annotation pins them, even when nothing in DEX reads `Foo.BAR`. Empirically on a leaked-host triage pass over ~14 popular Play APKs, **~71% of leaked-host literal hits in production APKs had zero DEX consumers** — they were R8/Kotlin-Metadata leftovers from build flavors that were stripped of their callers but not their data. Before walking back a host literal, confirm the containing class is *consumed* somewhere by another DEX file:

```bash
# Once you have the file that holds the literal, name the obfuscated enclosing class:
rg -nl 'verified-it\.capitalone\.com' "$SRC"
# -> com/example/SomeObfuscatedClass.java

# Then check whether any other DEX file references that class name (excluding kotlin.Metadata strings):
rg -nFw 'SomeObfuscatedClass' "$SRC" | grep -v 'kotlin/Metadata\|@Metadata' | head
```

If the only references are inside the file itself (self-reference) or inside `kotlin.Metadata` annotation literals on other classes, the string is dead. Record as `unreachable`. For the full leaked-host runbook including the four gate categories (A1 BuildConfig / A2 feature flag / A3 intent extra / A4 build-pin), see `references/leaked-host-triage.md`.

**Reflection-trampoline caveat (pairip-style anti-tamper).** Some Play-protected apps replace the body of a manifest-named Activity/Service with a single reflective call whose `Method` handle is populated at runtime by native code:

```java
// com.dashlane.ui.activities.DeepLinkRoutingActivity.onCreate()
nRvCZi.QDdhPXfzXCrHxb.invoke(null, this, bundle);
```

Following the call graph from the manifest-named entry class will dead-end. Switch to **content search on the known deep-link path strings** (paths and schemes pulled from the manifest):

```bash
# We know dashlane://*/vault and dashlane://*/mplesslogin exist from the manifest.
rg -nl '"/vault"|"/mplesslogin"|"dashlane://"' "$SRC"
```

The real router will appear in the matching files — usually a `NavigatorImpl.handleDeepLink` or similar, often in a `navigation` / `routing` / `deeplink` package. Add this content-search step to the rg pass whenever the manifest entry class body is one or two lines of reflection.

### Backend-rich API map pass

If the APK looks like a rich backend client (many API paths, generated clients, request signing, GraphQL/gRPC/WebSocket, feature flags, tenant/account/device/payment/order concepts), run the lightweight API map pass before writing hypotheses:

```python
extract_api_map(
    src="findings/decompiled/<pkg>/sources",
    out="findings/<pkg>/api_map.jsonl",
    summary="findings/<pkg>/backend_richness.json",
    dedupe=True,
)
# Returned dict includes `summary` with backend_richness / total_score /
# unique_value_counts / synergy_flags — no jq needed for routine inspection.
```

For JS/Dart shells, run the same script over `findings/<pkg>/js-analysis` or `findings/<pkg>/dart-analysis` after Step 7.5/7.6. Use `references/backend-rich-apk-workflows.md` to decide whether to reconstruct API maps, feature flags, request signing, workflow state machines, or bridge-to-backend traces.

Backend-rich outputs are target maps. Default their hypotheses to `confidence_tier=needs_backend_validation` unless authorized backend testing proves BOLA, workflow bypass, mass assignment, SSRF/open redirect, replay, or bridge-to-backend action impact.

## Step 5 — Semgrep scanner baseline (label scanner gaps)

Semgrep is a precise, explainable scanner baseline. Use the public Android security rule pack against the JADX sources, then label each hypothesis against it.

```bash
semgrep --config p/security-audit \
        --config p/mobsfscan \
        --config r/java \
        --metrics=off \
        --json --output findings/baselines/<pkg>/semgrep.json \
        findings/decompiled/<pkg>/sources
```

For each finding hypothesis, attach `scanner_gap`:

- `exact baseline finding` — Semgrep flagged the same entrypoint/source/sink
- `adjacent baseline finding` — Semgrep saw the risky API but not the chain
- `generic warning only` — Semgrep produced a category, not a chain
- `not found` — no relevant Semgrep rule

Most impactful logic bugs end up at `adjacent` or `not found`; that is the value of the capability.

For Android-specific rule packs, see `references/scanners.md`.

## Step 6 — Joern for call/data context on shortlisted methods

Joern is the right tool when a chain needs caller/callee or data-flow context. Use it on selected JADX trees, not the whole corpus. CPG concept and query language: [docs.joern.io](https://docs.joern.io/code-property-graph/), [docs.joern.io/quickstart](https://docs.joern.io/quickstart/).

```bash
joern --script <(cat <<'EOF'
importCode(inputPath = "findings/decompiled/<pkg>/sources", projectName = "<pkg>")
EOF
)
```

Then run focused queries (recipes in `references/joern-recipes.md`):

- exported activities whose `onCreate` reads `getIntent()` and reaches `startActivity`
- methods reading `getStringExtra` whose values flow into `loadUrl`
- callers of `addJavascriptInterface` and what the bridge exposes

Stop using Joern as soon as you have enough context to write the hypothesis. It is not a corpus scanner.

## Step 7 — optional CodeQL for path-precise evidence

CodeQL has Android-specific Java/Kotlin queries: intent redirection ([java-android-intent-redirection](https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/)), unsafe WebView fetch ([java-android-unsafe-android-webview-fetch](https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/)), arbitrary APK installation, WebView JavaScript settings, and more ([java/](https://codeql.github.com/codeql-query-help/java/)). Use CodeQL when a finding needs path-precise (SARIF) evidence for an external report.

Recipes: `references/codeql-recipes.md`.

CodeQL database creation from JADX-decompiled source is best-effort: it works for source-rich apps but not every decompile. Treat it as optional escalation.

## Step 7.5 — React Native and hybrid apps: trace into the JS bundle

For React Native, Capacitor, Cordova, and other JS-driven shells, Java-side findings are almost always incomplete. The Java side typically:

- declares a `MainActivity` that wraps a JS runtime
- forwards intent data / cookies / file paths into JS via native bridges with **no validation in Java**
- delegates trust to the JS layer

A bare Java-side finding ("activity hands intent.getData() to JS, no scheme validation") is **unactionable until you read the JS handler**. Most of the time the JS layer enforces its own allowlist; sometimes it does not. Without the JS-side trace, the hypothesis is `needs_route_map_validation` at best.

### 7.5a — Identify the bundle format first

```bash
find findings/decompiled/<pkg>/resources/assets -maxdepth 1 \
  \( -name 'index*.bundle*' -o -name '*.jsbundle' \) -exec file {} \;
```

Three outcomes drive different recipes:

- **Plain JS** (`ASCII text`, `data`, or `UTF-8`) → recipe 7.5b (prettier). Most older RN apps and Capacitor/Cordova ship plain JS.
- **Hermes bytecode** (magic `c6 1f bc 03`, `file` reports `data`) → recipe 7.5c (hbctool disasm). Default for newer RN; **observed on MetaMask, Trust Wallet, Bitpay, Coinbase, Discord**.
- **Encrypted / packed bundle** → expect `setBundleAssetName` to point at an alternate file and a custom loader; treat as dynamic-only and note in `missing_evidence`.

### 7.5b — Plain JS bundle

```bash
BUNDLE=findings/decompiled/<pkg>/resources/assets/index.bundle
mkdir -p findings/<pkg>/js-analysis
npx --yes prettier@3.3.3 --parser babel --print-width 120 "$BUNDLE" \
  > findings/<pkg>/js-analysis/index.pretty.js
wc -l findings/<pkg>/js-analysis/index.pretty.js
JSDIR=findings/<pkg>/js-analysis
```

### 7.5c — Hermes bytecode bundle

```bash
pipx install hbctool 2>/dev/null  # one-time
BUNDLE=findings/decompiled/<pkg>/resources/assets/index.android.bundle
JSDIR=findings/<pkg>/js-analysis
mkdir -p "$JSDIR"
hbctool disasm "$BUNDLE" "$JSDIR/hbc"
# disasm produces a string table + per-function HBC instructions; the string table
# is the single most useful artifact for tracing bridge names and route keys.
rg -nN -e 'YOUR_BRIDGE' -e 'addEventListener' -e 'Linking' "$JSDIR/hbc/strings.json" | head
```

String-table grep is fast: route keys (`open_url`, `_PATHS_TO_SCREENS_MAP`, `DEEP_LINK_*`, scheme literals like `"metamask"`, `"trust"`, `"wc"`) live there verbatim. Cross-reference hits against the HBC function bodies that load them.

### 7.5d — Grep the bridge surface, then follow the data backwards

For each Java-side bridge you flagged (`emitNewIntentReceived`, `RNCookieManagerAndroid`, `RNFileViewer`, `addJavascriptInterface` name, etc.), find in `$JSDIR`:

1. **Where the bridge symbol is referenced** (`rg -n RNCookieManagerAndroid $JSDIR`).
2. **Whether the surrounding module wraps it and whether anyone imports the wrapper.** A bridge that is wrapped but never called is `unused_bridge_attack_surface`, not a live finding.
3. **What controls the arguments at every call site.** Trace backwards: are URL/path/cookie values derived from intent data, remote config, or static constants? If they trace back to `Linking.addEventListener('url', ...)`, you are reading the deep-link handler — capture the allowlist there.
4. **The allowlist / router map.** Look for `*_PATHS_TO_SCREENS_MAP`, `ROUTES`, `DEEP_LINK_*`, `ALLOWED_HOSTS`. A strict allowlist downgrades the Java-side finding to `hardening_only`. A `contains`/`startsWith`/regex check is a real bug.

### What a clean trace looks like

```
intent.getData() (Java)
  -> emitNewIntentReceived(data) (Java bridge)
    -> Linking 'url' event in JS (module ABC)
      -> if (scheme === 'offlinepay') validateHost('merchant.app') -> validatePath0('navigate') -> screenMap[name] || fallback
      -> if (scheme === 'https') validateHost(APAY_DOMAIN) -> ...
      -> else metric('InvalidProtocol')
```

The chain is only as strong as its weakest validator. Record the JS-side validators in the hypothesis evidence so the same finding can be re-evaluated against the next bundle version.

### Pre-bundle hypotheses are wrong half the time

A Java-side static finding for a React Native or Capacitor/Cordova app should default to `confidence_tier=needs_route_map_validation` until the JS trace lands. Promoting it to `strong_static_chain` without the JS layer review produces over-grade reports.

## Step 7.6 — Flutter/Dart AOT apps: trace into `libapp.so`

Mirror of 7.5 for Flutter/Dart-AOT shells. The Java/Kotlin side declares a `FlutterActivity` (or subclass) plus a wall of MethodChannel registrations in `configureFlutterEngine` / `o(flutterEngine)`; every routing decision is in the AOT-compiled Dart in `lib/<abi>/libapp.so` (plus `flutter_assets/kernel_blob.bin` for the kernel snapshot).

A Java-side finding ("MainActivity forwards `intent.getDataString()` into the Flutter engine without validation") is **unactionable until you read the Dart handler**. Default grade: `needs_route_map_validation`.

### 7.6a — Detect and locate

```bash
find findings/decompiled/<pkg> -path '*lib/*/libapp.so' -o -name 'kernel_blob.bin' 2>/dev/null
file findings/decompiled/<pkg>/resources/lib/arm64-v8a/libapp.so 2>/dev/null
```

Presence of `libapp.so` plus `libflutter.so` confirms Flutter AOT.

### 7.6b — Recover Dart structure with blutter

[`blutter`](https://github.com/worawit/blutter) reverse-engineers `libapp.so` into class names, methods, and string constants. One-time setup is non-trivial (clones Dart SDK headers per Flutter version); cache the output.

```bash
# https://github.com/worawit/blutter — Python 3 + Dart SDK headers
blutter findings/decompiled/<pkg>/resources/lib/arm64-v8a/ findings/<pkg>/dart-analysis/
```

Produces:

- `objs.txt` — class names + field layout
- `pp.txt` — every Dart object literal (string constants, including route keys, allowlists, scheme literals)
- `radare2/<arch>/blutter_frida.js` — Frida hook scaffold for dynamic validation

Grep `pp.txt` for the same things you'd grep a JS bundle for:

```bash
rg -nN -e 'safepalwallet' -e 'wc:' -e 'allowedHost' -e 'PATHS_TO' \
       findings/<pkg>/dart-analysis/pp.txt | head
```

### 7.6c — Match MethodChannel names

List every Java-side `new MethodChannel(messenger, "<name>")` from the Flutter engine setup; each name is an entry point exposed to Dart. Find the Dart-side handler for each (blutter naming follows the original class path):

```bash
# Java side — names registered in MainActivity.configureFlutterEngine / o(flutterEngine)
rg -n 'new C6.o\|new MethodChannel\|new EventChannel' findings/decompiled/<pkg>/sources \
   | rg -o '"[^"]+"' | sort -u
# Dart side — find the corresponding handler
rg -nN '<channel_name>' findings/<pkg>/dart-analysis/
```

The Java-to-Dart routing topology is the equivalent of the RN router map. Strict allowlist in Dart → `hardening_only`. Loose check → real bug.

### When blutter is unavailable

Fall back to:

- `strings -a libapp.so | rg -e 'scheme://' -e 'PATHS_TO' -e 'allowedHost'` — quick smoke; misses structure but surfaces route keys.
- `radare2 -A libapp.so` + manual class-walk on the addresses blutter would have named.
- Dynamic-only: Frida hook on the MethodChannel call-site and capture every (method, args) pair as you fuzz the deep-link surface.

## Step 8 — FlowDroid for lifecycle-aware taint when stakes warrant it

For complex source→sink claims spanning the Android lifecycle, FlowDroid ([blog](https://blogs.uni-paderborn.de/sse/tools/flowdroid/), [github](https://github.com/secure-software-engineering/FlowDroid)) is the canonical engine. Cost is real (Java, `android.jar` for the API level, sources/sinks config), so only escalate when impact and evidence demand it.

Reserve FlowDroid for hypotheses where:

- impact is account takeover / payment / identity
- the chain crosses lifecycle/callback boundaries
- Semgrep + Joern + CodeQL still can't prove or disprove the flow

## Step 9 — write hypotheses, normalize, validate

Use the schema in `references/output-schema.md`. One JSONL record per candidate; supply a `class` slug to auto-fill MASVS/CWE/MASWE tags. Then:

```python
# MCP tool — emit deterministic Markdown report + JSONL appendix.
normalize_semantic_findings(
    inputs=["findings/hypotheses.jsonl"],
    output_format="markdown",
    out="findings/report.md",
)
```

For authorized validation, derive ADB commands from `androguard.json` (decoded schemes/hosts/components):

```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'myapp://route?dn_probe=1' \
  com.target.package
adb logcat -d | rg -i 'target|webview|deep'
```

Validation tiers (from `references/workflow.md`):

- `tier0_static_only`
- `tier1_local_device_no_live_backend`
- `tier2_test_account_or_qa_backend`
- `tier3_explicit_production_authorization`

## Bug classes to prioritise

Detailed patterns in `references/bug-classes.md`. Summary:

- **Deep link / router bugs** — host validation by `contains`/`startsWith`, stale allowlisted partner domains, `next`/`redirect`/`returnUrl` reaching `WebView.loadUrl` with auth context, OAuth callback abuse. Background: [Android deep-link risks](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks), [Oversecured deep-link research](https://oversecured.com/blog/android-deep-link-vulnerabilities), [MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/).
- **Intent redirection / private component reachability** — exported component reads `getParcelableExtra`/nested intent and `startActivity`, preserving data URI/flags/grants ([Android guidance](https://developer.android.com/privacy-and-security/risks/intent-redirection), [CodeQL](https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/)).
- **WebView trust-boundary bugs** — attacker-influenced URL plus `setJavaScriptEnabled(true)` + `addJavascriptInterface` / `postWebMessage` + auth cookies/headers; `shouldOverrideUrlLoading` of `intent://` or app routes ([Android unsafe URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading), [native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges), [CodeQL](https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/)).
- **Dirty Stream / share-target file overwrite** — exported share/import target trusts `content://` provider display names, `EXTRA_TITLE`, or caller paths and writes into app-private storage; impact depends on later trusted use of overwritten config/token/code/cache ([Microsoft Dirty Stream](https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/), [Android filename guidance](https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename)).
- **Provider SQLi / provider file exposure** — exported provider with no signature permission accepts caller-controlled selection/projection/path/table routing or broad FileProvider paths; distinguish exported boilerplate from sensitive rows/files reachable.
- **APK-discovered backend API bugs** — APK reveals mobile-only REST/GraphQL/gRPC/WebSocket endpoints, DTOs, feature flags, object IDs, request-signing, and workflow verbs that map to BOLA/IDOR, mass assignment, SSRF/open redirect, state-machine bypass, or webview-bridge-to-native-API actions. Static APK evidence is usually `needs_backend_validation` until tested with authorized accounts/QA backend.
- **Auth/session/client-state bugs** — login decisions from mutable local state, client-validated reset/invite/magic tokens, hardcoded keys participating in account-state operations, premium/admin gates from local booleans.
- **Non-prod host / endpoint reachable from production (leaked-host chain)** — production APK ships a QA/stage/dev/sandbox hostname *plus* the selector logic to pick it. Triage with the four-category gate matrix (A1 BuildConfig / A2 feature flag / A3 intent extra / A4 build-pin via Dagger or bootstrap initializer). Empirically ~7% of leaked hosts in popular apps are real `feature_flag_gated` chains, ~21% are A4 build-pinned, ~71% are R8-leftover dead strings. Full runbook in `references/leaked-host-triage.md`.

Historical pattern reference: `references/historical-patterns-2023-2026.md`. It is intentionally search-biased toward public CVEs/writeups; use it for pattern inspiration, not prevalence claims. APK-to-backend references: `references/apk-to-backend-api.md`, `backend-rich-apk-workflows.md`, `feature-flag-mining.md`, `request-signing-and-attestation.md`, `workflow-state-machines.md`, and `hybrid-bridge-to-backend.md`.

Every hypothesis must connect entrypoint → source → trust boundary → sink → impact. If one is missing it stays a hypothesis, not a finding. Record `missing_evidence` honestly.

## Scale strategy

- Inventory first, decompile second. Most APKs in a corpus never need JADX.
- **Detect runtime kind before JADX** (Step 3 probe). If the app is React Native or Flutter AOT, the Java pass is a thin layer; budget time for 7.5 / 7.6 up front, not after.
- **Sort the JADX queue by class count ascending.** Cheap APKs finish first; heavy APKs (banking/wallet, 25k+ classes, `-Xmx6g`/`-Xmx8g`) run last and at lower parallelism. Failure of one heavy APK then doesn't starve the rest.
- Read **handfuls of files** per APK, not whole trees. Use `rg` + `androguard.json` exported/BROWSABLE components to pick which files.
- Skip `namespace_kind=known_library` unless first-party code supplies attacker-controlled data or sensitive context.
- Compare against Semgrep only after forming hypotheses, never before — scanners anchor discovery if you read them first.
- Deduplicate findings by `(package, entrypoint, source, sink, impact)`. `normalize_semantic_findings` does this for you.
- **JS/Dart-shell apps cluster** on similar Java-side patterns. After two or three per impact class, the recurring shape (e.g. all C_wallet wallets forward intent data to JS unchecked) becomes the class-level finding; per-APK reports should focus on the JS/Dart-side delta from the class baseline.

## Finding hypothesis contract

```json
{
  "title": "short impact-oriented title",
  "apk": "file.apk",
  "package": "com.example",
  "masvs": ["MASVS-PLATFORM"],
  "class": "deep_link_to_authenticated_webview",
  "entrypoint": "exported BROWSABLE Activity / scheme / host / receiver / provider",
  "source": "attacker-controlled value",
  "trust_boundary": "why the app should not trust it",
  "sink": "security-sensitive operation reached",
  "impact": "account takeover / token theft / private component access / auth bypass / data exposure",
  "evidence": ["file:line snippets, manifest facts, joern/codeql output paths"],
  "validation_plan": ["adb command, helper-app plan, test-account steps"],
  "scanner_gap": "not found | generic warning only | adjacent baseline finding | exact baseline finding",
  "confidence_tier": "confirmed_dynamic|strong_static_chain|needs_backend_validation|needs_route_map_validation|hardening_only|generic_library_noise",
  "validation_tier": "tier0_static_only|tier1_local_device_no_live_backend|tier2_test_account_or_qa_backend|tier3_explicit_production_authorization",
  "missing_evidence": ["what must be checked before exploitability can be claimed"]
}
```

## References (read on demand)

- `../../references/sources.md` — capability-root citation registry (industry standards, public CVE/research links, tool docs, internal-research provenance). Every external claim in the per-skill references resolves here.
- `references/bug-classes.md` — full pattern catalogue with grounding URLs.
- `references/leaked-host-triage.md` — runbook for non-prod hostnames shipped in production DEX (A1/A2/A3/A4 gate categories, outcome schema, known false-positive shapes).
- `references/workflow.md` — validation tier definitions and corpus-vs-targeted timing.
- `references/output-schema.md` — finding JSONL + corpus manifest schema.
- `references/joern-recipes.md` — Joern import + focused Android CPG queries.
- `references/codeql-recipes.md` — CodeQL Java/Kotlin DB build + Android query pack invocation.
- `references/scanners.md` — Semgrep/MobSF/APKHunt/ripgrep recipes for scanner-gap labelling.
- `references/corpus-acquisition.md` — AndroZoo / F-Droid / device extraction; pair with `../android-corpus-prep` for the DuckDB-on-Parquet selection path.
