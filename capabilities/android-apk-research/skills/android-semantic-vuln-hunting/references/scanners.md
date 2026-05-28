# Android scanner baseline recipes

Use these recipes after writing semantic hypotheses. Store outputs under `findings/baselines/<package>/`. The point is to label each hypothesis with `scanner_gap` (`exact` / `adjacent` / `generic` / `not found`).

## Semgrep with the Android packs

Public, free, fast, and explainable. The first scanner to run.

```bash
PKG=<package>
SRC=findings/decompiled/$PKG/sources

semgrep --config p/security-audit \
        --config p/mobsfscan \
        --config r/java \
        --metrics=off \
        --json --output findings/baselines/$PKG/semgrep.json "$SRC"
```

The `p/mobsfscan` registry pack ships MobSF's rule set as Semgrep rules and covers Android-specific Java/Kotlin/XML checks (hardcoded secrets, weak crypto, exported components, WebView misuse). `p/security-audit` adds language-agnostic security audit rules; `r/java` adds general Java correctness/security rules. Smoke-tested on the Stone JADX tree (89 results, dominated by `mobsf.mobsfscan.android.*` rules).

Useful flags:

- `--severity=ERROR` to suppress informational rules during baselining
- `--include='*.java'` if Kotlin decompilation is noisy
- `--metrics=off` for air-gapped runs

Interpretation:

- Strong on explainable pattern findings (`addJavascriptInterface`, `setJavaScriptEnabled(true)`, exported components without permissions).
- Weak on app-specific routing semantics and multi-hop chains.
- Each Semgrep hit is a *lead*. Map it to the closest hypothesis or note it as a generic finding for the appendix.

## MobSF (full static + dynamic platform)

Use the REST API when a MobSF server is reachable.

```bash
HASH=$(curl -sS -F "file=@app.apk" "$MOBSF_URL/api/v1/upload" \
        -H "Authorization:$MOBSF_API_KEY" | jq -r .hash)

curl -sS -X POST "$MOBSF_URL/api/v1/scan" \
     -H "Authorization:$MOBSF_API_KEY" \
     -d "scan_type=apk&hash=$HASH"

curl -sS "$MOBSF_URL/api/v1/report_json" \
     -H "Authorization:$MOBSF_API_KEY" \
     -d "hash=$HASH" \
     -o findings/baselines/<package>/mobsf.json
```

Interpretation:

- Good broad MASVS-aligned baseline (network security config, certificate pinning, manifest flags, dangerous APIs).
- Output is noisy and compliance-flavoured — use as scanner_gap labelling, not as the report.

## mobsfscan (CLI subset of MobSF rules)

When you don't have a MobSF server.

```bash
mobsfscan --json findings/decompiled/<package>/sources \
          --output findings/baselines/<package>/mobsfscan.json
```

Same rule provenance as MobSF static analysis; quicker to run, narrower coverage. Good for offline runs.

## APKHunt

When APKHunt and Go are installed.

```bash
go run apkhunt.go -p app.apk -l > findings/baselines/<package>/apkhunt.txt
# Bulk:
# go run apkhunt.go -m corpus/apks -l > findings/baselines/apkhunt-corpus.txt
```

Interpretation:

- MASVS-oriented static checks.
- Less structured output; preserve raw logs and summarize manually.

## Focused ripgrep baseline

Not a vulnerability detector. Useful to prove that semantic slices didn't miss obvious neighbourhoods.

```bash
rg -n -e 'getParcelableExtra' -e 'Intent\.parseUri' -e 'startActivity\(' \
       -e 'loadUrl\(' -e 'addJavascriptInterface' \
       -e 'setJavaScriptEnabled\s*\(\s*true' \
       -e 'SharedPreferences' -e 'Authorization' -e 'Bearer' \
       findings/decompiled/<package>/sources \
       > findings/baselines/<package>/high-value-grep.txt
```

## Scanner-gap labels

For each finding hypothesis, set `scanner_gap`:

- `exact baseline finding` — scanner reported same entrypoint/source/sink/impact class
- `adjacent baseline finding` — scanner saw a related risky API/component but not the chain
- `generic warning only` — scanner reported a broad category without an actionable chain
- `not found` — no relevant scanner output

For this capability, `adjacent` and `generic` are usually where the user's value lives.

## Known coverage gaps (auto-label `scanner_gap=not found`)

Bug-class shapes that the baseline scanners (`p/security-audit`, `p/mobsfscan`, `r/java`, MobSF, mobsfscan, APKHunt) do not currently cover. When a hypothesis matches one of these shapes, attach `scanner_gap=not found` without re-running the scanner — the absence is structural.

Examples in the right column are internal corpus observations (static-analysis only; see `../../../references/sources.md` for provenance framing). They illustrate the shape; they are not vendor-confirmed advisories.

| Bug class | Why scanners miss it | Illustrative example (corpus observation) |
|---|---|---|
| **Non-prod host swap via server-flippable feature flag** — production binary reads an ECS / LaunchDarkly / Split.io / FirebaseRemoteConfig / Optimizely / Statsig string and swaps a base URL to a QA/stage/dev host | No rule looks for `(feature-flag client call) → (string-switch with multiple URL constants) → (host substitution)`. The flag client itself is third-party SDK code, so noise rules suppress it. | Chase Mobile `mobl_AEMService_QAEnvironment` (Split.io), Outlook FIC token, Match P2P SDK (Mf.a featureToggle gating in-app toggle visibility). |
| **Non-prod host swap via intent extra without `BuildConfig.DEBUG`** — exported BROWSABLE activity reads a `boolean`/`String` extra and reaches a `setEndpoint` / `EndpointManager` sink | Semgrep rules for `addJavascriptInterface` and `intent.getData()` exist but none chain `getBooleanExtra → setEndpoint`. | Teams `enableCanaryEndpointForMTService`. |
| **Deep link to account-state-change (no WebView)** — `LaunchedEffect` on the destination Composable calls a server-side accept/complete/register API with deep-link args as inputs | All deep-link rules assume a WebView sink. | Dashlane `mplesslogin?id=&key=` (D_secret class). |
| **A4 build-pin patterns** — Dagger Factory binding a compile-time enum, bootstrap initializer overriding persisted env state, build-flavor literal compare | Scanners do not introspect dagger-generated factories or `androidx.startup.Initializer` startup graphs. | eBay `EnvironmentRepositoryModule_BindEnvironmentRepositoryFactory`, FitBit `HttpConfigInitializer`, ESPN `"release" == "bet"`. |
| **JS-bridge-to-native-API action** (RN / Capacitor / Cordova) — Java bridge wired but the auth-context-bearing argument flow is inside the JS/Dart bundle | Scanners do not read Hermes bytecode or Dart AOT. The Java side looks harmless. | Multiple C_wallet wallets observed in corpus runs. |
| **Request-signing or attestation bypass / fallback** — multi-tier signing canonicalization, HMAC-replay-safe-flag, attestation `IGNORE_ON_FAILURE` paths | Scanners look for hardcoded keys, not for fallback paths in signer code. | (no public empirical yet; pattern documented in `request-signing-and-attestation.md`). |

Pre-labelling these gaps speeds up reporting on subsequent passes — once a shape is in this table, future hypotheses of the same shape attach `scanner_gap=not found` automatically.

## Known-noise rules (auto-label `generic_library_noise`)

These rules fire on third-party SDK code that is the **expected design pattern**, not a finding. Pre-classify hits on these `(rule_id, file path glob)` pairs as `generic_library_noise` so they stop polluting per-class reports.

| Rule | File glob | Why it's noise |
|---|---|---|
| `mobsf.mobsfscan.webview.webview_javascript_interface` | `**/com/reactnativecommunity/webview/*.java` | RN `RNCWebView` registers `ReactNativeWebView` as its bridge by design; finding is the RN architecture |
| `mobsf.mobsfscan.webview.webview_debugging` | `**/com/reactnativecommunity/webview/*.java` | Debug-only call guarded by a build flag (`W6.a.*`); production builds are off |
| `mobsf.mobsfscan.android.secrets.hardcoded_api_key` | `**/nativeModules/NotificationModule.java`, `**/com/google/firebase/messaging/*.java` | FCM message-key constants (`google.message_id`, `gcm.notification.title`) trip the regex |
| `mobsf.mobsfscan.android.secrets.hardcoded_username/password` | `**/com/braze/**`, `**/com/intercom/**` | Hardcoded SDK field names match the secret-name regex |
| `java.lang.security.audit.unsafe-reflection.unsafe-reflection` | `**/kotlin/reflect/**`, `**/com/facebook/react/**` | Kotlin/RN runtime reflection is fundamental to the framework |
| `mobsf.mobsfscan.android.secrets.hardcoded_*` | `**/Dagger*HiltComponents*.java`, `**/*_Factory.java`, `**/*_MembersInjector.java`, `**/*_GeneratedInjector.java`, `**/R.java` | DI-generated companion classes and resource constants have field names like `username`, `password`, `apiKey` that match the secret-name regex but are never values |

A small jq filter keeps the report clean:

```bash
jq '.results | map(select(
  (.check_id == "mobsf.mobsfscan.webview.webview_javascript_interface" and (.path | test("com/reactnativecommunity/webview"))) or
  (.check_id == "mobsf.mobsfscan.android.secrets.hardcoded_api_key" and (.path | test("NotificationModule|firebase/messaging"))) or
  (.check_id == "mobsf.mobsfscan.webview.webview_debugging" and (.path | test("com/reactnativecommunity/webview"))) or
  ((.check_id | test("mobsf.mobsfscan.android.secrets.hardcoded_")) and (.path | test("Dagger.*HiltComponents|_Factory\\.java|_MembersInjector\\.java|_GeneratedInjector\\.java|/R\\.java$|/generated/")))
  | not
))' findings/baselines/<pkg>/semgrep.json > findings/baselines/<pkg>/semgrep-denoised.json
```

Empirical:

- C_wallet pass (MetaMask, RN-Hermes): Semgrep returned 4 findings; 3 fell into the RN-noise rows.
- D_secret pass (Dashlane / Proton Pass / LastPass, all native Kotlin): Semgrep returned 365 / 1,022 / 111 findings. The `hardcoded_username|password|api_key` rules alone produced 1,200+ hits across the three apps, almost all on Dagger/Hilt generated classes and Kotlin field metadata — the new Dagger/_Factory row catches the majority. The real-signal rules in `D_secret` are `webview_javascript_interface` (LastPass account-recovery + share, Dashlane NitroSso), `xmlinputfactory_xxe` (LastPass serialization), and `webview_debugging` (LastPass — needs release-flag check).

Extend the table as new noise patterns appear; the rule is that a finding belongs here only if it fires on **library code shipped by every app in the class** (or on framework-generated code) and the finding is **expected behaviour** for that library / generator.
