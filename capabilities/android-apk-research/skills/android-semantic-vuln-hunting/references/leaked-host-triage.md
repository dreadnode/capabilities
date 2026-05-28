# Leaked-host triage

Grounding:
- OWASP MASVS-CODE + MASVS-NETWORK: https://mas.owasp.org/MASVS/08-MASVS-CODE/ , https://mas.owasp.org/MASVS/04-MASVS-NETWORK/
- MASTG-TECH-0025 Automated Static Analysis (use these heuristics alongside scanner output, not in place of it): https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0025/
- CWE-1188 Insecure Default Initialization of Resource: https://cwe.mitre.org/data/definitions/1188.html
- CWE-489 Active Debug Code (build-flag sub-pattern A1/A4): https://cwe.mitre.org/data/definitions/489.html
- CWE-540 Inclusion of Sensitive Information in Source Code: https://cwe.mitre.org/data/definitions/540.html

Use this reference when a production APK ships a string literal in DEX that names a non-production hostname — QA, staging, sandbox, dev, preprod, internal, dogfood, canary, test, integration. The question this reference answers is **"can a third party reach a code path that swaps the production host for the leaked one, or is the string dead?"**.

Empirically grounded on an internal corpus pass over 116 popular Google Play apps, 26 of which shipped at least one non-prod hostname in DEX (static analysis only; see `../../../references/sources.md` for provenance). Of the 14 P1+P2 packages triaged in depth:

- **1 of 14 (~7%)** had a real reachable gate (Chase Mobile, server-flippable Split.io feature flag).
- **3 of 14 (~21%)** had a non-runtime build-pin gate (eBay Dagger, FitBit bootstrap initializer, ESPN build-flavor string compare). Production-safe in the released artifact.
- **10 of 14 (~71%)** had no reachable consumer at all — R8 retained the string inside a Kotlin top-level object with `@Metadata` but no DEX caller. Dead string.

**Take the regex hit as a weak prior, not a strong one.** Most leaked-host strings in popular apps are R8/minification leftovers. Walk the consumer chain before treating the hit as a candidate finding.

## When to use this reference

- Inventory scan or `attack_surface.jsonl` flagged one or more non-prod host literals in a production APK.
- A focused `rg` against decompiled sources found the host in a base-URL constant, a setter argument, or a URL-construction string.
- You have time-bounded budget (target: ~5–15 minutes per package) and want a comparable outcome record across many packages.

If the user is asking about a single APK they care about deeply, also load `android-targeted-assessment`; this reference is the methodology, the skill is the workflow shell.

## Outcome schema

Every package processed must resolve to exactly one of these:

| outcome | meaning | grade |
|---|---|---|
| `build_config_gated` | `BuildConfig.DEBUG`, build-flavor string compare, Dagger compile-time module binding, or bootstrap initializer overrides the gate every cold start | production-safe; record and move on |
| `feature_flag_gated` | server-flippable feature flag controls the branch (ECS, LaunchDarkly, Split.io, FirebaseRemoteConfig, Statsig, Optimizely, custom config service) | **latent** — same shape as the Chase Mobile Split.io CDN-swap and Outlook FIC token observations (internal corpus research); promote to `confidence_tier=strong_static_chain`, `validation_tier=tier2_test_account_or_qa_backend` (because validation requires the vendor's flag console / authorized account) |
| `intent_extra_or_query_param_gated` | any local app can flip the gate via intent extra, deep-link query parameter, or a SharedPreferences write reachable from an exported settings activity | **real** — same shape as the Microsoft Teams `enableCanaryEndpointForMTService` canary-endpoint observation (internal corpus research); promote to `confidence_tier=strong_static_chain`, `validation_tier=tier1_local_device_no_live_backend` |
| `unreachable` | no production code path reaches the string; dead constant, third-party SDK config, OAuth scope literal, host-detection regex, or R8 leftover | record as `hardening_only` or skip |

Only `feature_flag_gated` and `intent_extra_or_query_param_gated` are finding-shaped. The other two are negative-result closures.

## Gate categories

### A1 — `BuildConfig.DEBUG` / `isDebug()`

Classic build-flag gate, runtime read but resolves to a build-time constant after R8.

```bash
rg -n 'BuildConfig\.DEBUG|BuildConfig\.FLAVOR|isDebug\(\)|isDevDebug\(\)|isDev\(\)' "$SRC"
```

Production-safe. Record as `build_config_gated` / `outcome=production_safe`.

### A2 — Feature flag (server-flippable)

The gate reads a string/boolean/int from a feature-flag client. **This is the high-value finding shape this runbook is tuned for.**

```bash
# ECS / Firebase / LD / Split.io / Optimizely / Statsig / custom-named
rg -n 'getEcsSetting|LDClient\.|boolVariation|stringVariation|FirebaseRemoteConfig|Statsig\.checkGate|Statsig\.getConfig' "$SRC"
rg -n 'io\.split\.android|mClient\.getTreatment|split\.getTreatment|Split\.' "$SRC"
rg -n 'OptimizelyClient|optimizelyManager|featureToggle\.a\(|featureToggles?\.' "$SRC"
rg -n 'configurationManager\.|configClient\.|getRemoteString\|getRemoteBoolean' "$SRC"
```

When you find the gate, name the flag key, the consumer, and the hosts reachable on each branch. Promote to a hypothesis matching the JSON template at the end of this file.

**Validation tier:** `tier2_test_account_or_qa_backend` — confirming exploitability requires inspecting the vendor's flag-targeting console on an authorized account, not a local-device probe.

### A3 — Intent extra / query param / exported pref-writer

The gate reads `intent.getStringExtra(...)`, `getQueryParameter(...)`, or a SharedPreferences value that an exported settings-debug activity writes.

```bash
rg -n 'getStringExtra\(|getBooleanExtra\(|getQueryParameter\(|intent\.getData\(\)\.getQueryParameter' "$SRC"
# Check whether SharedPreferences writes for the env key are reachable from exported components
rg -n '"environment"|"env"|"baseUrl"|"apiHost"|"server"' "$SRC"
```

Cross-reference any SharedPreferences writer activity against the manifest (`aapt2 dump xmltree --file AndroidManifest.xml <apk>`) — if it's `exported=true` or declares an intent-filter, the gate is third-party-reachable.

**Validation tier:** `tier1_local_device_no_live_backend` — a helper app on the same device or an `adb shell am start` reproduces the chain.

### A4 — Build-pin patterns

Structurally distinct from A1 — these resolve at *compile* or *startup* time, not at every runtime read. Stronger guarantee than `BuildConfig.DEBUG` because there is no runtime read to flip. Documented from internal corpus research (provenance per `../../../references/sources.md`).

| Sub-pattern | Detection | Illustrative example (corpus observation) |
|---|---|---|
| **Dagger compile-time pin** | `dagger.internal.Factory` whose `bindXxx` / `provideXxx` method returns a hard-wired enum/value | eBay: `EnvironmentRepositoryModule_BindEnvironmentRepositoryFactory.bindEnvironmentRepository() { return new FixedEnvironmentRepository(QaMode.PRODUCTION); }` |
| **Bootstrap-initializer override** | `EagerInitializer` / `Application.onCreate` / app-startup `Initializer` calls `setConfig(compileTimeValue)` with a flag that explicitly ignores persisted user overrides | FitBit: `HttpConfigInitializer.a(context)` calls `serverEnvironmentInitializerO.initializeEnvironmentConfig(wmoVarY, /*z=*/false)`. With `z=false`, `setServerConfig(compileTimeEnvironment)` runs every cold start, overwriting any prior write. |
| **Build-flavor string compare** | `if ("release" == "bet")` or similar — R8 replaces the literal per flavor; the production build evaluates to `false` | ESPN: `if ("release" == "bet") { ... setQa(true) ... }` — only the `bet` flavor sets the QA SharedPreferences key |

```bash
# Dagger Factory binding a compile-time constant
rg -nE 'public static [A-Za-z<>]+ bind[A-Za-z]+\(\) \{\s+return new [A-Za-z]+\([A-Z_a-z\.]+\.[A-Z_]+\);' "$SRC"

# Bootstrap initializer that ignores persisted override
rg -n 'EagerInitializer|androidx\.startup\.Initializer|HttpConfigInitializer|EnvironmentInitializer' "$SRC"

# Build-flavor literal compare (post-R8 leftover)
rg -nE '"(release|debug|prod|qa|dev|staging|preprod)"\s*==\s*"' "$SRC"
rg -nE 'kotlin\.jvm\.internal\.Intrinsics\.areEqual\("[a-z]+"\s*,\s*"[a-z]+"' "$SRC"
```

Production-safe in the released artifact. Record as `build_config_gated` with `gate_evidence` naming the specific sub-pattern (A4-dagger, A4-bootstrap, A4-flavor) so the next pass can spot the same shape faster.

### A0 — Unreachable (the default outcome)

R8 + Kotlin Metadata retains the string but no DEX consumer reaches it. Common shapes:

- **Public Kotlin top-level object** with `@Metadata(k=1|2, ...)` containing the string. The Metadata annotation is what keeps the object alive; the field itself has zero readers. Empirically dominant in corpus runs across airline, streaming, productivity, news, and creative-tool apps.
- **Allowlist / regex** that *mentions* the host as a string literal in a `Pattern.compile` or `contains` check. The literal is consumed by a regex compiler / `String.contains`, not by an HTTP client. Slack's `(slack|slack-gov|slack-gov-dev|slack-mil-dev)` workspace-URL detector is the canonical example.
- **OAuth scope literal** that ends in `.ReadWrite` / `.Read` / `.default` / `-Internal.ReadWrite`. The "internal" suffix names a token scope, not a host modifier. Outlook's `https://substrate.office.com/User-Internal.ReadWrite` is a scope URI, not an endpoint.
- **JSON test fixture** containing the host in a documentation/sample payload string — e.g. a `TestJson.kt` that ships a stage CDN URL inside an HTML article fixture used only by an in-app dev-menu preview path.
- **Sample / fixture / seed data** for an unused feature.

To confirm a string is unreachable:

```bash
# Find the file that contains the literal
rg -nl "$HOST" "$SRC"

# Identify the enclosing class / object
# Walk back: does any other class import or reference this one?
grep -rn 'import .*<obfuscated-class-name>' "$SRC" | head
rg -n '<obfuscated-class-name>\b' "$SRC" | head

# If zero consumers, the string is unreachable.
```

Record as `unreachable` / `outcome=production_safe`. Do not promote.

## Per-package runbook (~5–15 minutes each)

For each package on a workqueue, repeat this loop. Strict time-boxing matters — the negative-result rate is high, so spend most of the per-package budget *deciding to close*, not *deep-reading*.

### Step 1 — decompile (cheap path)

```bash
SRC=findings/<run>/decompiled/<pkg>/sources
if [ ! -d "$SRC" ]; then
    APK=$(ls corpus/.../apks/<pkg>*.apk | head -1)
    # Heap tier by DEX class count — see android-semantic-vuln-hunting skill
    JAVA_OPTS="-Xmx6g" jadx --show-bad-code --no-debug-info \
        -d "findings/<run>/decompiled/<pkg>" "$APK"
fi
```

### Step 2 — locate consumers of the leaked host string

```bash
TARGET='static2-qa1.chasecdn.com'   # one host at a time
rg -nl "$TARGET" "$SRC"
```

Three shapes you will see:

- **(A) String literal embedded in a class constant.** Walk back to find what reads the constant. Usually a `URLProvider` / `EnvironmentManager` / `ConfigManager` / `BackendEnvironment` enum that returns one of N URLs based on a `currentEnvironment` field.
- **(B) String passed into `setEndpoint(...)` / `setBaseUrl(...)` / `setHost(...)`.** Walk back to find the caller of the setter. The caller is the gate.
- **(C) String only appears in a logging statement, JSON fixture, comment, or `Pattern.compile`.** Dead branch from a removed feature or a regex consumer. Record as `unreachable`.

### Step 3 — identify the gate

For shape (A) — environment selector:

```bash
# What populates the environment field?
rg -n 'currentEnvironment|envName|setEnvironment|getEnvironment|backendEnvironment|FitbitBackendEnvironment' "$SRC"
```

Classify the writer/source against the A1/A2/A3/A4 categories above.

For shape (B) — setter call:

```bash
rg -n 'setEndpoint\(|setBaseUrl\(|setHost\(|setServerConfig\(' "$SRC"
# For each call site, read 10 lines before to see what feeds the URL argument
```

Same A1/A2/A3/A4 classification on the caller.

For shape (A) when you cannot find a writer:

```bash
# Find any caller of the enclosing class/object
rg -n '<EnclosingClassName>\b' "$SRC" | grep -v 'kotlin\\.Metadata' | head
```

If the only references are inside the class itself or in `kotlin.Metadata` literals, the string is unreachable.

### Step 4 — record outcome

Append one line per package to `findings/<run>/leaked-host-workqueue.jsonl`:

```json
{
  "package": "com.chase.sig.android",
  "hosts": ["static2-qa1.chasecdn.com", "static2-qa2.chasecdn.com"],
  "consumer_path": "fN/C5672.mo9740() — switch on Split.io flag; consumed by nu/C15513.tn0",
  "gate_kind": "feature_flag_gated",
  "gate_evidence": "InterfaceC36156.mo71972('mobl_AEMService_QAEnvironment', 'default') reads a Split.io string flag; q1/q2/q3/q4 return matching QA hosts.",
  "outcome": "latent_flag",
  "notes": "AEM CDN serves video + JSON content to the authenticated banking session."
}
```

Valid `gate_kind` values: `build_config_gated`, `feature_flag_gated`, `intent_extra_or_query_param_gated`, `unreachable`.

Valid `outcome` values:

- `production_safe` — `build_config_gated` (any A1/A4 sub-pattern) or `unreachable`
- `latent_flag` — `feature_flag_gated`; needs vendor-flag-console or authorized backend test to confirm exploitability
- `local_reachable` — `intent_extra_or_query_param_gated`; the finding shape worth promoting to a `tier1` hypothesis

### Step 5 — promote (only if `latent_flag` or `local_reachable`)

Append a hypothesis to `findings/<run>/hypotheses/hypotheses.jsonl` matching the schema in `output-schema.md`. The Chase Mobile feature-flag and Microsoft Teams intent-extra observations referenced above are template shapes — copy their structure (illustrated by the JSON sample further down) so `normalize_semantic_findings` produces a clean report.

After the workqueue is processed, regenerate the report:

```python
# Tool — emits deterministic Markdown.
normalize_semantic_findings(
    inputs=["findings/<run>/hypotheses/hypotheses.jsonl"],
    output_format="markdown",
    out="findings/<run>/report.md",
)
```

## Biases to avoid

Empirical, repeated across internal corpus passes:

1. **Treating a regex hit as evidence of a real chain.** The leaked-host signal is ~7% strong-static-chain, ~21% build-pinned, ~71% dead. Cap per-package time accordingly — spend the *first* 2 minutes confirming the consumer exists at all.
2. **Stopping at A1.** "It's gated by `BuildConfig.DEBUG`" closes a chain; "it's gated by `BuildConfig.DEBUG` *and the writer SharedPref key is also exposed via an exported settings activity*" does not. Read the writer chain to the end before recording `build_config_gated`.
3. **Workqueue tunnel vision.** If a `local_reachable` or strong `latent_flag` finding lands in the first 3 packages, the temptation is to deep-read it before finishing the queue. Don't — the corpus-wide signal is the whole point. Finish the queue first; the strongest promoted hypothesis can be deep-read after.
4. **Cheap-path gravity (already-decompiled apps).** Apps you've already decompiled in a previous pass are tempting because the marginal cost is zero. Cap re-reads per pass; spend the freed time on a target class that hasn't been opened yet.
5. **Assuming the per-environment URLProvider is the only gate.** Some apps (eBay-class Dagger pin, FitBit-class bootstrap initializer) wire the environment value through Dagger / bootstrap-initializer paths that *override* any persisted/reachable value at startup. Always trace back to where the `currentEnvironment` field is *first written* in the process lifecycle.

## Reference checklist

- [ ] Pass uses inventory `attack_surface.jsonl` or equivalent regex over DEX strings to enumerate leaked hosts.
- [ ] Workqueue is finite, ranked, ~5–15 min per package, and explicitly *not* deep-read.
- [ ] Each package resolves to exactly one outcome.
- [ ] `build_config_gated` records distinguish A1 vs A4 sub-patterns.
- [ ] `feature_flag_gated` records name the flag key and the flag-service vendor.
- [ ] `intent_extra_or_query_param_gated` records name the intent extra / query param / SharedPref key and the exported component that writes it.
- [ ] `unreachable` records explain *why* the string is unreachable (R8-leftover, regex consumer, OAuth scope, JSON fixture).
- [ ] Hypotheses are appended only for the two promote-worthy outcomes.
- [ ] Final report regenerated via `normalize_semantic_findings`.
- [ ] Pass self-assessment records the outcome distribution and any new gate sub-pattern that appeared.
