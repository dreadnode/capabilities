# Semantic Android bug classes

Use this reference when reviewing `slices.jsonl` or turning a slice into a vulnerability hypothesis. The capability's bias is toward **impactful chains** that require app-specific reasoning and are likely to be missed or reduced to generic warnings by traditional scanners.

## Review frame

For every candidate chain, answer five questions:

1. **Entrypoint** — Which external actor can reach the code path? Browser, another app, share sheet, notification, push, exported component, content provider, app link, custom scheme, WebView navigation, or backend-controlled config?
2. **Source** — Which values are attacker-controlled? URI scheme/host/path/query/fragment, Intent action/data/categories/extras, nested Intent, file/content URI, JavaScript message, local mutable state, server redirect, or app config?
3. **Trust boundary** — What assumption is wrong? The caller is trusted, the URL is first-party, the component is internal, local state is authoritative, the user/account context is unchanged, the nested Intent is safe, or the domain remains owned.
4. **Sink** — What sensitive operation happens? WebView navigation with auth context, component launch, API request, account/session mutation, token generation/validation, file/provider access, JavaScript bridge call, or privileged SDK action.
5. **Impact** — What can the attacker actually accomplish? Account takeover, auth bypass, token theft, private component access, unauthorized action, file/PII disclosure, tenant/account confusion, or payment/entitlement abuse.

If one of the five is missing, keep the item as a hypothesis, not a finding.

## Deep link / router chains

Grounding:
- Android unsafe deep links: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
- OWASP MASTG deep link testing: https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/
- Oversecured deep link account takeover patterns: https://oversecured.com/blog/android-deep-link-vulnerabilities

High-value patterns:

- `BROWSABLE` Activity routes `Intent.getData()` into an internal router.
- Router accepts `url`, `redirect`, `next`, `returnUrl`, `callback`, `continue`, `target`, `path`, or `deeplink` parameters.
- Host validation uses `contains`, `startsWith`, `endsWith`, broad regex, string replacement, or URI parsing inconsistently.
- App Link/domain allowlist includes partner, staging, campaign, shortlink, or expired-looking domains.
- Deep link reaches OAuth, password reset, magic link, referral, wallet/payment, account settings, or support-chat flows.

Validation ideas:

- Try host-confusion payloads only in authorized test context: `https://trusted.com.attacker.tld/`, `https://trusted.com@attacker.tld/`, punycode/mixed-case/encoded-dot variants.
- Check whether `assetlinks.json` exists for App Links and whether custom schemes are used for OAuth callbacks.
- For stale domains, use passive DNS/WHOIS/HTTP status as evidence; do not take over domains unless explicitly authorized.

## Intent redirection / private component reachability

Grounding:
- Android intent redirection risk guidance: https://developer.android.com/privacy-and-security/risks/intent-redirection
- CodeQL intent redirection: https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/
- Element Android intent-redirection case study: https://www.shielder.com/blog/2024/04/element-android-cve-2024-26131-cve-2024-26132-never-take-intents-from-strangers/

High-value patterns:

- Exported component reads nested Intent via `getParcelableExtra`, `getSerializableExtra`, `Bundle.get`, or `Intent.parseUri` and launches it.
- Forwarded Intent preserves data URI, component name, flags, clip data, or grant flags.
- The target is private or performs privileged actions under the victim app identity.
- The exported component has no caller permission/signature check.
- Router actions can open internal screens that normally require login, KYC, 2FA, entitlement, or user confirmation.

Validation ideas:

- Build an explicit proof plan with `adb shell am start` for simple extras or a small helper app for nested Intent/Parcelable cases.
- Watch for `FLAG_GRANT_READ_URI_PERMISSION`, `ClipData`, and content provider access.
- Distinguish “can launch screen” from “can complete privileged action”; impact requires the latter or strong evidence it is reachable.

## WebView trust-boundary chains

Grounding:
- Android unsafe WebView URI loading: https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading
- Android WebView native bridges: https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges
- CodeQL unsafe Android WebView fetch: https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/
- Home Assistant Android WebView case: https://securitylab.github.com/advisories/GHSL-2023-142_Home_Assistant_Companion_for_Android/

High-value patterns:

- External URL reaches `WebView.loadUrl`, `postUrl`, `loadDataWithBaseURL`, or a network request used to populate WebView content.
- `setJavaScriptEnabled(true)` and `addJavascriptInterface` coexist with externally controlled navigation.
- App attaches auth headers/cookies, user identifiers, bearer tokens, device IDs, or payment/session context to the request.
- `shouldOverrideUrlLoading` handles `intent://`, custom schemes, or app-internal routes.
- Bridge methods expose native actions, token/account data, file access, or privileged SDK calls.

Validation ideas:

- Confirm whether cookies/auth headers are present for attacker-influenced URL loads.
- Enumerate bridge method names and argument types from decompiled code.
- Mark as lower confidence when URL control exists but no authenticated context or sensitive bridge is found.

## Auth/session/client-state chains

Grounding:
- OWASP MASVS-AUTH (Authentication and Session Management): https://mas.owasp.org/MASVS/05-MASVS-AUTH/
- MASTG-TEST-0017 Testing Stateful Session Management (Android): https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/
- CWE-602 Client-Side Enforcement of Server-Side Security: https://cwe.mitre.org/data/definitions/602.html
- CWE-287 Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html

High-value patterns:

- Login/session/entitlement decisions derived from `SharedPreferences`, SQLite, files, cache, extras, or feature flags.
- User ID, tenant ID, role, account ID, phone/email, or organization ID accepted from an Intent/deep link without server revalidation.
- Password reset, invite, promo, or magic-login tokens generated/validated entirely client-side.
- Hardcoded key participates in token signing/encryption, request signing, password reset, or account recovery.
- Local state gates privileged screens but backend calls lack matching authorization checks.

Validation ideas:

- State whether validation is static-only, local-device dynamic, or backend-dependent.
- For backend-dependent claims, require a test account and explicit authorization.
- Avoid overclaiming from local bypass alone; prove or plan how to prove server-side acceptance.

## Deep link to account-state-change (no WebView)

Grounding:
- OWASP MASVS-PLATFORM + MASVS-AUTH: https://mas.owasp.org/MASVS/06-MASVS-PLATFORM/ , https://mas.owasp.org/MASVS/05-MASVS-AUTH/
- MASTG-TEST-0028 Testing Deep Links: https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/
- MASWE-0058 Insecure Deep Links: https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0058/
- CWE-352 Cross-Site Request Forgery (equivalent for mobile deep-link CSRF): https://cwe.mitre.org/data/definitions/352.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html

Distinct from the deep-link-to-WebView class: there is no WebView at all. The sink is a server-side state-changing API call (device registration, family/team invite accept, contact share-add, subscription enroll, account-key rotation, magic-link consume) that the app fires from a `LaunchedEffect` / `onCreate` / coroutine `launch` as soon as the BROWSABLE handler resolves the path.

High-value patterns:

- BROWSABLE Activity routes `Intent.getData()` query parameters straight into `NavDirections` arguments (`Bundle.putString("id", ...)`).
- The destination Composable / Fragment has a `LaunchedEffect` whose only precondition is `id != null && key != null` and which calls a ViewModel action that hits an "accept" / "complete" / "register" endpoint.
- The endpoint accepts attacker-supplied identifiers / keys / tokens with no server-side requirement that the *sender* device generated them.
- The pre-screen unlock prompt (if any) shows only a generic "unlock the app" string — not "you are about to register a new device" or "you are accepting an invite from X".

**Illustrative example (internal corpus observation, password-manager class):** a `dashlane://mplesslogin?id=&key=` deep-link auto-completes a device-to-device registration in Dashlane v6.262 (2026-05) — the Java side runs the full transfer-completion crypto flow without an explicit confirmation modal between the BROWSABLE handler and the `MplessCompleteTransferService.execute(...)` call. This is a static-analysis finding from internal corpus research, not a vendor-confirmed advisory; the *shape* (BROWSABLE → `LaunchedEffect` → state-changing API with deep-link args) is what to look for in any password-manager / 2FA / identity-class APK. See `../../../references/sources.md` for the provenance framing.

Validation ideas:

- Distinguish "deep link can open the screen" from "deep link can complete the action" by reading every `LaunchedEffect` / `init` / coroutine `launch` on the destination screen for **side-effect calls that take the deep-link args directly**.
- For Compose Navigation, the `NavDirections.getArguments()` Bundle is the trust boundary — anything passed in there becomes ViewModel input on next composition. Trace every consumer.
- A confirmation gate that is a *button* in the same Composable is still a gate — the bug is only present when the action fires before any user interaction on the destination screen.

## APK-discovered backend API chains

Use this class when the APK is the map to a rich backend, and the likely vulnerability is a web/API issue rather than an on-device issue. Full workflow: `apk-to-backend-api.md`.

High-value patterns:

- APK reveals mobile-only endpoint families, GraphQL operations, gRPC/protobuf stubs, WebSocket events, feature-flagged routes, or request DTOs that are not visible from the public web app.
- Object IDs cross authorization boundaries: `userId`, `accountId`, `tenantId`, `orgId`, `familyId`, `childId`, `vaultId`, `deviceId`, `orderId`, `paymentId`, `roomId`, `messageId`, `attachmentId`.
- Workflow verbs can be called out of order or under a different account context: `accept`, `approve`, `complete`, `activate`, `claim`, `redeem`, `recover`, `reset`, `verify`, `bind`, `pair`, `link`, `migrate`, `transfer`.
- Request DTOs contain privilege-bearing or server-owned fields: `role`, `isAdmin`, `verified`, `ownerId`, `tenantId`, `status`, `state`, `price`, `discount`, `scope`, `permissions`, `entitlements`.
- URL/callback parameters are submitted to backend fetchers or redirectors: `redirect_uri`, `returnUrl`, `callback`, `webhook`, `avatarUrl`, `imageUrl`, `preview`, `unfurl`, `importUrl`, `sourceUrl`.
- WebView/JS bridge can invoke native API clients with mobile auth/session/device context, turning a web-origin bug into a backend action.
- Request-signing layers expose replay/confusion surfaces: HMAC canonicalization, nonce/timestamp handling, device ID binding, attestation bypass/fallback.

Validation ideas:

- Static endpoint + DTO + object model evidence is a **backend hypothesis**, not a confirmed web vuln.
- Label most candidates `needs_backend_validation`; proving BOLA/workflow/mass-assignment requires authorized test accounts, QA backend, or explicit production authorization.
- Prefer read-only probes first: object metadata, status endpoints, preview endpoints, non-destructive GraphQL queries.
- For destructive flows (payment, transfer, invite, device pair, account recovery), write a validation plan instead of probing unless scope is explicit.
- Record whether the APK provides enough information to reconstruct required headers/signatures without extracting real user secrets.

## Content/file/provider exposure chains

Grounding:
- Microsoft Dirty Stream: https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/
- Android untrusted ContentProvider filename guidance: https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename
- ownCloud Android provider SQLi / path validation case: https://securitylab.github.com/advisories/GHSL-2022-059_GHSL-2022-060_Owncloud_Android_app/

High-value patterns:

- Exported `ContentProvider`, broad `FileProvider` paths, path traversal in provider/openFile logic, or URI grants forwarded to nested Intents.
- Share/import flows copy attacker-controlled URIs into private storage or expose private files back through share targets.
- **Dirty Stream shape:** exported `ACTION_SEND` / `ACTION_SEND_MULTIPLE` / import target reads a malicious `content://` URI, trusts `OpenableColumns.DISPLAY_NAME`, `Intent.EXTRA_TITLE`, or caller-supplied path, then writes under `cacheDir`, `filesDir`, databases, shared prefs, WebView state, plugin/config, or code-loading directories.
- **Provider SQLi shape:** exported provider without signature permission feeds caller-controlled `selection`, `projection`, `sortOrder`, URI segment, or table key into `rawQuery`, `execSQL`, `SQLiteQueryBuilder`, or custom query construction without `setStrict` / `setProjectionMap` / hardcoded table routing.
- Provider access depends on path/account parameters supplied by the caller.
- Logs, databases, cached auth material, attachments, health/financial documents, message media, shared preferences, or app configuration are reachable.

Validation ideas:

- Use read-only provider queries in a local emulator/test device where authorized.
- For Dirty Stream, use a local helper app/provider with a malicious display name; do not require a live backend.
- Separate “provider exported” from “sensitive rows/files reachable.”
- Separate “can write a file” from impact; impact requires showing that overwritten file is later trusted, executed, uploaded, or used as auth/config state.
- Record required permissions and whether signature permissions block external callers.

## Non-prod host / endpoint reachable from production (leaked-host chain)

Grounding:
- OWASP MASVS-CODE (Code Quality and Build Settings) + MASVS-NETWORK: https://mas.owasp.org/MASVS/08-MASVS-CODE/ , https://mas.owasp.org/MASVS/04-MASVS-NETWORK/
- MASTG-TECH-0025 Automated Static Analysis (scanner caveats apply): https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0025/
- CWE-1188 Insecure Default Initialization of Resource: https://cwe.mitre.org/data/definitions/1188.html
- CWE-489 Active Debug Code (the build-config sub-pattern): https://cwe.mitre.org/data/definitions/489.html

Distinct from "secret in DEX" or "hardcoded URL": the production APK *intentionally* ships a non-prod hostname (QA, staging, dev, sandbox, dogfood, canary, internal) and *also* ships the selector logic to pick it. The question is whether the selector is reachable by a third party in a production-signed install.

For the full triage runbook, outcome schema, and known false-positive patterns (R8-retained dead objects, regex consumers, OAuth scope literals), see `leaked-host-triage.md`.

The gate-classification matrix. Categories A1/A2/A3 are runtime reads; A4 is structurally distinct (build-time / startup-time pin) and surfaced during a leaked-host triage pass on popular Google Play apps — internal corpus observation; see `../../../references/sources.md` for provenance.

| Gate category | Resolves at | Third-party reachable? | Grade |
|---|---|---|---|
| **A1** `BuildConfig.DEBUG`, `isDevDebug()`, `isDebug()` | runtime, but build-pinned constant after R8 | no | `build_config_gated` / production-safe |
| **A2** server-flippable feature flag (ECS, LaunchDarkly, Split.io, FirebaseRemoteConfig, Statsig, Optimizely, custom config) | runtime, vendor-controlled | partially — vendor's flag console can target arbitrary users | `feature_flag_gated` / **promote** to `strong_static_chain` + `tier2_test_account_or_qa_backend` |
| **A3** intent extra, deep-link query param, exported settings-pref writer | runtime, third-party-controlled | yes | `intent_extra_or_query_param_gated` / **promote** to `strong_static_chain` + `tier1_local_device_no_live_backend` |
| **A4** Dagger compile-time `Factory.bind*`, app-startup `Initializer` that overrides persisted state, or post-R8 build-flavor string compare (`"release" == "bet"`) | build time / cold start | no | `build_config_gated` / production-safe |

A4 sub-patterns:

- **A4-dagger**: a `dagger.internal.Factory` whose `bindXxx` / `provideXxx` returns a hard-wired enum (`return new FixedEnvironmentRepository(QaMode.PRODUCTION)`). No runtime read; the dagger graph for the release flavor cements the value.
- **A4-bootstrap**: an `androidx.startup.Initializer` / `EagerInitializer` / `Application.onCreate` calls `setConfig(compileTimeValue)` with a flag that explicitly *ignores* any persisted user state on every cold start. Even if an exported settings activity exists and writes the env SharedPreferences value, the bootstrap initializer reverts it before the first network call.
- **A4-flavor**: a `"release" == "bet"` literal compare (R8 substitutes the flavor string per build). The production flavor evaluates false; the gate writers inside are dead.

A4 is a stronger guarantee than A1 because A1 is at least observable in the bytecode as a runtime read (`BuildConfig.DEBUG.get()` style), whereas A4 either disappears in dagger's generated factory (no runtime read at all) or reverts at startup. Recording A4 vs A1 in `gate_evidence` helps the next pass spot the same shape faster.

**Illustrative outcome distribution** from an internal corpus pass over 14 popular Google Play apps that shipped a non-prod hostname literal in DEX (static analysis only; provenance per `../../../references/sources.md`):

- 1 / 14 was a real `feature_flag_gated` shape — production banking app using a Split.io string flag (`mobl_AEMService_QAEnvironment` in Chase Mobile, swapping AEM content-CDN hosts among 4 QA tiers).
- 3 / 14 were A4 build-pin: eBay (A4-dagger, `EnvironmentRepositoryModule_BindEnvironmentRepositoryFactory` → `QaMode.PRODUCTION`), FitBit (A4-bootstrap, `HttpConfigInitializer` calls `initializeEnvironmentConfig(_, /*z=*/false)`), ESPN (A4-flavor, `if ("release" == "bet")`).
- 10 / 14 were `unreachable` (R8-leftover Kotlin top-level objects, regex consumers, OAuth scope literals, JSON fixtures).

High-value patterns:

- Production binary contains a `URLProvider` / `EnvironmentManager` / `BackendEnvironment` / `Endpoints` enum with 3+ entries (typically `PROD`, `STAGE`, `DEV`/`QA`).
- The current environment is selected by reading a SharedPreferences string, a feature-flag client, or an enum-by-name lookup keyed off a SharedPreferences value.
- A consumer of the per-environment host loads attacker-controlled content into a WebView, video player, or content fragment renderer inside an authenticated session — the leak can chain into a CDN-content-control finding.
- The setter for the env field is reachable from a non-exported "ServerSettingsActivity" but a bootstrap initializer always overrides it (A4-bootstrap) — flag the gap but record as production-safe.
- The feature-flag service uses targeting by account ID, so flipping for one user does not flip for everyone — impact is bounded to the targeted user set but is not a per-device toggle.

Validation ideas:

- Static-only: record `gate_kind`, `gate_evidence`, and the consumer code path. Distinguish A1 from A4 sub-patterns in `gate_evidence`.
- Local device (tier1): for A3 only — use `adb shell am start` with the deep-link / intent extra, or build a small helper app to write the exported SharedPreferences value, then `adb shell am force-stop` + relaunch and inspect network traffic.
- Test account (tier2): for A2 only — request a targeted flag value from the vendor's console for an authorized test account and observe.
- Do not probe live QA hostnames without explicit per-target authorization; the QA tier is usually *internal* (banking, retail, fitness) infrastructure not in public DNS.
