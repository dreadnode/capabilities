# Agent utility index

When you load an Android APK research skill, use this as the quick discovery map for what the capability can do. Prefer these utilities before inventing ad hoc commands.

The orchestration layer is the `android-research` MCP (10 tools listed below). Methodology — decompile, search, scan, query, taint — runs as bash + canonical CLIs because the heap-tier table, rule-pack ensemble, query recipe, and pattern selection *are* the value. See `workflow.md` § "Why bash, not MCP" for the rationale per upstream tool we considered.

## Environment probe

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Probe which underlying CLIs are reachable | `inventory_status` MCP tool | dict: uv / apkid / aapt2 / jadx / semgrep / joern / codeql / adb / hbctool / blutter status | Once per session, at start. Tells you which skill steps will work end-to-end. |

## Corpus and manifest triage

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Inventory APKs with manifest/components/APKiD | `run_corpus_inventory` MCP tool | `apks/<sha>/{inventory,androguard,apkid,status}.json`, `attack_surface.jsonl` | First pass over one or many APKs. |
| Extract one row per component | `extract_components` MCP tool | `components.jsonl` | After inventory, before decompile, for component-level ranking. |
| Rank exported/BROWSABLE/share/provider components | `rank_components` MCP tool | `components_ranked.jsonl`, `components_ranked.md` | Build the component inbox for broad corpus or impact-class pass. |
| Detect runtime kind | `detect_runtime_kind` MCP tool | dict with `runtime_kind` in {`native`, `react_native_hermes`, `flutter_aot`, ...} | Always before JADX; decides JS/Dart follow-up and heap budget. |

## Protector triage (when APKiD flags packing)

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Detect DexProtector / Promon Shield signals | `detect_protector` MCP tool | dict with `protector`, `confidence`, `triage_strategy`, `artifacts.dexprotector_unpack_supported` | Whenever APKiD reports a packer hit or `.dat` blobs appear in `assets/`. |
| Static unpack of libdp.so (arm64-v8a) | `dexprotector_unpack` MCP tool | recovered `libdp.so` ELF | Only when `detect_protector` reports `dexprotector_unpack_supported=true`. |

## Decompile and source triage

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Decompile APK | `jadx --show-bad-code --no-debug-info -d ...` (bash) | source/resource tree | Only for APKs you will read. Heap based on class count. |
| Run class-specific grep | `scripts/run_class_rg.sh <CLASS> "$SRC" findings/<pkg>/` (bash) | `rg-class-*.txt` | First reading pass when impact class is known. |
| Universal source/sink grep | recipe in `android-semantic-vuln-hunting` Step 4 (bash) | `rg.txt` / `triage/<pkg>.rg.txt` | Always after decompile; read files with source+sink clusters. |
| Scanner baseline | `semgrep --config p/security-audit --config p/mobsfscan --config r/java` (bash) | `semgrep.json` | After hypotheses form; label scanner gaps. The semgrep MCP can't express our multi-config ensemble — see workflow.md. |

## Backend-rich APK discovery

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Extract APK-derived API/backend map | `extract_api_map` MCP tool | endpoint/client/auth/signing/object/workflow/flag/bridge rows + richness summary | Any APK with Retrofit/Apollo/gRPC/WebSocket/Firebase, request signing, feature flags, tenant/account/device/payment/order concepts. |
| Rank backend-rich targets | `rank_backend_richness` MCP tool | backend-rich APK inbox | After extracting API maps across multiple APKs. |
| Feature flag mining | `references/.../feature-flag-mining.md` grep recipe | `rg-feature-flags.txt` | When remote config/experiments/flag names appear. |
| Request signing / attestation review | `references/.../request-signing-and-attestation.md` grep recipe | `rg-signing-attestation.txt` | When HMAC/signature/nonce/Play Integrity/cert pinning appears. |
| Workflow state-machine reconstruction | `references/.../workflow-state-machines.md` | workflow template | When verbs like accept/approve/complete/recover/pair/transfer appear. |
| Hybrid bridge to backend trace | `references/.../hybrid-bridge-to-backend.md` | bridge-to-API trace | RN/Flutter/WebView/Capacitor/Cordova apps where JS/Dart/web input reaches native API clients. |

## Hybrid/runtime follow-up

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Plain RN/JS bundle | `prettier` recipe in skill Step 7.5 (bash) | `index.pretty.js` | `react_native_js` or plain bundle. |
| Hermes bundle | `hbctool disasm` recipe in skill Step 7.5 (bash) | HBC strings/functions | `react_native_hermes`; grep strings first. |
| Flutter/Dart AOT | `blutter` recipe in skill Step 7.6 (bash) | Dart objects/strings | `flutter_aot`; fallback to `strings libapp.so`. |

## Deep evidence escalation

| Intent | Utility | Output | When to use |
|---|---|---|---|
| Focused call/data context | Joern recipes (bash) | CPG slices/query output | Only on shortlisted methods/files. The Joern MCP exists but its volume budget doesn't justify adoption — see workflow.md. |
| Path-precise Java/Kotlin evidence | CodeQL recipes (bash) | SARIF/query results | Public/MASVS-grade claims needing precise path evidence. |
| Lifecycle-aware taint | FlowDroid (bash) | taint paths | High-impact lifecycle-spanning claims. |
| Normalize hypotheses | `normalize_semantic_findings` MCP tool | Markdown/JSONL normalized report with MASVS/CWE/MASWE tags | Final report generation. |

## Quick decision tree

1. **Have APK(s), no decompile yet?** `inventory_status` → `run_corpus_inventory` → `extract_components` → `rank_components` → `detect_runtime_kind`.
2. **Single APK?** Use `android-targeted-assessment`; decompile only that APK.
3. **APKiD flagged a packer / `.dat` blobs in assets?** `detect_protector` first; if `dexprotector_unpack_supported`, run `dexprotector_unpack` before any other reading.
4. **Rich backend signs?** Run `extract_api_map` immediately after decompile and read `backend_richness.json`.
5. **Hybrid shell?** Do JS/Dart analysis before grading Java-side findings.
6. **Finding formed?** Add scanner baseline label, confidence tier, validation tier, missing evidence. Run `normalize_semantic_findings` for the report.
7. **Backend/API claim?** Default to `needs_backend_validation` and write a tier2/tier3 validation plan unless authorized testing already happened.
