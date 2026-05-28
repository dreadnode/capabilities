# Workflow recipes

This reference defines the corpus-scale and targeted workflows, validation tiers, and the tool-vs-CLI boundary.

## Discoverability first

Agents should not rely on memory for available APK-research utilities. Start with `agent-utility-index.md` when orienting, then choose the smallest applicable flow:

```bash
sed -n '1,220p' agent-utility-index.md
```

This index lists corpus inventory/ranking, runtime detection, focused rg profiles, backend API map extraction, backend richness ranking, feature-flag mining, request-signing review, workflow reconstruction, hybrid bridge tracing, scanner baselines, and report normalization.

## Corpus triage (1000s of APKs)

```text
run_corpus_inventory (parallel, resumable)
  → extract_components + rank_components for the component inbox
  → jadx -d only for the top batch
  → rg the focused source/sink set on first-party code
  → semgrep p/android baseline + scanner_gap labelling
  → joern for call/data context on the handful of methods that matter
  → optional codeql / FlowDroid escalation
  → finding JSONL → normalize_semantic_findings → report
```

Almost every APK in a corpus stops after `rank_components` or `rg`. JADX, Semgrep, Joern, CodeQL, and FlowDroid each cost real time; only escalate when the chain warrants it.

## Targeted assessment (one APK)

```text
run_corpus_inventory on the single APK
  → read androguard.json + apkid.json (no decompilation yet)
  → detect_protector (if APKiD flagged anything) → optional dexprotector_unpack
  → detect_runtime_kind → JADX heap budget + JS/Dart follow-up routing
  → jadx -d
  → rg over first-party code
  → semgrep p/android baseline
  → joern for call/data context where needed
  → optional codeql when path-precise evidence matters
  → hypothesis JSONL → normalize_semantic_findings → report
  → authorized adb validation
```

The pipeline is the same; the difference is depth on entrypoints, routers, and bridges.

## Validation tiers

Honest tiering matters more than confident-sounding writeups.

- **`tier0_static_only`** — code/manifest evidence only. Default tier.
- **`tier1_local_device_no_live_backend`** — ADB launch, emulator, logcat capture, no backend mutation. Safe when the user has a test device and tells you so.
- **`tier2_test_account_or_qa_backend`** — test account or QA backend interaction in scope.
- **`tier3_explicit_production_authorization`** — only with written authorization; produce a minimum-impact proof and stop.

Default to tier 0/1 unless the user has explicitly authorised higher tiers.

## Tool vs CLI boundary

The orchestration layer is wrapped in the `android-research` MCP. The methodology layer (decompile, search, scan, query, taint) stays in bash + canonical CLIs because the heap-tier table, rule-pack ensemble, query recipe, and pattern selection *are* the value — wrapping them as MCP tools would constrain the agent more than it enables.

| MCP tool | Why a tool, not bash |
|---|---|
| `inventory_status` | One-shot environment probe: uv, apkid, aapt2, jadx, semgrep, joern, codeql, adb, hbctool, blutter. Cheap to call once at session start. |
| `run_corpus_inventory` | Process pool, per-APK timeouts, SHA256-keyed artifact layout, resume, Androguard + APKiD orchestration. Bash equivalents drop on the floor at scale. |
| `extract_components` | Streams every `androguard.json` under an inventory dir and falls back to `aapt2 dump xmltree` for the multi-dex APKs that break Androguard 4.1.3. Output is one JSONL row per `(apk, type, name)` — the input to `rank_components`. |
| `rank_components` | Applies the risk-prior table and emits the component inbox. Determinism + the read-budget tag matters for time-boxed corpus passes. |
| `detect_runtime_kind` | Returns a fixed enum (`native`, `react_native_hermes`, `flutter_aot`, …) driving JADX heap and Step 7.5 / 7.6 routing. One-second probe; perfect MCP surface. |
| `detect_protector` | Decides whether to load `android-protector-triage` and whether `dexprotector_unpack` will succeed. Pure-Python signal extraction; no Android device required. |
| `dexprotector_unpack` | Unicorn-backed static unpack of libdp.so for DexProtector-protected APKs (arm64-v8a). Heavy enough to deserve its own typed surface; conditional on `detect_protector`. |
| `extract_api_map` | Regex-mines API endpoints, generated clients, request-signing hints, feature flags, object IDs, and workflow verbs. Drives backend-rich APK triage. |
| `rank_backend_richness` | Sorts `backend_richness.json` summaries across a corpus. The next-targets-to-probe queue for backend hypotheses. |
| `normalize_semantic_findings` | Deterministic finding schema with MASVS/CWE/MASWE auto-tagging, dedup key, confidence/validation tier inference, Markdown/CSV/JSONL renderers. Stable contract across runs. |

Everything else — JADX decompile, ripgrep, Semgrep, Joern, CodeQL, FlowDroid, adb — uses the canonical CLI directly. Read the matching skill for the recipes.

### Why bash, not MCP — for JADX, Semgrep, Joern

The "use bash" choice is not the absence of a decision; it's a deliberate one. The audit, with evidence:

- **`semgrep mcp`** (semgrep 1.23.3 builtin; standalone `semgrep/mcp` repo archived 2025-10-28). The `semgrep_scan` MCP tool accepts only `code_files: [{path}]` — no `config` argument. It runs the default `auto` rule set. Our methodology *requires* the multi-pack ensemble (`--config p/security-audit --config p/mobsfscan --config r/java`); the MCP surface can't express it. Output also can't be redirected to `findings/baselines/<pkg>/semgrep.json` from the tool. Adopting it would regress the methodology to "scan with defaults."
- **`zinja-coder/jadx-mcp-server`** (632★) + **`jadx-ai-mcp` plugin** (2,171★). The README is explicit: *"Requires JADX-GUI with the JADX-AI-MCP plugin running — this is not a headless solution. The server communicates with an active decompiler instance via HTTP."* The 25-tool surface (`fetch_current_class`, `get_selected_text`, `xrefs_to_method`, `rename_variable`) is an analyst co-pilot for live GUI sessions. Our workflow is headless `jadx -d` across 86 APKs in parallel and then `rg` over the disk tree — wrong architectural fit.
- **`zinja-coder/apktool-mcp-server`** (same author as the jadx variant). Same GUI-coupled / interactive co-pilot architecture against `apktool d`. We only use apktool as a fallback path (`aapt2 dump xmltree` in `extract_corpus_components.py`), so the headless / multi-APK gap is the same as jadx-mcp-server.
- **`sfncat/mcp-joern`** (43★, Apr 2026, MIT) clears the recency floor but Joern is already our lowest-volume step ("only on shortlisted methods"). Marginal automation gain vs. a recipe in `joern-recipes.md`. Worth a separate spike later if Joern volume grows.
- **`JordyZomer/codeql-mcp`** (146★) ships without a LICENSE file — license-trap, not redistributable.

If a new upstream MCP appears that *does* accept multi-pack configs (semgrep) or *can* drive headless decompile (jadx), revisit. Until then, the methodology lives in the skill prose where the heap-tier table, rule-pack choice, and Joern recipe can be taught.

### Why no top-level agent

Sibling capabilities (`ios-forensics`, `memory-forensics`, `web-security`, `bloodhound`) ship a coordinating agent that binds skills via frontmatter and gates tools. This capability deliberately does not.

The four skills here cover non-overlapping intent shapes — corpus prep, broad semantic hunting (Mode A/B/C), single-APK depth, and protector triage — and each carries a precise `description:` trigger plus an `allowed-tools:` gate. The routing decision is *which skill to load*, and the skill frontmatter is enough to express that. An agent prompt layered on top would duplicate the Mode A/B/C selection logic already in `android-semantic-vuln-hunting/SKILL.md` without adding a `tools:` gate or `model:` pin a skill can't already express.

Revisit if a future workflow needs persistent operating posture across multiple skills in one session (e.g. evidence rules + tool-priority order that span corpus prep and vuln hunting), or if a model pin distinct from the session default becomes the right choice for these workflows.

## Operator-run scripts (large IO, not MCP tools)

These stay scripts because they download bulk data the operator should supervise:

- `scripts/androzoo_gp_metadata.py download` — ~1+ GB Google Play metadata
- `scripts/androzoo_download.py` — APK downloads with rate limiting and a download manifest
- `scripts/androzoo_to_parquet.py` — one-time conversion of the metadata sources to columnar Parquet
- `scripts/gplaydl_bulk.py` — anonymous Google Play bulk downloader (Aurora token dispenser)

Their internals are unrelated to agent reasoning. Selection itself is `duckdb -c "SELECT ..."` against the Parquet files — see `android-corpus-prep` for the canonical recipe.

## Scanner-gap labels (recap)

Per finding hypothesis, attach `scanner_gap` after Semgrep/MobSF/APKHunt/`mobsfscan`:

- `exact baseline finding`
- `adjacent baseline finding`
- `generic warning only`
- `not found`

`adjacent` and `not found` are usually where the user's findings live.
