# android-apk-research

Static semantic-bug research on Android APKs — deep-link routers, intent redirection, WebView trust boundaries, auth/session/client-state bypass, Dirty Stream share targets, and APK-derived backend API chains. A 10-tool orchestration MCP (`android-research`) handles the wide, parallel work — corpus inventory, component ranking, runtime classification, protector detection/unpack, API-map extraction, finding normalization — while the heavyweight decompile-and-hunt methodology (JADX heap tiers, ripgrep pattern packs, Semgrep rule ensembles, Joern/CodeQL recipes) lives in the skills as bash, where it belongs. Everything here is **static**: no device, no emulator, no live backend.

**Shape:** one MCP server (`android-research`, self-bootstrapping via `uv run`), four skills — `android-corpus-prep` (AndroZoo/Play target selection), `android-semantic-vuln-hunting` (canonical at-scale methodology), `android-targeted-assessment` (one-APK depth mode), `android-protector-triage` (DexProtector/Promon handling). Findings ground in OWASP MASVS / MASTG, MASWE, and CWE.

## What the MCP exposes

Ten tools, grouped by pipeline stage. They orchestrate scripts under `scripts/`; the actual decompilation and scanning stays in the skills.

| Stage | Tools |
|---|---|
| Probe | `inventory_status` |
| Corpus inventory | `run_corpus_inventory` |
| Attack-surface ranking | `extract_components`, `rank_components`, `detect_runtime_kind` |
| Protector triage | `detect_protector`, `dexprotector_unpack` |
| Backend mapping | `extract_api_map`, `rank_backend_richness` |
| Reporting | `normalize_semantic_findings` |

## Setup

The MCP self-bootstraps (PEP 723 / `uv run`) — no Python install step. The work it orchestrates depends on external CLIs that are **not** bundled; the manifest `checks:` block surfaces missing hard prerequisites in the TUI capability manager.

**Hard prerequisites** (manifest `checks:` — capability is degraded without them):

| Tool | Why |
|---|---|
| `uv` | Runs the MCP and its PEP 723 scripts |
| `jadx` | DEX → Java decompilation (the core hunting surface) |
| `apktool` | Resource / manifest decoding |
| `aapt` or `aapt2` | Manifest fallback when Androguard errors on multi-dex APKs |
| `semgrep` | Rule-pack triage of decompiled source |
| `apkid` | Packer / protector signal during inventory |

**Skill-step tools** (not checked at install, but `inventory_status` reports them — needed for specific methodology steps): `joern`, `codeql`, `adb`, plus hybrid-runtime follow-ups `hbctool` (Hermes), `blutter` (Flutter/Dart AOT), and `prettier` / `npx` (JS bundle work). `android-corpus-prep` additionally uses DuckDB for AndroZoo Parquet selection. Call `inventory_status` once at session start to see which steps will run end-to-end on the host.

**Tunables** (set via the deployer environment — secrets screen or web app; no `.env` autoload):

| Var | Default | Change when |
|---|---|---|
| `ANDROID_RESEARCH_MAX_OUTPUT_CHARS` | `20000` | Tool output is being truncated and you need more inline context |
| `ANDROID_RESEARCH_TIMEOUT` | `300` | Reference default only; each tool takes its own `timeout` arg (per-APK inventory 180s, unpack 600s, etc.) |

## Before you trust it

- **Static only.** `extract_api_map` output is a *target map* for backend hypotheses, not proof — findings default to `needs_backend_validation` until tested against authorized accounts. No exploitation, no live-backend probing, no APK patching ships here.
- **DexProtector unpack is arm64-v8a only.** `dexprotector_unpack` statically recovers `libdp.so` via Unicorn emulation (it never *executes* the blob); other ABIs and other protectors fall back to adjacency analysis only. Always run `detect_protector` first and gate on `dexprotector_unpack_supported`.
- **Authorization is the operator's job.** The skills default to static + authorized read-only validation; pointing the pipeline at APKs or backends you're not cleared to test is out of scope by design.

Agent-facing usage — the JADX heap tiers, ripgrep/Semgrep/Joern/CodeQL recipes, bug-class catalog, and finding schema — lives in `skills/`, not here. The MCP carries a header note on the "why bash, not MCP" split; the long-form rationale is in `skills/android-semantic-vuln-hunting/references/workflow.md`.
