---
name: enrichment-playbook
description: Enrich a downloaded package artifact with reversing and vulnerability analysis data — archive extraction, per-file hashing, strings, entropy, YARA, OSV, Scorecard, and handoff to language-specific reversing capabilities. Use when the user has a package file or purl and asks to "enrich", "deep scan", "unpack and analyse", or wants to combine Spectra Assure data with reversing tools.
---

# Enrichment Playbook

Goal: take a specific package artifact and squeeze out every signal a downstream analyst or agent might need — without wasting tokens on irrelevant noise.

## Input contract

You need one of:

- A purl with a pinned version → use `ecosystem_download` (or `spectra_import_purl` + `spectra_download_artifact` for a Portal copy).
- A local file path already on disk.

Everything downstream works from a local path.

## Stage 1: Normalise & inventory

1. Compute the archive's SHA-256 (`file_entropy` prints it alongside size and magic bytes).
2. `extract_archive` into a per-artifact subdirectory under `SECURE_SOFTWARE_DIR`. The extractor refuses absolute-path or `..` entries — if it rejects files, that itself is a reportable finding.
3. `file_inventory` the extraction root. Save the output if large; keep the summary in context.

## Stage 2: Static triage

For each *interesting* file in the inventory, pick the right tool:

| File type                            | Tool                               | What to look for                                        |
| ------------------------------------ | ---------------------------------- | ------------------------------------------------------- |
| .js / .py / .rb / .php / .sh / .ps1  | `file_strings`                     | Obfuscation markers, URLs, base64 blobs, eval chains    |
| .so / .dylib / .dll / .exe / ELF     | `file_entropy` + `file_strings`    | Packed sections (entropy ≫ 7.0), imports, IoCs          |
| .wasm                                | `file_entropy`                     | Unexpected size/entropy vs. declared role               |
| .jar / .war / .apk                   | `extract_archive` (they're zips)   | Then recurse on the inner classes                       |
| .dll / .exe (.NET)                   | Hand to `dotnet-reversing` tools   | Decompile, namespace enumeration, suspicious call flow  |

"Interesting" means anything that shouldn't be in the archive (pre-built binaries in a source package, install-time hooks like `postinstall`, test fixtures that exec, encoded strings, vendored SDKs).

## Stage 3: Rule-based scan

If the user provides YARA rules (inline or a file), run `yara_scan` recursively over the extraction root. If they don't have rules, suggest the open-source sets (Neo23x0/signature-base, Yara-Rules/rules) rather than inventing rules on the fly — stale rules produce noise.

## Stage 4: External enrichment

- `osv_query_purl` with the pinned purl — attach the OSV record IDs to the findings.
- `scorecard_fetch` against the source repo if one is declared in the package metadata.
- If Spectra Assure has a Portal record for this version, `spectra_export_report report_type=rl-json` gives you RL's full analysis; `rl-cve` is the terse CVE digest. Save to disk via `save_as=`.

## Stage 5: Chain findings

Anything of interest is worth combining:

- A YARA hit on a file + a high-entropy `.js` wrapper + an unpinned postinstall script = probable malicious implant, not coincidence.
- An OSV critical in a transitive dep + Scorecard's `Dangerous-Workflow` ≤ 2 = probable near-term supply-chain target.

In the final output, never list raw tool results — summarise, cite the file path and the rule/CVE/check that fired, and keep the evidence bundle on disk (paths, not contents).

## Handoff

If the package contains .NET assemblies, explicitly call out the `dotnet-reversing` tool set and hand over the list of file paths to decompile — don't try to do it here. Same pattern applies for any future language-specific reversing capability: enrich first, hand off second.
