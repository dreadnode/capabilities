---
name: supply-chain-analysis
description: Analyse the supply chain of a project's dependency closure using Spectra Assure reports, SBOM export (CycloneDX/SPDX/SARIF), OSV, and Scorecard. Use when the user asks to "audit dependencies", "check a requirements.txt / package.json / Cargo.lock", "generate an SBOM", or "find risky transitive dependencies".
---

# Supply-Chain Analysis Playbook

Goal: inventory a project's dependencies, rank them by risk, and produce a machine-readable SBOM plus a prioritised action list.

## 1. Enumerate dependencies

Read the manifest the user points at. Parse without installing:

- `package.json` + `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`
- `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`
- `Gemfile.lock`, `Cargo.lock`, `go.sum`, `pom.xml`, `*.csproj`, `packages.lock.json`

Convert every pinned dependency to a purl. If a transitive dependency lacks a pinned version, call that out — unpinned transitives are a supply-chain risk in their own right.

## 2. Bulk-query Spectra Assure

`spectra_search_packages` accepts up to 50 purls per call. Batch the dependency list and collect:

- Which dependencies are known to the Community catalogue (baseline).
- Which have been flagged malicious (binary signal — stop and surface immediately).
- Quality / vulnerability summaries per package.

For any flagged package, follow the `package-triage` skill to produce a detailed write-up.

## 3. SBOM generation

If the user has a Portal project that corresponds to this codebase, use `spectra_export_report` with `report_type=cyclonedx` or `spdx` to get a signed SBOM from Spectra Assure directly. Save it via `save_as=<file>` rather than inlining megabytes of JSON into the response.

If there is no Portal project:

1. Create a purl list yourself.
2. For each, `spectra_get_version_report` gives file-level data you can stitch into a lightweight CycloneDX document.
3. Hand the user the per-package data and recommend `spectra_import_purl` + the official export if they want a signed SBOM.

## 4. Vulnerability correlation

- Run `osv_query_purl` across the full dependency list. OSV is cheap and public — do it even when Spectra Assure already has CVE data, because advisories go public on OSV first.
- Produce a ranked list: critical → high → medium → low, with CVE IDs and the affected component's position in the tree (direct vs transitive). Transitive criticals are harder to fix; flag them distinctly.

## 5. Health scoring

- For each direct dependency that is library-shaped (i.e., has a git repo in the community report), run `scorecard_fetch` on the repo.
- Flag dependencies where *any* of these are true:
  - Scorecard `Maintained` ≤ 3
  - Scorecard `Vulnerabilities` ≤ 5
  - Community report shows no recent version publishes in >18 months
  - Sole maintainer, single-person bus factor

These are the packages most likely to host the *next* malicious update.

## 6. Output

Return two artifacts:

1. **Executive summary** (pasteable):
   ```
   Scanned: N direct deps, M transitive
   Malicious: <count>   <purl>
   Critical CVEs: <count>   <CVE list>
   Unmaintained: <count>   <names>
   SBOM: <absolute path to the saved SBOM file>
   ```
2. **Action list**, ordered by blast radius × fixability:
   - Immediate: malicious / critical CVE / broken package.
   - This sprint: high CVEs with patched versions available.
   - Backlog: Scorecard hygiene, license flags, unpinned transitives.

Always save SBOMs and long reports to disk with `save_as=` — the agent context is not where multi-megabyte JSON belongs.
