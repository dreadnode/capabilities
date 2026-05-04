---
name: package-triage
description: Triage a suspicious or newly encountered software package end-to-end using Spectra Assure Community reports, OSV vulnerability data, OpenSSF Scorecard, and static inspection. Use when the user asks to "triage a package", "investigate this library", "is this npm/pypi/gem safe", or supplies a purl or package name.
---

# Package Triage Playbook

Goal: produce a short, evidence-backed verdict on whether a specific package version is safe to adopt — malware risk, known CVEs, supply-chain hygiene, and anything surprising in the artifact itself.

## 1. Establish identity

Pin down the *exact* artifact:

1. Resolve the user's input to a canonical purl. Examples:
   - "lodash 4.17.21" → `pkg:npm/lodash@4.17.21`
   - "requests" (no version) → use `spectra_get_package` to get the latest published version, then pin.
   - A SHA256 → use `spectra_search_packages` with the hash to find packages that match or *contain* it.
2. If the user supplies only a partial purl or a vague name, run `spectra_search_packages` first and confirm which result they mean before spending cycles.

Record: `purl`, `version`, `repo URL` (from the community report), and the expected artifact hash.

## 2. Pull the Spectra Assure Community report

Use `spectra_get_version_report` with the purl and version. Note:

- Overall verdict and quality score.
- Malware / malicious behaviour detections and any YARA-family hits.
- Vulnerability counts (critical / high / medium / low) and the specific CVEs called out.
- License findings (copyleft / proprietary).
- Any reproducible-build or tampering signals.

If the package is not in the catalogue, fall back to `ecosystem_download` and work from the artifact alone — RL has not analysed it.

## 3. Cross-reference vulnerabilities

Spectra Assure's CVE list is authoritative but OSV sometimes has quicker coverage of just-disclosed advisories:

- `osv_query_purl` with the pinned purl.
- Diff OSV results against the RL report. Anything in OSV but not in RL is the most interesting signal — flag it in the output.

## 4. Check supply-chain health

If the community report includes a source repo (e.g. `github.com/psf/requests`):

- `scorecard_fetch` for the repo.
- Call out any checks scoring ≤ 3 (unmaintained, missing code review, binary artifacts in repo, etc.). These are *leading indicators* — a good package today can rot.

## 5. Inspect the artifact

For anything flagged as suspicious, or when the user explicitly wants a deeper look:

1. `ecosystem_download` to pull the archive locally (or `spectra_import_purl` + `spectra_download_artifact` if you want RL's preserved copy).
2. `extract_archive` into a working directory.
3. `file_inventory` to get the per-file SHA-256 manifest.
4. For binaries or obfuscated scripts: `file_entropy` + `file_strings`. Entropy > 7.5 on a nominally-text file (JS, Python, Ruby) is a strong tampering signal.
5. Optional: `yara_scan` with the user's rules or a community ruleset for deeper pattern matching.
6. For .NET assemblies in the archive, hand off to the `dotnet-reversing` capability (its tools are available under the `dotnet_*` namespace) to decompile and trace suspicious call flow.

## 6. Write the verdict

Produce a concise report the user can paste into a ticket:

```
Package: pkg:npm/<name>@<version>
Spectra Assure: <overall score>  <# malware>  <# vulns by severity>
OSV: <# advisories>  <list IDs>
Scorecard: <overall>/10  — <notable weak checks>
Artifact: <sha256>  size=<bytes>  entropy=<value>
Flags:
  - <specific finding with evidence>
  - ...
Recommendation: <adopt / adopt with pinned version / avoid / investigate further>
```

Only promote something to a "flag" if you have concrete evidence (a CVE ID, a YARA hit, a malicious file path, an anomalous hash). Weak signals belong in a "worth watching" sub-list, not in the flags section — false positives erode trust.
