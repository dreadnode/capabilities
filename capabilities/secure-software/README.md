# secure-software

Package supply-chain analysis built on the ReversingLabs [secure.software](https://www.secure.software/) (Spectra Assure) Community catalogue — millions of pre-analysed open-source package versions, searchable by purl or hash. The `secure-software` agent pins a package to an exact version, pulls RL's malware / vulnerability / hygiene report, then enriches with OSV (known CVEs) and OpenSSF Scorecard (repo health). For artifacts that need a closer look it imports them into your Portal, exports SBOMs (CycloneDX / SPDX / SARIF), downloads the file, and runs native static triage — extract, hash, strings, entropy, YARA.

**vs. [`spectra-assure`](../spectra-assure):** that sibling is a Docker MCP wrapping RL's Portal *scanner* for deep behavioral binary analysis (`rl_protect_scan` / `_diff_behavior`); this one is native Python over the secure.software Community *catalogue search* plus OSV / Scorecard enrichment — no Docker, no scanner, free-tier-first. Reach for `spectra-assure` to scan an artifact you hold; reach for `secure-software` to look one up.

## What's in the box

| Component | Purpose |
|---|---|
| `agents/secure-software` | Autonomous analyst — pins versions, cites every finding to a source, hands binaries off to reversing tools |
| `skills/package-triage` | One package, deep, verdict wanted |
| `skills/supply-chain-analysis` | A manifest / lockfile, broad coverage, SBOM + ranked action list |
| `skills/enrichment-playbook` | An artifact already on disk, every usable static signal |
| `tools/spectra.py` | secure.software Community search + version reports (free tier) and Portal import / status / report export / artifact download |
| `tools/enrich.py` | Ecosystem download (npm/pypi/gem/cargo/maven/nuget/go), archive extract + per-file hashing, strings / entropy / YARA, OSV and Scorecard lookups |

## Setup

The capability self-bootstraps via `uv run`; supply config through the deployer environment (secrets screen or web app — no `.env` autoload).

| Var | Default | Notes |
|---|---|---|
| `SPECTRA_ASSURE_TOKEN` | **none — fails closed** | Required for any secure.software call. Create a Personal Access Token in the Portal (Account settings). The first API call raises if unset. |
| `SPECTRA_ASSURE_HOST` | `my.secure.software` | Portal host. |
| `SPECTRA_ASSURE_PATH` | `demo` | Portal slug after the host. |
| `SPECTRA_ASSURE_ORG` / `SPECTRA_ASSURE_GROUP` | none | Required **only** for Portal import / export / download. Community search and version reports work without them. |
| `SECURE_SOFTWARE_DIR` | `~/workspace/secure-software` | Where downloads, extractions, and SBOM exports land. Responses carry paths, not contents. |

OSV.dev and OpenSSF Scorecard are unauthenticated; `yara_scan` needs `yara-python` installed (it degrades gracefully and tells you if it's missing).

## Scope

- **Report / SBOM formats** (Portal export): `cyclonedx`, `spdx`, `sarif`, `rl-json`, `rl-cve`, `rl-checks`, `rl-diff`, `rl-uri`, `rl-summary-pdf`.
- **Read-only against secure.software** — the only writes are files under `SECURE_SOFTWARE_DIR`. `clean_workdir` is the one destructive tool and is fenced to that directory.
- **Chains into `dotnet-reversing`** — when an extracted artifact contains .NET assemblies, the agent hands the file paths to the `dotnet_*` tools rather than analysing binaries inline.

## Usage

```
>>> @secure-software is pkg:pypi/requests@2.31.0 safe to adopt?
>>> @secure-software audit the dependencies in ./requirements.txt and rank by risk
```
