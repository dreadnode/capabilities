# ios-forensics

A curated [MVT](https://github.com/mvt-project/mvt) (Mobile Verification Toolkit) surface for triaging iOS acquisitions for mercenary-spyware compromise — Pegasus, Predator, QuaDream, RCS, Hermit. The `mvt` MCP wraps the `mvt-ios` CLI behind verb-named tools (device info, installed apps, configuration profiles, TCC grants, data usage, SMS, calls, Safari, shutdown log) plus a STIX-IoC sweep that correlates every module against published indicator feeds. Backup-native helpers (`Manifest.db` resolution, read-only SQLite, plist parsing) let the agent pivot a flagged record into the underlying artifact. The `ios-forensics-analyst` agent drives the whole loop: identify → triage → focused hunt → extract → report.

This is triage, not chain-of-custody forensics. It tells you whether a device looks compromised and pins findings to specific artifacts; it does not produce court-grade evidence packages or perform acquisition.

**Shape:** one agent (`ios-forensics-analyst`), one MCP server (`mvt`, ~19 tools), five playbook skills (image triage, spyware hunt, communications analysis, activity reconstruction, config/persistence review). Sibling capability `memory-forensics` mirrors this shape for memory images.

## Setup

**1. Install MVT.** The MCP does not vendor it. It resolves the command as `MVT_COMMAND` → `mvt-ios` on `PATH` → a PEP 723 fallback that runs the `mvt` package installed into the `uv` venv. The fallback works, but install MVT explicitly so the version is yours to control:

```
pipx install mvt        # or: uv tool install mvt
```

**2. Produce an input.** MVT reads one of two source kinds — every tool takes a `source_kind`:

| `source_kind` | What it is | How to get it |
|---|---|---|
| `backup` | iTunes/Finder backup directory | Finder (or `idevicebackup2 backup` from libimobiledevice). **Enable encryption** before backing up — it pulls Health, keychain metadata, and more that an unencrypted backup omits. |
| `fs` | Full-filesystem extraction | A jailbreak / `checkm8`-class acquisition (commercial tooling or `palera1n`-style). |

Most modules run on a backup. A handful are FFS-only and are the highest-signal spyware artifacts — `shutdown_log`, PowerLog, WebKit DataStore/resource logs, crash `.ips` files. If you only have a backup, the agent will say so rather than fabricate a verdict.

Encrypted backups: supply the password to `mvt_decrypt_backup`, which writes a decrypted working copy. The password is passed to `mvt-ios` as a CLI argument, so it is briefly visible to local process listings while the subprocess runs.

**3. Bring STIX IoCs.** Spyware detection is only as current as the indicators you feed it. MVT correlates modules against STIX2 IoC files supplied via the `iocs=` parameter — these are **not** bundled. Pull the latest from [Amnesty's Security Lab](https://github.com/AmnestyTech/investigations), Citizen Lab, Kaspersky GReAT, or Volexity, or hand-write a minimal STIX2 file for custom indicators. Absence of STIX hits is not a clean verdict; feeds lag live campaigns by weeks to months.

### Tuning

No credentials or secrets. Optional environment variables:

| Var | Default | Change when |
|---|---|---|
| `MVT_COMMAND` | unset | You want a specific `mvt-ios` binary (e.g. a pinned venv) instead of `PATH` resolution. |
| `MVT_TIMEOUT` | `900` (s) | A module on a large FFS times out; raise it. Per-subprocess. |
| `MVT_MAX_OUTPUT_CHARS` | `200000` | Tool output is truncating mid-analysis and your context budget can absorb more. |

## Usage

Drive it through the agent:

```
>>> @ios-forensics-analyst triage the backup at ~/cases/device-01 with the Amnesty STIX feed at ~/iocs/amnesty.stix2.json
```

It runs `mvt_status` → `mvt_info` to fix device context, sweeps the high-signal modules, runs the STIX correlation, then pivots any hit into the underlying SQLite/plist record. The five skills carry the per-phase methodology; the agent loads them as evidence demands.

## Before you trust it

- **Triage scope, not custody.** Findings are evidence-pinned but this is not an acquisition or chain-of-custody tool. Treat suspected mercenary-spyware findings as sensitive — default to minimum distribution until victims and legal/human-rights stakeholders are briefed.
- **Backups underperform FFS.** The most diagnostic spyware artifacts (shutdown_log, WebKit DataStore, crash logs) only exist in a full-filesystem extraction. A clean backup sweep is not an all-clear.
- **IoC currency is on you.** Detection depends entirely on the STIX feed you supply and when it was last updated.
- **No tests ship** for the MCP server. The SQLite helpers open read-only with `ATTACH`/`DETACH` denied at the authorizer, so query tools can't write or reach beyond the named database.
