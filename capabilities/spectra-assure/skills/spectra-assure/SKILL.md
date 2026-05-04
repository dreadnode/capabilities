---
name: spectra-assure
description: Use when scanning third-party packages, manifests, or lockfiles for malware, tampering, vulnerabilities, or policy violations via ReversingLabs Spectra Assure.
---

# Spectra Assure — Supply Chain Triage

Spectra Assure is not Snyk / Dependabot. Its differentiator is **behavioral differential analysis of compiled artifacts** — it can detect *tampering* and *malicious insertions* between two versions of the same package, which signature-based SCA misses entirely. Use it that way.

## Tools

| Tool | Purpose |
|------|---------|
| `rl_protect_scan` | Scan packages by PURL (`pkg:pypi/ultralytics@8.3.41`, `pkg:npm/express@4.19.2`) |
| `rl_protect_scan_manifest` | Scan `requirements.txt`, `package.json`, `pyproject.toml`, `Gemfile`, `setup.cfg`, `*.gemspec` |
| `rl_protect_summarize` | Full risk details for flagged packages (secrets, vulns, tampering, malware) |
| `rl_protect_interpret` | Extract one slice: `vulnerabilities` \| `indicators` \| `malware` \| `overrides` \| `governance` \| `dependencies` \| `errors` |
| `rl_protect_diff_behavior` | Compare two versions of a package for behavioral regressions (the tampering detector) |

## Profiles

`minimal` · `baseline` · `hardened` (default) · custom YAML path.

Use `hardened` unless the user asks otherwise. `minimal` is only useful for triaging a failing CI check quickly.

## Decision Tree

```
scan → REJECT   → MUST fix.   Pivot to summarize + interpret(malware|indicators).
     → WARN     → Triage.     Assess by reachability and exploitability.
     → PASS     → Record.     Still note any overrides used.
```

`REJECT` is not configurable severity — it's Spectra Assure's policy engine saying *do not ship this*. Treat it as a hard gate.

## Canonical Workflows

### 1. Pre-merge manifest scan (the common case)

```
rl_protect_scan_manifest(
  manifest_path="/project/requirements.txt",
  report_name="pr-4821-backend",
  profile="hardened",
  check_deps="release,transitive",
)
```

Read the compact summary. For every `REJECT` or high-risk `WARN`:

```
rl_protect_summarize(report_id=...)
```

Then slice:

```
rl_protect_interpret(report_id=..., task="malware",    package="ultralytics")
rl_protect_interpret(report_id=..., task="indicators", package="ultralytics")
```

### 2. Tampering check on a suspicious upgrade (the high-value case)

When a dependency jumps minor/patch unexpectedly, or maintainer changed, or the package appeared on a threat feed — **do not just scan the new version**. Diff it.

```
rl_protect_diff_behavior(
  package="ultralytics",
  old_version="8.3.40",
  new_version="8.3.41",
)
```

Look at added network endpoints, new shell/exec indicators, new filesystem writes, added dynamic loaders. These are the signals SCA misses.

### 3. Single-package spot check

```
rl_protect_scan(
  purls="pkg:pypi/requests@2.32.3,pkg:npm/axios@1.7.2",
  report_name="spot-check-2026-04-22",
)
```

## Report Output Conventions

When reporting findings to the user, structure as three tiers:

1. **Immediate kill** — `REJECT` with malware/tampering indicators. Name the package, version, and the specific indicator (e.g., "added DNS exfiltration to `api.anyrun[.]live`"). No equivocation.
2. **Pin-and-monitor** — `WARN` for known CVEs with available patches or mitigations. Include CVE ID, CVSS, exploit maturity if present, and the fixed version.
3. **Accept-with-rationale** — `PASS` with any overrides applied, or `WARN` findings with no reachable path. State the rationale explicitly so it's auditable.

Never summarize by count alone ("3 rejects, 12 warns"). Leadership needs the *name of the package* and the *nature of the finding*.

## Compliance Framing (when asked)

Spectra Assure findings map to:
- **NIST SSDF** PW.4.1, PW.4.4, PS.3.1 — component provenance and integrity
- **EO 14028** — SBOM attestation + known-bad component gating
- **OWASP Top 10** A06:2021 — Vulnerable and Outdated Components

Cite these only when the user is operating in a compliance / attestation context.

## Environment

Requires `RL_TOKEN` (prefix `rlcmm-` for Community, `rls3c-` for Enterprise). Enterprise also needs `RL_PORTAL_SERVER` and `RL_PORTAL_ORG`. If a scan fails with an auth error, say so plainly — don't retry with degraded profiles.

## What Not To Do

- Don't run `rl_protect_scan` on a list of 200 PURLs as a substitute for manifest scanning — manifest scans resolve the dependency graph correctly.
- Don't summarize without running `rl_protect_scan*` first — `rl_protect_summarize` requires a `report_id` from a prior scan.
- Don't lower the profile to make a `REJECT` go away. If the user wants to accept a risk, use `overrides` and document the rationale.
