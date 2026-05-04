---
name: ios-image-triage
description: Structured first-pass triage of an unknown iOS acquisition — iTunes/Finder backup or full-filesystem extraction. Use when handed an iOS image and asked "what's on this phone and does it look compromised?" — establishes ground truth before any targeted hunt.
---

# iOS Image Triage

## When to Use
- First contact with an unfamiliar iOS backup or FFS
- Incident scoping before deep-diving (spyware hunt, comms analysis, etc.)
- Quick posture check on a device handed over for review

## Goal
Answer these in order: what device / iOS, what apps, what profiles, what grants, any STIX hits, any obvious anomalies.

## Procedure

### 1. Identify the source
Run `mvt_status` then `mvt_info`. Record:
- Device name, model (product type), serial / UDID
- iOS build + major version
- Acquisition timestamp (last backup date for backups; FFS capture time if present)
- Encryption status (backups only)

All subsequent tools take `source_kind` — set it once based on this (`backup` for iTunes/Finder, `fs` for FFS).

If the backup is encrypted, run `mvt_decrypt_backup` into a working directory and use that as `source` for everything that follows.

### 2. Installed apps
`mvt_installed_apps`. Look for:
- Bundle IDs you don't recognize — look up on App Store, flag blanks
- Apps installed very recently relative to the compromise window
- Enterprise-signed / sideloaded apps outside the App Store (`AppleInternal`, `Enterprise`, `Developer` marker in metadata)
- Known-bad bundle IDs (Hermit, Predator loaders — see Amnesty STIX)
- Duplicates with near-identical names (lookalike icons / typosquats)

### 3. Configuration profiles (high signal)
`mvt_configuration_profiles`. *Every* installed profile deserves a sentence of explanation:
- Corporate MDM from a known vendor (Jamf, Intune, VMware Workspace ONE) → typically benign; verify issuer
- Apple Beta profile / carrier profile → typically benign
- Anything else — especially self-signed, recently installed, granting VPN / Root-CA / Supervision → investigate
- Rogue profiles are the #1 iOS persistence + MitM vector for opportunistic attackers

### 4. TCC grants
`mvt_tcc`. Score every non-Apple grant:
- Microphone / Camera / Screen Recording to a non-AV / non-communication app → suspicious
- Full-Disk-Access equivalents on iOS (Files, Photos-All) to a recently-installed app → suspicious
- Location (Always) to anything not obviously location-aware → suspicious
- Accessibility (Switch Control, AssistiveTouch) unexpectedly enabled → investigate; AX grants are a classic mobile stalkerware footprint

### 5. Cellular / data usage
`mvt_datausage`. Red flags:
- Processes with non-zero bytes that don't match any bundle in `mvt_installed_apps`
- Short-lived rows (`ZFIRSTTIMESTAMP` and `ZTIMESTAMP` near-identical) for unknown processes
- Large WWAN egress from background daemons
Cross-reference PIDs / process names against your installed-apps list.

### 6. Broad STIX sweep
If you have an Amnesty / Citizen Lab / vendor STIX file:
`mvt_check_iocs(source, iocs="/path/to/stix.json")`

This runs every module with IoC correlation. Read the `_detected` entries first — any hit warrants a focused `spyware-hunt`.

If no STIX file is to hand, download the latest Amnesty feed or skip this step and come back to it.

### 7. Shutdown log (FFS only — very high signal)
`mvt_shutdown_log`. The iOS shutdown log keeps a per-process record of processes that delayed shutdown. Multiple Pegasus campaigns were first surfaced by anomalous shutdown-log entries (Kaspersky's Triangulation writeup, Amnesty's 2021 reports).

- Unknown / short-named / numeric-named processes in shutdown_log = high priority
- Entries pointing at paths outside `/usr`, `/System`, `/private/var/containers` = high priority

### 8. Record findings
Triage table columns: module, record / identifier, evidence pointer (file or DB row), verdict (benign / suspicious / confirmed), skill to run next.

## Heuristic Priorities
If you only have time for three things: (a) configuration_profiles + tcc, (b) datausage cross-referenced against installed_apps, (c) `mvt_check_iocs` with a current STIX. Those catch ~80% of iOS compromises outside of sophisticated zero-click spyware (which needs the full `spyware-hunt` playbook).

## Common Pitfalls
- Trusting `mvt_installed_apps` alone — uninstalled or hidden apps can still have left-over `datausage` / `tcc` rows
- Assuming a profile is benign because it's signed — self-signed enterprise profiles are trivial to generate
- Skipping `mvt_info` — without device context every finding downstream is ambiguous
- Running a broad STIX sweep on an encrypted backup before decrypting (modules will produce empty or partial results)
- Treating an empty `shutdown_log` as "all clear" — the log rotates; absence of evidence isn't evidence of absence
