---
name: spyware-hunt
description: Hunt for mercenary iOS spyware — Pegasus, Predator, QuaDream, RCS, Hermit. Correlates STIX IoCs across SMS, Safari, Manifest.db, datausage, and shutdown_log, and pivots hits into concrete evidence. Use after triage surfaces a STIX match or on any device where mercenary spyware is plausible.
---

# Mercenary Spyware Hunt

## When to Use
- Triage surfaced a STIX match (any module's `_detected` entry)
- Device belongs to an at-risk role (journalist, HRD, dissident, diplomat, executive)
- Open-source intel mentions the target by name in a spyware writeup
- Apple Threat Notification was received by the device owner

## Background — why iOS spyware is different
- Modern mercenary spyware (Pegasus since 2021, Predator, QuaDream, RCS) favors **zero-click** delivery via iMessage, FaceTime, or Messages URLs — no user interaction, minimal on-device artifacts
- Implants are memory-resident or quickly self-delete; **collateral logs** (shutdown.log, WebKit DataStore, DataUsage, crashes) are usually the only durable evidence
- **STIX IoCs** maintained by Amnesty's Security Lab, Citizen Lab, Kaspersky GReAT, and Volexity are the authoritative ground truth — keep them current

## Procedure

### 1. Run the STIX sweep first
```
mvt_check_iocs(source, iocs="/path/to/amnesty-ioc.stix2.json",
               source_kind="backup" | "fs")
```
Read `<module>_detected` entries. Each hit is authoritative — Amnesty's indicators are curated and versioned.

For every hit: note module, record, matched indicator (domain / process / file path), and the IoC's provenance field (which family / campaign).

### 2. Shutdown log (FFS only — do this next)
`mvt_shutdown_log`. The log records processes holding shutdown. Pegasus and related implants frequently appear with short, generic names. Compare against a baseline (clean reference device on matching iOS).
- `/private/var/db/com.apple.xpc.roleaccountd.staging` entries — high signal
- Unnamed or numerically-named processes — high signal
- Processes with paths outside system roots — high signal

### 3. DataUsage cross-reference
`mvt_datausage`. Spyware needs to exfiltrate — it shows up in DataUsage.sqlite:
- Rows for process names not present in `mvt_installed_apps`
- Rows where `ZFIRSTTIMESTAMP ≈ ZTIMESTAMP` (process lived briefly, exfil'd, died)
- WWAN egress from non-obvious system services

Pivot any suspect process into `ios_backup_list path_substring=<proc>` to find logs or caches naming it.

### 4. Message-vector analysis
Zero-click iMessage exploits leave partial traces:
- `mvt_sms_messages iocs=...` — URLs in messages matching Pegasus / Predator delivery domains
- Extract `sms.db` via `ios_backup_extract domain=HomeDomain relative_path=Library/SMS/sms.db` and run `ios_sqlite_query` for messages around the suspected compromise window; look for short-lived threads with unusual senders
- Check `mvt_run_module` → `imagent_crashes` style modules (via FFS, `.ips` crash files mentioning imagent, MessagesBlastDoorService, mediaserverd, WebKit)

### 5. Safari / WebKit forensics
- `mvt_safari_history iocs=...` — one-click delivery domains
- On FFS: `mvt_run_module webkit_session_resource_log` and `webkit_resource_load_statistics` — resources loaded across sites, a rich record of one-click attack chains
- Extract `WebKit/Databases` SQLites for per-site storage anomalies

### 6. Manifest + filesystem pivot
`mvt_manifest iocs=...` scans Manifest.db paths/domains against STIX. Additionally:
```
ios_backup_list path_substring="com.apple.xpc.roleaccountd"
ios_backup_list path_substring="staging"
ios_backup_list path_substring=".plist.db"
```
Any unexpected hit in system domains is an investigate-immediately.

### 7. Timeline correlation
Pull every timestamp you've collected — shutdown_log entries, datausage first-seen, suspicious SMS receipt, unusual Safari hit, configuration profile install — into a single ordered timeline. A Pegasus infection typically looks like:

```
T+0    suspicious iMessage / Safari hit
T+0..T+60s   imagent / MessagesBlastDoorService / mediaserverd crash (FFS .ips)
T+0..T+hours  unknown process in datausage, short-lived
T+days  anomalous shutdown_log entries
```

If your evidence lines up on that shape, confidence is "likely" even without a direct STIX hit.

### 8. Extract for offline analysis
For every confirmed or likely finding:
- `ios_backup_extract` the originating DB / plist
- Hash it; feed it and derived IoCs back into `mvt_check_iocs` across related devices
- Preserve the decrypted backup directory as evidence (hash + chain-of-custody note)

## STIX Rules Starter (inline, when you have custom IoCs)
MVT's STIX2 format accepts `domain-name`, `url`, `file:hashes.'SHA-256'`, `email-addr`, `ipv4-addr`, `process:name`. For a one-shot custom IoC, write the minimal STIX2 JSON and pass it via the `iocs` parameter — the same data model the public feeds use.

## Reporting
For each finding, state: family (best match from STIX provenance), confidence (confirmed / likely / suspected), artifacts, timeline, delivery vector (iMessage / Safari / Mail / WhatsApp / social), and whether the device is still compromised (evidence only, or active C2 in datausage / shutdown_log).

## Common Pitfalls
- Treating absence of STIX hits as a clean verdict — feeds lag real campaigns by weeks to months
- Only scanning backups when FFS is available — shutdown_log, WebKit DataStore, and crash logs are FFS-only and are the highest-signal spyware artifacts
- Forgetting to correlate timestamps — isolated anomalies are easy to dismiss; a 30-second cluster is almost always real
- Publishing findings before the victim is briefed — targeted-spyware findings are sensitive; default to minimum-distribution
- Missing Lockdown Mode / iOS version as a control — if the device is on recent iOS with Lockdown Mode enabled and still shows implant behavior, that's a *higher* confidence signal, not lower
