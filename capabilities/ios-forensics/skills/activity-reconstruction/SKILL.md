---
name: activity-reconstruction
description: Reconstruct what happened on an iOS device and when — application usage, backgrounds/foregrounds, device lock state, location, cellular context — using knowledgeC.db, routined, PowerLog, CellularUsage, Safari, and related artifacts. Builds evidence-backed timelines.
---

# Activity Reconstruction

## When to Use
- Need to answer "what was the user doing at time T?"
- Spyware hunt surfaced a suspect time window — need to know what else happened then
- Alibi / placement questions (was the device at location L at time T?)
- Device-usage pattern review (shifts in activity around incident)

## Goal
Produce a defensible timeline: timestamps, events, sources, confidence — tied directly to DB rows or plist entries.

## Primary Artifacts (by information density)

| Artifact | Source | What you get | Source kind |
|---|---|---|---|
| `knowledgeC.db` | `AppDomainGroup-group.com.apple.Preferences/Library/CoreDuet/Knowledge/` | App in focus, device lock, backlight, media playing, location context — *the* iOS timeline | backup + fs |
| `InteractionC.db` | `AppDomainGroup-group.com.apple.coreduet/Library/CoreDuet/People/` | Contact interactions, share-sheet use | backup |
| `PowerLog` (`powerlog.PLSQL`) | FFS only | Boot / shutdown / app power draw | fs |
| `CellularUsage.db` | `WirelessDomain/Library/Databases/CellularUsage.db` | SIM / carrier changes | backup |
| `DataUsage.sqlite` | `WirelessDomain/Library/Databases/DataUsage.sqlite` | Per-process network bytes | backup |
| `routined` | `HomeDomain/Library/Caches/com.apple.routined/*.db` (backup often sparse; FFS has the full set) | Significant locations, visits | backup + fs |
| `Safari History.db` | `HomeDomain/Library/Safari/History.db` | URL + visit timestamps | backup |
| `Photos.sqlite` | `CameraRollDomain/Media/PhotoData/Photos.sqlite` | Photo creation, location, album membership | backup |
| `Health`/`healthdb_secure.sqlite` | `HealthDomain/Health/healthdb_secure.sqlite` | Activity samples, heart rate, workouts | backup (encrypted-backup only) |

## Procedure

### 1. Pull knowledgeC.db first
```
ios_backup_extract(backup_dir, "AppDomainGroup-group.com.apple.Preferences",
                   "Library/CoreDuet/Knowledge/knowledgeC.db",
                   output_dir)
```
Core tables / streams to query:
- `/app/inFocus` — which app was in focus and for how long
- `/app/activity` — app background/foreground events
- `/device/isLocked` — lock state transitions
- `/device/isPluggedIn` — charging transitions
- `/audio/mediaPlaying` — media playback (nowplayingd)
- `/app/usage` — rolled-up usage counts
- `/location/visit` — visits to significant locations

Canonical query (adjust to the window of interest):
```sql
SELECT
  ZOBJECT.ZSTREAMNAME AS stream,
  ZOBJECT.ZVALUESTRING AS value,
  datetime(ZOBJECT.ZSTARTDATE + 978307200, 'unixepoch') AS start,
  datetime(ZOBJECT.ZENDDATE + 978307200, 'unixepoch') AS end,
  (ZOBJECT.ZENDDATE - ZOBJECT.ZSTARTDATE) AS duration_s
FROM ZOBJECT
WHERE ZOBJECT.ZSTARTDATE + 978307200 BETWEEN :t_start AND :t_end
ORDER BY ZOBJECT.ZSTARTDATE;
```

Interpretive notes:
- `/app/inFocus` with duration near zero = brief tap / background trigger
- Media playing when device `isLocked=1` = audio-only / headphones / CarPlay scenario
- Backlight on when `isLocked=1` = someone interacted with notifications without unlocking

### 2. Stitch with Safari + Photos for narrative context
- Safari `History.db` → `history_items` joined to `history_visits` gives URL + visit timestamp
- Photos `Photos.sqlite` → `ZASSET.ZDATECREATED` + optional `ZADDITIONALASSETATTRIBUTES` location
- Correlate: app in focus = Safari AND Safari history visit timestamp = same → confirm user action, not automated fetch

### 3. Location
Backup path (sparse): `mvt_run_module(source, module="locationd")` or extract `HomeDomain/Library/Caches/locationd/*`.
FFS path (full): `mvt_run_module(source, source_kind="fs", module="locationd")` plus `routined` tables (`CoreRoutine`, `RTVisit` objects, `Cloud.sqlite`).

For significant locations on FFS: `ios_backup_list path_substring="routined"` then query the `Cloud.sqlite` + `Local.sqlite` files' `ZRTLEARNEDVISIT`, `ZRTLEARNEDLOCATION`. Note the coordinate rounding (~50m) and confidence column.

### 4. Cellular context
```
ios_backup_extract backup_dir "WirelessDomain" "Library/Databases/CellularUsage.db" out
ios_sqlite_query(<CellularUsage.db>, "SELECT ZLABEL, ZICCID, datetime(ZSUBSCRIBERINFOUPDATEDATE+978307200,'unixepoch') FROM ZSUBSCRIBERINFO")
```
SIM changes tell you: the user swapped carriers, eSIM was provisioned, or someone replaced the SIM — relevant for IMSI-catcher and SIM-swap cases.

### 5. Power / boot events (FFS only)
`PowerLog` (`powerlog.PLSQL`) contains tables like `PLProcessMonitorAgent_EventPoint_ProcessExit`, `PLSleepWakeAgent_Interval_Session`, `PLAccountingOperator_EventNone_Nodes`. Boot and shutdown timestamps close to incident windows frequently matter.

### 6. Build the timeline
One row per event, ordered. Columns: `timestamp`, `duration`, `source` (table + DB), `event`, `actor` (app / daemon / system), `confidence` (direct = row-backed; derived = inferred).

Merge with timestamps from `spyware-hunt` (shutdown_log entries, suspicious SMS, datausage onsets, configuration profile installs). The combined timeline is usually what answers the case's fundamental question.

## Cocoa Timestamp Note
Every iOS SQLite store uses **Cocoa time**: seconds (sometimes nanoseconds) since 2001-01-01 UTC. Convert with `ts + 978307200` for seconds, or `ts / 1e9 + 978307200` for nanoseconds, then standard `datetime(..., 'unixepoch')`. Miss this once and your entire timeline is offset by 31 years; we mention it here because that exact mistake shows up in almost every first-timer report.

## Reporting
Deliver as a timeline table (CSV or markdown). For every row, include a stable pointer to the source (DB name, table, rowid) so anyone can re-derive the claim.

## Common Pitfalls
- Quoting `knowledgeC.db` durations in minutes when they're seconds
- Treating `/app/inFocus` as "user looked at the phone" — could be CarPlay, Apple Watch handoff, or notification-center glance
- Missing the FFS-only tables in `routined`; the iTunes-backup version has a small subset
- Not accounting for time-zone — iOS stores UTC; render in the device's locale only after conversion, and document which TZ you're showing
- Assuming a single Photos location proves presence — AirDrop, iCloud-shared albums, and WhatsApp shared images carry their source EXIF, not the subject device's position
