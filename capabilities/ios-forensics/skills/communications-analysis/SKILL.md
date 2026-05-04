---
name: communications-analysis
description: Review SMS / iMessage / calls / contacts / mail / third-party messengers recovered from an iOS acquisition to surface targeted social-engineering, suspicious delivery URLs, unknown correspondents, and deleted-but-recoverable records.
---

# Communications Analysis

## When to Use
- Spyware hunt surfaced a message-vector hit (Pegasus one-click / zero-click)
- Incident involves social engineering, BEC, sextortion, or harassment
- Scoping who the subject communicated with during an incident window
- Recovering deleted messages / contacts / call history

## Goal
Reconstruct the subject's communication graph, surface anomalies, and extract durable evidence for any message / call that matters.

## Procedure

### 1. Inventory what's present
Before digging in, confirm what communication surfaces exist on this acquisition:
```
mvt_installed_apps
```
- Built-in (always): Messages (SMS/iMessage), Phone, Mail, FaceTime
- Common third-party: WhatsApp, Signal, Telegram, Wire, Wickr, WeChat, Line, Viber, Discord, Slack, Teams, iMessage with Business, Hangouts / Google Chat, Messenger

`ios_backup_list domain_filter="AppDomainGroup-group.net.whispersystems.signal.group"` and similar for any you want to investigate.

### 2. SMS / iMessage
```
mvt_sms_messages(source, iocs=<optional STIX>)
```
Extract `sms.db` for full-fidelity analysis:
```
ios_backup_extract(backup_dir, domain="HomeDomain",
                   relative_path="Library/SMS/sms.db",
                   output_dir="/tmp/ios-evidence/")
ios_sqlite_query(database=<extracted sms.db>, query="...")
```

Useful queries:
```sql
-- Message text + handle + date (Apple Cocoa timestamps)
SELECT m.rowid, h.id AS handle, m.is_from_me,
       datetime(m.date/1000000000 + 978307200, 'unixepoch') AS ts,
       m.service, m.text
FROM message m
LEFT JOIN handle h ON m.handle_id = h.rowid
ORDER BY m.date DESC LIMIT 500;

-- Threads with only one message received (often spam / lure)
SELECT h.id AS handle, COUNT(*) AS n,
       MIN(datetime(m.date/1000000000 + 978307200, 'unixepoch')) AS ts
FROM message m JOIN handle h ON m.handle_id = h.rowid
WHERE m.is_from_me = 0
GROUP BY h.id HAVING n = 1 ORDER BY ts DESC;

-- Messages containing URLs
SELECT h.id, m.text FROM message m
LEFT JOIN handle h ON m.handle_id = h.rowid
WHERE m.text LIKE '%http%' OR m.text LIKE '%://%';
```

Patterns to flag:
- Messages from short-code / unknown-country numbers with URLs → classic smishing / Pegasus lure
- "Your package is delayed…" / "You have a voicemail…" → phishing
- iMessage from email-format handles you don't recognize → potential targeting address
- Deleted-but-recoverable: rows in `message` where `chat_message_join` is missing or thread was purged → partial recovery possible
- Attachments table (`attachment`) with filenames that look like exploit artifacts (`.pdf`, `.gif`, `.html`, `.webarchive` from unusual senders)

### 3. Calls
```
mvt_calls(source)
```
For the fuller picture, extract and query `CallHistory.storedata`:
```
ios_backup_extract(backup_dir, "HomeDomain",
                   "Library/CallHistoryDB/CallHistory.storedata",
                   output_dir)
```
Columns of interest: `ZADDRESS` (number), `ZDATE` (Cocoa ts), `ZDURATION`, `ZORIGINATED` (0=incoming, 1=outgoing), `ZANSWERED`, `ZFACE_TIME_DATA`, `ZCALLTYPE`.

Flag:
- Very short unanswered incoming calls (duration 0, answered 0) from unknown numbers → social-engineering prep / FaceTime-based exploit probes
- FaceTime audio/video calls from unknown addresses (several 2022 QuaDream / Pegasus chains used FaceTime)
- Clusters of incoming/outgoing calls immediately before suspicious SMS activity

### 4. Contacts
```
mvt_run_module(source, module="contacts")
```
Or extract `AddressBook.sqlitedb` directly from `HomeDomain/Library/AddressBook/AddressBook.sqlitedb`. Useful for:
- Contacts added close to the incident window
- Contacts with only a handle (no name) but high message volume
- Contact labels that look placed (`Tech Support`, `Insurance Claim`, `HR`)

### 5. Mail
Mail is stored under `HomeDomain/Library/Mail/`. Envelope index:
```
ios_backup_list(backup_dir, domain_filter="HomeDomain",
                path_substring="Mail/V")
```
Extract `Envelope Index` (a SQLite DB) and query:
```sql
SELECT m.rowid, s.sender, su.subject,
       datetime(m.date_received, 'unixepoch') AS ts,
       m.size, m.flags
FROM messages m
LEFT JOIN addresses s ON m.sender = s.rowid
LEFT JOIN subjects su ON m.subject = su.rowid
ORDER BY m.date_received DESC LIMIT 200;
```

### 6. Third-party messengers
Each app keeps its own store — no universal schema. Common locations:
- Signal: `AppDomainGroup-group.net.whispersystems.signal.group/Documents/Signal.sqlite`
- WhatsApp: `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite`
- Telegram: `AppDomainGroup-ph.telegra.Telegraph/postbox/media/...`
- WeChat: `AppDomain-com.tencent.xin/Library/Application Support/MicroMessenger/.../MM.sqlite`

For each: list the domain with `ios_backup_list`, extract the primary SQLite, and apply query patterns similar to the SMS/messages analysis above. Pay attention to group memberships, invite links, and large media attachments from unknown senders.

### 7. Derive and re-sweep
Every suspicious URL, handle, phone number, email address, and attachment hash goes into a new STIX file:
- Re-run `mvt_check_iocs` with the augmented feed
- Share the feed with adjacent cases if appropriate

## Reporting
For every flagged communication: direction (incoming/outgoing), timestamp, remote handle, app / service, message excerpt, attachments, and the reason it was flagged (URL match / thread pattern / temporal correlation). Tie every claim to an extracted DB row.

## Common Pitfalls
- Believing thread deletion ≈ evidence gone — joined tables often still hold records
- Ignoring FaceTime (audio + video) — historical iOS exploit chains used it
- Treating iMessage handles as phone-numbers — email-format handles are common and easily spoofed-looking
- Missing `attachment` rows — the binary bytes live as backup files; follow the `filename` column into the backup
- Reading Apple Cocoa timestamps as Unix — they're seconds since 2001-01-01 (add 978307200 if stored as seconds, or divide by 1e9 first if nanoseconds)
