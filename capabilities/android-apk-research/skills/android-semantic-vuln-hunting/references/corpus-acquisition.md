# APK corpus acquisition

Use this reference when the user wants popular or common APKs for research. The goal is a lawful, reproducible corpus with provenance, not a mystery folder of binaries.

## Best options

### 1. User-provided owned or authorized APKs

Best for actionable findings. Ask the user to provide:

- APK directory path
- authorization/scope note
- app category or package list
- whether dynamic validation is allowed
- whether test accounts are available

### 2. `gplaydl` (PyPI) — anonymous Google Play, recommended primary

For *currently-listed* Play apps this is now the fastest path. `gplaydl` (v2.x, March 2026, actively maintained) authenticates anonymously via [Aurora Store](https://auroraoss.com/)'s public token dispenser, rotating ~20 device profiles. No Google account, no API key.

- PyPI: https://pypi.org/project/gplaydl/
- Source: https://github.com/rehmatworks/gplaydl
- Speed: **~20-25 MB/s per stream** against Google's CDN, scales with parallelism. Roughly 30-60× faster than AndroZoo per APK in our measurements.
- Use `scripts/gplaydl_bulk.py` for bounded parallel JSONL-driven bulk pulls.

**Cannot fetch:**
- delisted apps (Zenly, Facebook Lite, old Outlook Lite, Kiwi Browser, etc.)
- paid apps (Threema, OnePassword 7, etc.)
- region-locked apps under the current token's locale
- beta-channel-only apps

For all of those, fall back to AndroZoo (below).

**Terms note.** This operates in a gray zone of Google's ToS. Aurora's dispenser uses accounts provisioned for anonymous read access; Google has tolerated this for years but never blessed it. Appropriate for research, not for commercial redistribution. Don't abuse Aurora's free public dispenser — keep parallelism ≤ 8 for normal corpora.

### 3. AndroZoo — historical, paid, and delisted apps

AndroZoo is the standard research corpus for Android APKs and metadata. It requires access/API key approval and supports reproducible selection by package, market, date, size, VT metadata, and hash.

- Project: https://androzoo.uni.lu/
- Catalog: 27 M APK rows, 4.4 M packages, multi-market (Play + 14 others). Historical versions retained.
- **Throughput: ~440 KB/s per connection, up to ~20 concurrent. Plan accordingly.**
- Quota: 500,000 APKs per 6-month key cycle.
- Use when you need historical versions, delisted apps, or paid apps that researchers have archived.
- Selection: convert `latest_with-added-date.csv.gz` + `gp-metadata-aggregate.jsonl.gz` to Parquet (`scripts/androzoo_to_parquet.py`) once, then run DuckDB queries against the columnar files.
- Keep the query that produced the corpus so findings can be reproduced.

### 4. Official store/device extraction

Good for testing “popular APKs” without relying on mirror sites:

- Install apps from Google Play on a test device/account where terms and authorization permit.
- Extract installed package paths with `adb shell pm path <package>`.
- Pull APK splits with `adb pull`.
- Preserve package name, version, split list, and install source.

Example:

```bash
adb shell pm list packages | sed 's/package://' > packages.txt
adb shell pm path com.example.app
adb pull /data/app/.../base.apk corpus/com.example.app/base.apk
```

Split APKs/APK bundles may need all split files, not only `base.apk`.

### 4. F-Droid

Best fully open-source corpus for pipeline debugging, but less representative of high-impact consumer-account logic.

- Repo/index: https://f-droid.org/repo/index-v1.json
- Advantages: clear licensing/provenance, easy downloads, source code available for validation.
- Limitation: fewer finance/retail/identity targets and less closed-source routing/SDK complexity.

### 5. APKMirror / APKPure style mirrors

Use cautiously. They are convenient for popular APKs but weaker on authorization, provenance, terms, and reproducibility. If used, record exact URL, SHA256, package, version, and download time. Prefer official/device extraction or AndroZoo for serious research.

## Strong target profile for semantic logic bugs

Prioritize apps with:

- login/account/session flows
- OAuth/Social login/SSO
- payments, wallet, bank, travel, retail, telecom, health, identity, enterprise SaaS
- many deep links/App Links/custom schemes
- WebView-heavy hybrid flows
- partner/campaign/shortlink domains
- push notification/deferred deep link SDKs
- file sharing, messaging, attachments, documents, or support chat
- React Native/Flutter/Capacitor/Cordova bridges

Avoid spending early cycles on games, static content apps, or tiny utilities unless inventory shows rich entrypoints.

## Practical first corpus

For the first capability test, use 20-50 APKs:

1. 5-10 known vulnerable/training APKs to sanity-check detection behavior.
2. 10-20 F-Droid or internal apps to exercise scale and references legally.
3. 10-20 popular apps obtained through AndroZoo or official device extraction if available.

Keep a manifest:

```json
{"package":"com.example","version":"1.2.3","source":"androzoo|device|fdroid|user","sha256":"...","downloaded_at":"...","notes":"..."}
```

## Selection query ideas

- Size below 55 MB at first; decompilation and LLM slicing are cheaper.
- Recent releases from the last 12-24 months.
- Exclude obvious malware-only feeds for this workflow unless the user wants malware analysis.
- Include categories where auth/session/payment/data logic matters.
- Deduplicate by package and keep the newest version plus one older version if regression hunting is useful.




## Google Play metadata aggregate for popularity-based selection

AndroZoo's Google Play metadata page is the best way to find *popular* targets before selecting APK hashes. The aggregate file has one JSONL record per app and includes aggregated fields such as star ratings, rating/comment counts, and download counts. It is Google Play-only. If used in research output, cite the AndroZoo 2024 metadata paper in addition to the 2016 AndroZoo paper when APKs are used.

Capability boundary:

- Run large downloads as operator-supervised scripts: `scripts/androzoo_gp_metadata.py download`, `scripts/androzoo_to_parquet.py`, and `scripts/androzoo_download.py` (or `scripts/gplaydl_bulk.py` for currently-listed Play apps).
- Selection itself is `duckdb -c "SELECT ..."` against the Parquet files produced by `androzoo_to_parquet.py` — see the `android-corpus-prep` skill for the canonical popular-package / impact-class selection recipe.

Download aggregate metadata:

```bash
python3 scripts/androzoo_gp_metadata.py download \
  --kind aggregate \
  --out corpus/androzoo/meta/gp-metadata-aggregate.jsonl.gz \
  --progress
```

Convert both shipped sources to ZSTD Parquet once, then query with DuckDB. See the `android-corpus-prep` skill for the canonical recipe — popular-package selection plus clean-Play-APK join in seconds, sub-200 MB peak RAM.

Download selected APKs. The key is read from `ANDROZOO_API_KEY`; do not pass it inline unless necessary:

```bash
python3 scripts/androzoo_download.py \
  corpus/androzoo/apk-selection.jsonl \
  --out-dir corpus/androzoo/apks \
  --manifest-out corpus/androzoo/download_manifest.jsonl \
  --sleep 0.5
```

Important limitations:

- App-level metadata fields reflect the date metadata was acquired, not necessarily the version release date. Use them for target selection, not historical claims about a specific APK version.
- AndroZoo asks users to keep concurrency modest; the downloader is sequential by default.
