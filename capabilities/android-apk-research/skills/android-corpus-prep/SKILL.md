---
name: android-corpus-prep
description: "Use when preparing Android APK corpora — AndroZoo metadata download, popular-package selection via DuckDB, APK download from Play or AndroZoo, and per-pass provenance manifests."
allowed-tools:
  - run_corpus_inventory
  - bash
  - read
  - grep
  - glob
  - web_search
  - web_extract
  - report
license: MIT
---

# Android corpus preparation

Use this skill when the user needs APKs to analyze, wants a popular/common Android app corpus, or asks how to select targets from AndroZoo / F-Droid / device extraction. The flow is **scripts + DuckDB on Parquet** end-to-end; the only LLM tool in this skill is `run_corpus_inventory` (called after APKs are on disk).

## Outcome

Produce a reproducible corpus manifest that answers:

- where each package/APK came from
- why it was selected
- which exact SHA256/version was downloaded
- what authorization/provenance constraints apply
- where the APK files and manifests live

## Corpus layout (mandatory)

Organize every corpus pass as a self-contained directory under `corpus/passes/`. The pass directory — not the downloader — owns the APKs.

```
corpus/
├── shared/
│   └── androzoo-meta/              # AndroZoo metadata (gz + parquet), shared across passes
├── selections/                      # Exploratory target lists not tied to any pass
└── passes/
    └── corpus-N/
        ├── selection.jsonl          # Input target list
        ├── manifest-gplaydl.jsonl   # Per-source download manifests
        ├── manifest-androzoo.jsonl  # (only sources actually used)
        ├── apks/                    # All APKs for this pass, regardless of source
        ├── logs/                    # Downloader stdout/stderr, smoke runs, .tmp files
        └── README.md                # What the pass is and how to feed it forward
```

Rules:

- **One pass = one directory.** Never split APKs from the same pass across multiple folders based on which downloader produced them.
- `apks/` is the only place APKs live. `source` (`gplaydl`, `androzoo`, ...) is recorded as a field in the manifest row, not in the path.
- AndroZoo metadata files (`*.csv.gz`, `*.jsonl.gz`, Parquet) live under `corpus/shared/androzoo-meta/` — they are corpus-independent and 9 GB+.
- Exploratory target lists that don't correspond to a real download pass go to `corpus/selections/`.
- Manifest `path` fields must point at `corpus/passes/corpus-N/apks/...`.

## AndroZoo metadata-first path

This is the preferred path for popular/common APK hunting.

### 1. Fetch the metadata sources

```bash
# Google Play metadata aggregate (~1.3 GB gzipped JSONL).
python3 scripts/androzoo_gp_metadata.py download \
  --kind aggregate \
  --out corpus/shared/androzoo-meta/gp-metadata-aggregate.jsonl.gz \
  --progress

# AndroZoo APK index (~3.6 GB gzipped CSV).
curl -L -o corpus/shared/androzoo-meta/latest_with-added-date.csv.gz \
  https://androzoo.uni.lu/static/lists/latest_with-added-date.csv.gz
```

### 2. Convert both sources to ZSTD Parquet (one-time)

The shipped sources are large gzipped files you will join against repeatedly during corpus selection. Convert them to Parquet once. Working set drops 5–10× and DuckDB pushes predicates and column projections into the scan.

```bash
# ~80s for the JSONL, ~30s for the CSV on a Mac M-series.
python3 scripts/androzoo_to_parquet.py csv \
  corpus/shared/androzoo-meta/latest_with-added-date.csv.gz \
  corpus/shared/androzoo-meta/parquet/androzoo_latest.parquet

python3 scripts/androzoo_to_parquet.py json \
  corpus/shared/androzoo-meta/gp-metadata-aggregate.jsonl.gz \
  corpus/shared/androzoo-meta/parquet/androzoo_gp_metadata.parquet
```

What the script does that matters:

- CSV path runs the DuckDB CLI through a named pipe so the 7 GB decompressed CSV is never written to disk. Output ~3 GB Parquet.
- JSONL path uses **streaming pyarrow** with an **explicit schema**. DuckDB's `read_json` schema sniffer OOMs at 6 GB on the 1.3 GB source — never sniff a multi-GB JSONL. Nested `related_apks_in_AZ_info` is JSON-stringified into a single TEXT column to preserve round-trip without pulling List<Struct> typing in.

### 3. Materialize a popular-clean candidate set once per refresh

Run the popular-package selection + clean-Play-APK join straight in DuckDB. On a ~15k popular-package candidate set this is seconds with <200 MB peak RAM, and the output Parquet is ~1.3 MB — re-queryable in milliseconds:

```bash
duckdb -c "
COPY (
  WITH popular AS (
    SELECT pkg_name, max_nb_downloads AS dl, max_star_rating AS rating, max_ratingsCount AS ratings
    FROM 'corpus/shared/androzoo-meta/parquet/androzoo_gp_metadata.parquet'
    WHERE max_nb_downloads >= 10000000
      AND max_star_rating >= 3.5
      AND max_ratingsCount >= 1000
  ),
  candidates AS (
    SELECT
      l.sha256, l.pkg_name, l.vercode, l.apk_size, l.markets, l.added, l.vt_detection, l.dex_date,
      p.dl, p.rating, p.ratings,
      ROW_NUMBER() OVER (PARTITION BY l.pkg_name ORDER BY l.added DESC NULLS LAST, l.vercode DESC) AS rn
    FROM 'corpus/shared/androzoo-meta/parquet/androzoo_latest.parquet' l
    JOIN popular p USING (pkg_name)
    WHERE l.markets LIKE '%play.google.com%'
      AND coalesce(try_cast(l.vt_detection AS INTEGER), 0) <= 0
      AND coalesce(try_cast(l.apk_size AS BIGINT), 0) BETWEEN 1000000 AND 200000000
  )
  SELECT * EXCLUDE rn FROM candidates WHERE rn = 1
) TO 'corpus/shared/androzoo-meta/parquet/popular_latest_clean.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
"
```

Use this as the canonical input for per-corpus filter passes (banking, messaging, healthcare, etc.). Cuts the cost of "try a different filter" from 30s to 50ms.

### 4. Per-pass filter → selection.jsonl

Pick the subset for this pass with a focused DuckDB query against the canonical candidate set. Examples:

```bash
# Wallets — selection.jsonl with the columns the downloaders need.
# Tune the LIKE / IN lists for the target class; the example below is purely illustrative.
duckdb -c "
COPY (
  SELECT pkg_name AS package, sha256, vercode AS version_code, apk_size, dl, rating
  FROM 'corpus/shared/androzoo-meta/parquet/popular_latest_clean.parquet'
  WHERE lower(pkg_name) LIKE ANY ('%wallet%','%crypto%','%coin%','%defi%')
  ORDER BY dl DESC
  LIMIT 30
) TO 'corpus/passes/corpus-wallet/selection.jsonl' (FORMAT JSON);
"
```

### 5. Download the APKs

```bash
mkdir -p corpus/passes/corpus-wallet/{apks,logs}
```

**Primary — `gplaydl_bulk.py` for any selection that targets currently-listed Play apps.** Roughly 30–60× faster than AndroZoo per APK and needs no API key (anonymous Google Play auth via [Aurora Store](https://auroraoss.com/)'s public token dispenser):

```bash
python3 scripts/gplaydl_bulk.py \
  corpus/passes/corpus-wallet/selection.jsonl \
  --out-dir       corpus/passes/corpus-wallet/apks \
  --manifest-out  corpus/passes/corpus-wallet/manifest-gplaydl.jsonl \
  --jobs 8
```

The selection JSONL needs at minimum `{"package": "com.foo"}` per line; the script ignores `sha256` because Google Play serves the current version directly. Failures are written to the manifest; common errors are "App not found" (delisted) and "No download URL returned" (region-locked or paid).

**Fallback — `androzoo_download.py` for delisted, paid, or AndroZoo-only historical versions.** `--out-dir` is the SAME `apks/` directory as the gplaydl primary; the pass directory is the unit, not the downloader.

```bash
python3 scripts/androzoo_download.py \
  corpus/passes/corpus-wallet/fallback-androzoo-selection.jsonl \
  --out-dir       corpus/passes/corpus-wallet/apks \
  --manifest-out  corpus/passes/corpus-wallet/manifest-androzoo.jsonl \
  --jobs 10
```

AndroZoo throttles each connection to ~440 KB/s but allows ~20 concurrent. The default `--jobs 12` is a safe sweet spot. Use `--api-key-file` or `ANDROZOO_API_KEY` env var; never inline the key.

**Empirical comparison on an 89-package, 6.8 GB corpus:**

| Path | Wall time | Speed |
|---|---|---|
| `gplaydl_bulk` jobs=6 (78 succeed) + AndroZoo fallback (10 left) | ~10 min total | ~12 MB/s aggregate |
| Old serial AndroZoo only | ~3 h | ~440 KB/s |

See `../android-semantic-vuln-hunting/references/corpus-acquisition.md` for the full source-by-source landscape, terms, and tradeoffs.

## Other corpus sources

Read `../android-semantic-vuln-hunting/references/corpus-acquisition.md` before recommending a source. Short version:

- User-provided/internal APKs are best for actionable findings.
- Official device extraction is best for curated popular apps when authorization/terms allow.
- F-Droid is best for clean smoke testing and reproducible open-source samples.
- APK mirrors are fallback only; record URL, timestamp, version, SHA256, and signature/provenance caveats.

## Selection bias for semantic bugs

Prioritize packages with likely high-impact logic:

- account/login/session flows
- OAuth, SSO, identity, wallet, payments
- retail/travel/loyalty/telecom/health/enterprise SaaS
- WebView-heavy hybrid flows
- partner/campaign/shortlink/deferred deep link SDKs
- file sharing, messaging, documents, support chat
- React Native, Flutter, Cordova, Capacitor bridges

Avoid spending first-pass cycles on simple utilities, games, launchers, or static content unless metadata/inventory suggests rich entrypoints.

## Output manifest

For every corpus pass, preserve JSONL like:

```json
{"package":"com.example","title":"Example","selection_reason":"wallet keyword + high downloads","source":"androzoo","sha256":"...","version_code":"123","path":"corpus/passes/corpus-N/apks/com.example_123_deadbeef.apk","selection":"corpus/passes/corpus-N/selection.jsonl"}
```

`source` is the downloader (`gplaydl`, `androzoo`, ...) — it's metadata on the row, not a directory in the path. Use the manifest as the entrypoint for later inventory, decompilation, and reporting.

## Hand off to inventory

Once APKs are on disk, run `run_corpus_inventory` to produce SHA256-keyed artifact directories with Androguard manifest decoding and optional APKiD packer detection. That output drives the semantic-vuln-hunting pipeline.

```python
run_corpus_inventory(
    paths=["corpus/passes/corpus-N/apks"],
    out_dir="findings/corpus-N/inventory",
    jobs=8,
    include_apkid=True,
)
```

One pass directory → one inventory directory. Don't mix passes in a single inventory unless you've thought through how findings will attribute back.
