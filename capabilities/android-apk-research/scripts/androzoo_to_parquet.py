#!/usr/bin/env python3
"""Convert AndroZoo metadata sources to ZSTD Parquet for cheap repeated joins.

Two inputs:

- ``latest_with-added-date.csv.gz`` — multi-GB row-per-APK CSV. Converted via the
  DuckDB CLI piping a gunzip stream through a named pipe so we never land the
  decompressed 7 GB on disk. The whole CSV becomes ~3 GB ZSTD Parquet.
- ``gp-metadata-aggregate.jsonl.gz`` — multi-GB row-per-package JSONL with one
  nested ``related_apks_in_AZ_info`` dict and a few list-typed fields. We
  stream-decompress with Python, normalize the lists into ``"; "`` joined strings,
  serialize the nested dict to a JSON text column, and write fixed-schema Parquet
  with pyarrow. Memory stays at one batch (default 25k rows).

Why not let DuckDB sniff the JSONL schema? On a 1.3 GB file it OOM'd at the
schema-inference stage at 6 GB. Explicit schema + Python streaming keeps the
working set bounded and the columns typed.

Usage:

    androzoo_to_parquet.py csv  corpus/androzoo/meta/latest_with-added-date.csv.gz \\
                                corpus/androzoo/meta/parquet/androzoo_latest.parquet
    androzoo_to_parquet.py json corpus/androzoo/meta/gp-metadata-aggregate.jsonl.gz \\
                                corpus/androzoo/meta/parquet/androzoo_gp_metadata.parquet

The output files are the canonical input to DuckDB / Polars / pandas joins. Both
keep the original semantics (no rows dropped, no columns renamed) so they are a
drop-in replacement for the gz sources.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def _which_duckdb() -> str:
    path = shutil.which("duckdb")
    if not path:
        raise SystemExit(
            "duckdb CLI not on PATH; brew install duckdb or install the platform binary"
        )
    return path


def convert_csv(
    src: Path, dst: Path, memory_limit: str = "6GB", threads: int = 4
) -> dict[str, Any]:
    """Convert the AndroZoo CSV(.gz) to Parquet via DuckDB through a named pipe."""
    duckdb = _which_duckdb()
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="azcsv_"))
    pipe = tmp_dir / "csv.fifo"
    os.mkfifo(pipe)
    started = time.time()
    if src.suffix == ".gz":
        decomp = subprocess.Popen(["gzip", "-dc", str(src)], stdout=open(pipe, "wb"))
    else:
        decomp = subprocess.Popen(["cat", str(src)], stdout=open(pipe, "wb"))
    try:
        sql = (
            f"SET memory_limit='{memory_limit}';\n"
            f"SET threads={threads};\n"
            "COPY ("
            f"  SELECT * FROM read_csv('{pipe}', header=true, all_varchar=true)"
            ") TO '"
            + str(dst)
            + "' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);"
        )
        proc = subprocess.run(
            [duckdb, "-c", sql], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            return {
                "status": "error",
                "stderr": proc.stderr[-4000:],
                "stdout": proc.stdout[-4000:],
            }
    finally:
        decomp.wait()
        try:
            pipe.unlink()
        except FileNotFoundError:
            pass
        tmp_dir.rmdir()
    return {
        "status": "ok",
        "duration_sec": round(time.time() - started, 2),
        "src": str(src),
        "dst": str(dst),
        "dst_size_bytes": dst.stat().st_size,
    }


# --- JSONL → Parquet -----------------------------------------------------------------

import pyarrow as pa
import pyarrow.parquet as pq

GP_SCHEMA = pa.schema(
    [
        ("pkg_name", pa.string()),
        ("nb_meta", pa.int64()),
        ("nb_versionCode", pa.int64()),
        ("min_versionCode", pa.int64()),
        ("max_versionCode", pa.int64()),
        ("first_seen", pa.string()),
        ("last_seen", pa.string()),
        ("min_star_rating", pa.float64()),
        ("max_star_rating", pa.float64()),
        ("min_ratingsCount", pa.int64()),
        ("max_ratingsCount", pa.int64()),
        ("min_commentCount", pa.int64()),
        ("max_commentCount", pa.int64()),
        ("min_upload_date", pa.string()),
        ("max_upload_date", pa.string()),
        ("min_nb_downloads", pa.int64()),
        ("max_nb_downloads", pa.int64()),
        ("min_installationSize", pa.int64()),
        ("max_installationSize", pa.int64()),
        ("developerName", pa.string()),
        ("developerEmail", pa.string()),
        ("developerWebsite", pa.string()),
        ("developerAddress", pa.string()),
        ("related_apks_in_AZ_info_json", pa.string()),
    ]
)


def _coerce_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _join_list(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        return "; ".join(str(x) for x in v if x is not None) or None
    return str(v)


def _coerce_gp_row(o: dict[str, Any]) -> dict[str, Any]:
    nested = o.get("related_apks_in_AZ_info")
    return {
        "pkg_name": o.get("pkg_name"),
        "nb_meta": o.get("nb_meta"),
        "nb_versionCode": o.get("nb_versionCode"),
        "min_versionCode": o.get("min_versionCode"),
        "max_versionCode": o.get("max_versionCode"),
        "first_seen": o.get("first_seen"),
        "last_seen": o.get("last_seen"),
        "min_star_rating": _coerce_float(o.get("min_star_rating")),
        "max_star_rating": _coerce_float(o.get("max_star_rating")),
        "min_ratingsCount": o.get("min_ratingsCount"),
        "max_ratingsCount": o.get("max_ratingsCount"),
        "min_commentCount": o.get("min_commentCount"),
        "max_commentCount": o.get("max_commentCount"),
        "min_upload_date": o.get("min_upload_date"),
        "max_upload_date": o.get("max_upload_date"),
        "min_nb_downloads": o.get("min_nb_downloads"),
        "max_nb_downloads": o.get("max_nb_downloads"),
        "min_installationSize": o.get("min_installationSize"),
        "max_installationSize": o.get("max_installationSize"),
        "developerName": _join_list(o.get("developerName")),
        "developerEmail": _join_list(o.get("developerEmail")),
        "developerWebsite": _join_list(o.get("developerWebsite")),
        "developerAddress": _join_list(o.get("developerAddress")),
        "related_apks_in_AZ_info_json": json.dumps(nested, separators=(",", ":"))
        if nested
        else None,
    }


def convert_gp_jsonl(
    src: Path, dst: Path, batch_size: int = 25_000, progress: bool = True
) -> dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    total = 0
    batch: list[dict[str, Any]] = []
    open_fn = gzip.open if src.suffix == ".gz" else open
    writer = pq.ParquetWriter(str(dst), GP_SCHEMA, compression="zstd")
    try:
        with open_fn(src, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                batch.append(_coerce_gp_row(obj))
                if len(batch) >= batch_size:
                    writer.write_table(pa.Table.from_pylist(batch, schema=GP_SCHEMA))
                    total += len(batch)
                    batch.clear()
                    if progress and total % (batch_size * 10) == 0:
                        elapsed = time.time() - started
                        print(
                            f"  {total:>12,} rows  {elapsed:6.1f}s  ({total/elapsed:,.0f} rps)",
                            file=sys.stderr,
                        )
        if batch:
            writer.write_table(pa.Table.from_pylist(batch, schema=GP_SCHEMA))
            total += len(batch)
    finally:
        writer.close()
    return {
        "status": "ok",
        "duration_sec": round(time.time() - started, 2),
        "rows": total,
        "src": str(src),
        "dst": str(dst),
        "dst_size_bytes": dst.stat().st_size,
    }


# --- CLI -----------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert AndroZoo metadata to ZSTD Parquet"
    )
    sub = ap.add_subparsers(dest="kind", required=True)

    p_csv = sub.add_parser("csv", help="Convert latest.csv(.gz) -> Parquet via DuckDB")
    p_csv.add_argument("src", type=Path)
    p_csv.add_argument("dst", type=Path)
    p_csv.add_argument("--memory-limit", default="6GB")
    p_csv.add_argument("--threads", type=int, default=4)

    p_json = sub.add_parser(
        "json", help="Convert gp-metadata-aggregate.jsonl(.gz) -> Parquet (streamed)"
    )
    p_json.add_argument("src", type=Path)
    p_json.add_argument("dst", type=Path)
    p_json.add_argument("--batch-size", type=int, default=25_000)
    p_json.add_argument("--no-progress", action="store_true")

    args = ap.parse_args()
    if args.kind == "csv":
        result = convert_csv(
            args.src.expanduser().resolve(),
            args.dst.expanduser().resolve(),
            memory_limit=args.memory_limit,
            threads=args.threads,
        )
    else:
        result = convert_gp_jsonl(
            args.src.expanduser().resolve(),
            args.dst.expanduser().resolve(),
            batch_size=args.batch_size,
            progress=not args.no_progress,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
