#!/usr/bin/env python3
"""Download and query AndroZoo Google Play metadata aggregate files."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

AGG_URL = "https://androzoo.uni.lu/api/get_gp_metadata_file/aggregate"
FULL_URL = "https://androzoo.uni.lu/api/get_gp_metadata_file/full"


def api_key(args: argparse.Namespace) -> str:
    if getattr(args, "api_key", None):
        return args.api_key.strip()
    if getattr(args, "api_key_file", None):
        return Path(args.api_key_file).expanduser().read_text().strip()
    key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    if key:
        return key
    raise SystemExit(
        "AndroZoo API key required via --api-key, --api-key-file, or ANDROZOO_API_KEY"
    )


def download(args: argparse.Namespace) -> int:
    key = api_key(args)
    endpoint = AGG_URL if args.kind == "aggregate" else FULL_URL
    url = endpoint + "?" + urllib.parse.urlencode({"apikey": key})
    out = args.out or Path(f"gp-metadata-{args.kind}.jsonl.gz")
    out.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(
        url, headers={"User-Agent": "dreadnode-android-apk-research/0.1"}
    )
    with (
        urllib.request.urlopen(req, timeout=args.timeout) as resp,
        out.open("wb") as fh,
    ):
        total = int(resp.headers.get("content-length") or 0)
        done = 0
        last = time.time()
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            if args.progress and time.time() - last > 5:
                pct = f"{done / total * 100:.1f}%" if total else "?%"
                print(
                    json.dumps(
                        {
                            "downloaded": done,
                            "total": total,
                            "pct": pct,
                            "out": str(out),
                        }
                    ),
                    file=sys.stderr,
                )
                last = time.time()
    print(json.dumps({"out": str(out), "bytes": out.stat().st_size}, sort_keys=True))
    return 0


def open_jsonl(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return path.open("r", errors="replace")


def get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def walk_values(
    obj: Any, key_regex: re.Pattern[str], values: list[Any], limit: int = 20
) -> None:
    if len(values) >= limit:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if key_regex.search(k):
                values.append(v)
                if len(values) >= limit:
                    return
            walk_values(v, key_regex, values, limit)
    elif isinstance(obj, list):
        for v in obj:
            walk_values(v, key_regex, values, limit)
            if len(values) >= limit:
                return


def first_value_by_key(obj: Any, pattern: str) -> Any:
    vals: list[Any] = []
    walk_values(obj, re.compile(pattern, re.I), vals, limit=1)
    return vals[0] if vals else None


def as_float(v: Any, default: float = -1.0) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.replace(",", ""))
        except ValueError:
            return default
    return default


def as_int(v: Any, default: int = -1) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        digits = re.sub(r"[^0-9]", "", v)
        if digits:
            try:
                return int(digits)
            except ValueError:
                return default
    return default


def extract_record(obj: dict[str, Any]) -> dict[str, Any]:
    pkg = (
        obj.get("pkg_name")
        or obj.get("package")
        or obj.get("packageName")
        or first_value_by_key(obj, r"^(docid|packageName|package)$")
    )
    title = (
        obj.get("title")
        or obj.get("name")
        or first_value_by_key(obj, r"title|appTitle|name")
    )
    max_downloads = (
        obj.get("max_numDownloads")
        or obj.get("max_downloads")
        or obj.get("details.appDetails.numDownloads")
        or first_value_by_key(obj, r"numDownloads|downloads")
    )
    max_rating = (
        obj.get("max_star_rating")
        or obj.get("max_starRating")
        or obj.get("max_rating")
        or first_value_by_key(obj, r"star.?rating|rating")
    )
    ratings_count = (
        obj.get("max_ratingsCount")
        or obj.get("max_rating_count")
        or first_value_by_key(obj, r"ratingsCount|ratingCount")
    )
    comment_count = obj.get("max_commentCount") or first_value_by_key(
        obj, r"commentCount|reviewCount"
    )
    category = (
        obj.get("category")
        or obj.get("appCategory")
        or first_value_by_key(obj, r"category|genre")
    )
    version_code = (
        obj.get("max_versionCode")
        or obj.get("versionCode")
        or first_value_by_key(obj, r"versionCode")
    )
    return {
        "package": pkg,
        "title": title,
        "category": category,
        "max_downloads": as_int(max_downloads),
        "max_star_rating": as_float(max_rating),
        "max_ratings_count": as_int(ratings_count),
        "max_comment_count": as_int(comment_count),
        "version_code_hint": str(version_code) if version_code is not None else None,
        "az_metadata_date": obj.get("az_metadata_date")
        or first_value_by_key(obj, r"az_metadata_date"),
        "raw_keys": sorted(obj.keys())[:80],
    }


def matches(rec: dict[str, Any], args: argparse.Namespace) -> bool:
    if not rec.get("package"):
        return False
    if (
        args.min_downloads is not None
        and rec.get("max_downloads", -1) < args.min_downloads
    ):
        return False
    if (
        args.min_rating is not None
        and rec.get("max_star_rating", -1.0) < args.min_rating
    ):
        return False
    if (
        args.min_ratings_count is not None
        and rec.get("max_ratings_count", -1) < args.min_ratings_count
    ):
        return False
    hay = " ".join(
        str(rec.get(k) or "") for k in ["package", "title", "category"]
    ).lower()
    if args.keyword and not any(k.lower() in hay for k in args.keyword):
        return False
    if args.package_contains and not any(
        k.lower() in str(rec.get("package") or "").lower()
        for k in args.package_contains
    ):
        return False
    return True


def select(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    selected: list[dict[str, Any]] = []
    seen = matched = 0
    with open_jsonl(args.metadata_path) as fh:
        for line in fh:
            if not line.strip():
                continue
            seen += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            rec = extract_record(obj)
            if not matches(rec, args):
                continue
            matched += 1
            if args.sample:
                if len(selected) < args.limit:
                    selected.append(rec)
                else:
                    j = rng.randrange(matched)
                    if j < args.limit:
                        selected[j] = rec
            else:
                selected.append(rec)
                if len(selected) >= args.limit:
                    break
    selected.sort(
        key=lambda r: (r.get("max_downloads", -1), r.get("max_ratings_count", -1)),
        reverse=True,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in selected))
    print(
        json.dumps(
            {
                "seen": seen,
                "matched": matched,
                "written": len(selected),
                "out": str(args.out),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Download/query AndroZoo Google Play metadata"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    dl = sub.add_parser(
        "download", help="Download gp-metadata aggregate/full JSONL gzip"
    )
    dl.add_argument("--kind", choices=["aggregate", "full"], default="aggregate")
    dl.add_argument("--out", type=Path)
    dl.add_argument("--api-key")
    dl.add_argument("--api-key-file")
    dl.add_argument("--timeout", type=int, default=120)
    dl.add_argument("--progress", action="store_true")
    dl.set_defaults(func=download)

    sel = sub.add_parser(
        "select", help="Select packages from gp-metadata aggregate JSONL(.gz)"
    )
    sel.add_argument("metadata_path", type=Path)
    sel.add_argument("--out", type=Path, required=True)
    sel.add_argument("--limit", type=int, default=100)
    sel.add_argument("--sample", action="store_true")
    sel.add_argument("--seed", type=int, default=1337)
    sel.add_argument("--min-downloads", type=int, default=1_000_000)
    sel.add_argument("--min-rating", type=float, default=3.5)
    sel.add_argument("--min-ratings-count", type=int, default=1_000)
    sel.add_argument(
        "--keyword",
        action="append",
        help="Keyword in package/title/category; repeatable",
    )
    sel.add_argument(
        "--package-contains",
        action="append",
        help="Substring in package name; repeatable",
    )
    sel.set_defaults(func=select)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
