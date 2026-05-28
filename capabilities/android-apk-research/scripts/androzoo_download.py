#!/usr/bin/env python3
"""Download APKs from AndroZoo for a JSONL selection manifest.

The API key is read from --api-key, ANDROZOO_API_KEY, or a file specified by
--api-key-file. The key is never written to the output manifest.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import threading
import time
import shutil
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator

API_URL = "https://androzoo.uni.lu/api/download"


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Stream the selection JSONL line by line.

    Previous implementation loaded the whole file via read_text().splitlines();
    fine for small selections but the same anti-pattern we fixed elsewhere.
    """
    with path.open("r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("sha256"):
                yield obj


def api_key(args: argparse.Namespace) -> str:
    if args.api_key:
        return args.api_key.strip()
    if args.api_key_file:
        return Path(args.api_key_file).expanduser().read_text().strip()
    key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    if key:
        return key
    raise SystemExit(
        "AndroZoo API key required via --api-key, --api-key-file, or ANDROZOO_API_KEY"
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(row: dict[str, Any]) -> str:
    pkg = str(row.get("package") or "unknown").replace("/", "_")
    vc = str(row.get("version_code") or "novc").replace("/", "_")
    sha = str(row["sha256"])
    return f"{pkg}_{vc}_{sha[:12]}.apk"


def download_one(
    row: dict[str, Any], key: str, out_dir: Path, timeout: int, force: bool
) -> dict[str, Any]:
    out_path = out_dir / safe_name(row)
    expected = str(row["sha256"]).lower()
    result = dict(row)
    result["path"] = str(out_path)
    if out_path.exists() and not force:
        actual = sha256_file(out_path)
        result["download_status"] = "exists"
        result["downloaded_sha256"] = actual
        result["sha256_ok"] = actual.lower() == expected
        return result
    params = urllib.parse.urlencode({"apikey": key, "sha256": row["sha256"]})
    url = f"{API_URL}?{params}"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "dreadnode-android-apk-research/0.1"}
        )
        tmp_path = out_path.with_suffix(out_path.suffix + ".part")
        # Stream the response to disk so we never hold a 200 MB APK in RAM.
        # The previous resp.read() landed the whole body in memory before write.
        with (
            urllib.request.urlopen(req, timeout=timeout) as resp,
            tmp_path.open("wb") as out_fh,
        ):
            shutil.copyfileobj(resp, out_fh, length=1024 * 1024)
        tmp_path.replace(out_path)
        actual = sha256_file(out_path)
        result["download_status"] = "downloaded"
        result["downloaded_sha256"] = actual
        result["sha256_ok"] = actual.lower() == expected
        if not result["sha256_ok"]:
            result["error"] = "sha256 mismatch"
    except Exception as exc:  # noqa: BLE001 - written to manifest for retry decisions.
        result["download_status"] = "error"
        result["error"] = str(exc)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Download APKs from AndroZoo using a JSONL selection manifest"
    )
    ap.add_argument(
        "selection_jsonl",
        type=Path,
        help="APK selection JSONL (one row per APK with at least 'sha256'; see android-corpus-prep skill)",
    )
    ap.add_argument(
        "--out-dir", type=Path, required=True, help="Directory to write APKs"
    )
    ap.add_argument(
        "--manifest-out",
        type=Path,
        help="Download manifest JSONL; default <out-dir>/download_manifest.jsonl",
    )
    ap.add_argument(
        "--api-key",
        help="AndroZoo API key. Prefer ANDROZOO_API_KEY or --api-key-file to avoid shell history exposure",
    )
    ap.add_argument("--api-key-file", help="File containing AndroZoo API key")
    ap.add_argument(
        "--limit", type=int, help="Download at most this many selected rows"
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=12,
        help="Parallel downloads. AndroZoo throttles each connection to ~440 KB/s but allows "
        "up to ~20 concurrent downloads per their API docs. 12 is a safe default. Pass 1 for serial.",
    )
    ap.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Per-job dispatch delay in seconds. Use 0 for max throughput; raise if AndroZoo "
        "is being polite to your IP and 429s start showing up in the manifest.",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Per-download timeout seconds. Large APKs at ~440 KB/s can take 10+ minutes.",
    )
    ap.add_argument(
        "--force", action="store_true", help="Re-download even if file exists"
    )
    args = ap.parse_args()

    key = api_key(args)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.manifest_out or (args.out_dir / "download_manifest.jsonl")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_manifest = manifest_path.with_suffix(
        manifest_path.suffix + f".tmp.{os.getpid()}"
    )

    rows = list(iter_jsonl(args.selection_jsonl))
    if args.limit is not None:
        rows = rows[: args.limit]
    total = len(rows)

    counters = {"downloaded_or_exists": 0, "sha256_ok": 0, "errored": 0}
    started = time.time()
    manifest_lock = threading.Lock()

    def _work(row: dict[str, Any]) -> dict[str, Any]:
        return download_one(row, key, args.out_dir, args.timeout, args.force)

    with (
        tmp_manifest.open("w") as manifest_fh,
        cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool,
    ):
        futures = {}
        for row in rows:
            futures[pool.submit(_work, row)] = row
            if args.sleep:
                time.sleep(args.sleep)
        completed = 0
        for fut in cf.as_completed(futures):
            row = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = dict(row)
                res["download_status"] = "error"
                res["error"] = str(exc)
            status = res.get("download_status")
            if status in {"downloaded", "exists"}:
                counters["downloaded_or_exists"] += 1
            else:
                counters["errored"] += 1
            if res.get("sha256_ok"):
                counters["sha256_ok"] += 1
            with manifest_lock:
                manifest_fh.write(json.dumps(res, sort_keys=True))
                manifest_fh.write("\n")
                manifest_fh.flush()
            completed += 1
            elapsed = time.time() - started
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total - completed) / rate if rate > 0 else float("inf")
            print(
                json.dumps(
                    {
                        "completed": completed,
                        "total": total,
                        "rate_per_sec": round(rate, 3),
                        "eta_sec": round(eta, 1) if eta != float("inf") else None,
                        "sha256": row["sha256"],
                        "status": status,
                        "ok": res.get("sha256_ok"),
                        "path": res.get("path"),
                        "error": res.get("error"),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    tmp_manifest.replace(manifest_path)
    summary = {
        "requested": total,
        **counters,
        "duration_sec": round(time.time() - started, 1),
        "manifest": str(manifest_path),
        "jobs": args.jobs,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if counters["sha256_ok"] == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
