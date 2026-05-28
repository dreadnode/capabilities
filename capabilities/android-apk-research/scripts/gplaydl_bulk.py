#!/usr/bin/env python3
"""Bulk APK downloader on top of `gplaydl` (PyPI).

`gplaydl` is a one-package-at-a-time CLI tool with anonymous-token auth via
Aurora Store's dispenser. Empirically it sustains ~20–25 MB/s against Google's
CDN, vs. AndroZoo's ~440 KB/s per connection. For a 5 GB corpus that's the
difference between an afternoon and 4+ hours.

What this wrapper adds:

- Bounded parallelism (default 8) — gplaydl's internal parallelism is per-app
  splits/extras, not across packages. We want to download many packages at once.
- JSONL selection input compatible with our existing corpus_design flow
  (`{"package": "com.foo", ...}` lines).
- Resume-by-prefix: detects packages already present in the output directory and
  skips re-download. Useful when corpus selection grows incrementally.
- Per-package download manifest (JSONL) compatible with `run_corpus_inventory`
  via plain filesystem path; gplaydl names files `<package>-<vc>.apk`.
- Honest failure tracking: gplaydl exits non-zero on delisted packages and
  region-locked ones; we record the failure and keep going.

Limitations to know:

- Anonymous token = "delisted from Google Play" means we cannot fetch it (we
  fall back to AndroZoo in that case — see ``androzoo_download.py``).
- gplaydl downloads the *current* version. For older versions, pass --version.
- gplaydl writes split APKs and OBB extras by default; we pass --no-splits
  --no-extras for first-pass research corpora unless ``--include-splits`` or
  ``--include-extras`` is set.

Usage:

    gplaydl_bulk.py corpus/selection.jsonl --out-dir corpus/apks \\
        --manifest-out corpus/download_manifest.jsonl --jobs 8
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("package"):
                yield obj


def ensure_token(arch: str) -> None:
    """gplaydl caches tokens at ~/.config/gplaydl/auth-<arch>.json.

    Run `gplaydl auth` once up front so concurrent workers don't race on it.
    """
    token_path = Path.home() / ".config" / "gplaydl" / f"auth-{arch}.json"
    if token_path.exists():
        return
    proc = subprocess.run(
        ["gplaydl", "auth", "--arch", arch], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"gplaydl auth failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )


def find_existing_apk(out_dir: Path, package: str) -> Path | None:
    # gplaydl names files <package>-<vc>.apk; pick the largest if multiple exist.
    candidates = sorted(
        out_dir.glob(f"{package}-*.apk"),
        key=lambda p: p.stat().st_size if p.exists() else 0,
        reverse=True,
    )
    return candidates[0] if candidates else None


def download_one(
    row: dict[str, Any],
    out_dir: Path,
    arch: str,
    timeout: int,
    include_splits: bool,
    include_extras: bool,
    version: int | None,
    force: bool,
) -> dict[str, Any]:
    package = str(row["package"])
    result: dict[str, Any] = dict(row)
    result["arch"] = arch
    result["source"] = "gplaydl"

    if not force:
        existing = find_existing_apk(out_dir, package)
        if existing is not None:
            result["download_status"] = "exists"
            result["path"] = str(existing)
            result["size_bytes"] = existing.stat().st_size
            return result

    cmd = ["gplaydl", "download", package, "-o", str(out_dir), "-a", arch]
    if not include_splits:
        cmd.append("--no-splits")
    if not include_extras:
        cmd.append("--no-extras")
    if version is not None:
        cmd += ["-v", str(version)]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        result["download_status"] = "timeout"
        result["error"] = f"gplaydl timed out after {timeout}s"
        result["duration_sec"] = round(time.time() - started, 2)
        return result
    result["duration_sec"] = round(time.time() - started, 2)
    if proc.returncode != 0:
        result["download_status"] = "error"
        result["returncode"] = proc.returncode
        # gplaydl prints "App not found" / "Region locked" / "Premium app" to stdout.
        result["error"] = (proc.stdout or proc.stderr).strip()[-2000:]
        return result
    apk = find_existing_apk(out_dir, package)
    if apk is None:
        result["download_status"] = "error"
        result["error"] = "gplaydl exit 0 but no APK on disk"
        return result
    result["download_status"] = "downloaded"
    result["path"] = str(apk)
    result["size_bytes"] = apk.stat().st_size
    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bulk-download APKs via gplaydl with bounded parallelism"
    )
    ap.add_argument(
        "selection_jsonl",
        type=Path,
        help='JSONL with one {"package":"com.foo"} object per line',
    )
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument(
        "--manifest-out",
        type=Path,
        help="Output manifest JSONL (default <out-dir>/download_manifest.jsonl)",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=8,
        help="Parallel downloads (default 8). gplaydl's own download streams "
        "are already chunked, so 8 against the CDN is a safe sweet spot.",
    )
    ap.add_argument("--arch", default="arm64", choices=["arm64", "armv7"])
    ap.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Per-package timeout in seconds (default 600)",
    )
    ap.add_argument(
        "--include-splits",
        action="store_true",
        help="Also download split APKs (config splits / language splits)",
    )
    ap.add_argument(
        "--include-extras",
        action="store_true",
        help="Also download OBB files and Play Asset Delivery packs",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if an APK already exists for the package",
    )
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    if not shutil.which("gplaydl"):
        raise SystemExit("gplaydl not on PATH; pip install gplaydl")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.manifest_out or (args.out_dir / "download_manifest.jsonl")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_manifest = manifest_path.with_suffix(
        manifest_path.suffix + f".tmp.{os.getpid()}"
    )

    ensure_token(args.arch)

    rows = list(iter_jsonl(args.selection_jsonl))
    if args.limit is not None:
        rows = rows[: args.limit]
    total = len(rows)

    counters = {"downloaded": 0, "exists": 0, "errored": 0, "timeout": 0}
    started = time.time()
    manifest_lock = threading.Lock()

    def _work(row: dict[str, Any]) -> dict[str, Any]:
        return download_one(
            row,
            args.out_dir,
            args.arch,
            args.timeout,
            args.include_splits,
            args.include_extras,
            row.get("version_code")
            if isinstance(row.get("version_code"), int)
            else None,
            args.force,
        )

    with (
        tmp_manifest.open("w") as manifest_fh,
        cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool,
    ):
        futures = {pool.submit(_work, row): row for row in rows}
        completed = 0
        for fut in cf.as_completed(futures):
            row = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = dict(row)
                res["download_status"] = "error"
                res["error"] = str(exc)
            status = res.get("download_status", "error")
            if status == "downloaded":
                counters["downloaded"] += 1
            elif status == "exists":
                counters["exists"] += 1
            elif status == "timeout":
                counters["timeout"] += 1
            else:
                counters["errored"] += 1
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
                        "package": row["package"],
                        "status": status,
                        "path": res.get("path"),
                        "size_mb": round((res.get("size_bytes") or 0) / 1e6, 2),
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
        "throughput_apks_per_min": round(total / (time.time() - started) * 60, 2)
        if (time.time() - started) > 0
        else 0,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if counters["errored"] + counters["timeout"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
