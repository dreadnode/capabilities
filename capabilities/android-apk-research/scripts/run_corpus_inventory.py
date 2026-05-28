#!/usr/bin/env python3
"""Run a parallel, resumable first-pass inventory over an APK corpus.

This runner is intentionally an orchestrator. It reuses extract_attack_surface.py
for the cheap per-APK inventory, writes per-APK artifacts keyed by SHA256, and
emits aggregate JSONL/status files for ranking. It does not decompile APKs.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SOURCE_EXT = ".apk"

# Direct import of the sibling script. `extract_attack_surface.py` lives in the
# same scripts/ directory and provides `summarize_packers` + `rank` (pure-Python,
# no APK input) for the re-rank pass after APKiD signal lands. Importing as a
# module is materially cleaner than the dynamic spec_from_file_location dance
# the earlier version used; sys.path gymnastics live here so the rest of the
# module reads as normal Python.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import extract_attack_surface as _eas  # type: ignore[import-not-found]
except ImportError as exc:
    _eas = None  # type: ignore[assignment]
    print(f"warning: extract_attack_surface import failed: {exc}", file=sys.stderr)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def iter_apks(paths: Iterable[Path], limit: int | None = None) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = p.expanduser().resolve()
        if p.is_dir():
            out.extend(sorted(x for x in p.rglob(f"*{SOURCE_EXT}") if x.is_file()))
        elif p.is_file() and p.suffix.lower() == SOURCE_EXT:
            out.append(p)
    deduped = sorted(set(out))
    return deduped[:limit] if limit else deduped


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def atomic_write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(data)
    tmp.replace(path)


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return None


def run_androguard(apk: Path, out_path: Path, timeout: int) -> dict[str, Any] | None:
    if not shutil.which("uv"):
        return {
            "tool": "androguard",
            "status": "skipped_no_uv",
            "reason": "uv is required to run scripts/androguard_inventory.py (PEP 723 inline deps)",
        }
    script = Path(__file__).resolve().with_name("androguard_inventory.py")
    if not script.exists():
        return {
            "tool": "androguard",
            "status": "skipped_script_missing",
            "reason": f"androguard_inventory.py not found at {script}",
        }
    cmd = ["uv", "run", "--script", str(script), str(apk), "--out", str(out_path)]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"tool": "androguard", "status": "timeout", "timeout_sec": timeout}
    except Exception as exc:
        return {"tool": "androguard", "status": "error", "error": str(exc)}
    if proc.returncode != 0 or not out_path.exists():
        return {
            "tool": "androguard",
            "status": "error",
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "")[-4000:],
        }
    try:
        return json.loads(out_path.read_text(errors="ignore"))
    except Exception as exc:
        return {
            "tool": "androguard",
            "status": "error",
            "error": f"could not parse androguard.json: {exc}",
        }


def run_apkid(apk: Path, apkid_out: Path, timeout: int) -> dict[str, Any] | None:
    if not shutil.which("apkid"):
        return None
    cmd = ["apkid", "-j", str(apk)]
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "tool": "apkid",
            "status": "timeout",
            "timeout_sec": timeout,
            "output": str(exc),
        }
    except Exception as exc:
        return {"tool": "apkid", "status": "error", "error": str(exc)}
    raw = proc.stdout or ""
    parsed: Any
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {"raw_output": raw[-12000:]}
    result = {
        "tool": "apkid",
        "returncode": proc.returncode,
        "status": "ok" if proc.returncode == 0 else "error",
        "result": parsed,
    }
    atomic_write_json(apkid_out, result)
    return result


def analyze_one(args: tuple[str, str, str, bool, int, bool]) -> dict[str, Any]:
    apk_s, out_root_s, script_s, resume, timeout, include_apkid = args
    apk = Path(apk_s)
    out_root = Path(out_root_s)
    script = Path(script_s)
    started = time.time()
    started_at = utc_now()
    sha = ""
    status: dict[str, Any] = {
        "apk": str(apk),
        "stage": "inventory",
        "status": "started",
        "started_at": started_at,
        "tool": "extract_attack_surface.py",
    }
    try:
        sha = sha256_file(apk)
        artifact_dir = out_root / "apks" / sha
        inventory_path = artifact_dir / "inventory.json"
        status_path = artifact_dir / "status.json"
        apkid_path = artifact_dir / "apkid.json"
        status.update(
            {
                "sha256": sha,
                "artifact_dir": str(artifact_dir),
                "size": apk.stat().st_size,
            }
        )

        if resume and inventory_path.exists() and status_path.exists():
            previous = load_json(status_path) or {}
            if previous.get("status") == "ok":
                inventory = load_json(inventory_path) or {}
                return {
                    **status,
                    "status": "skipped",
                    "reason": "resume_existing_ok",
                    "finished_at": utc_now(),
                    "duration_sec": round(time.time() - started, 3),
                    "inventory": inventory,
                }

        artifact_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(status_path, status)
        tmp_jsonl = artifact_dir / "inventory.jsonl.tmp"
        cmd = ["python3", str(script), str(apk), "--out", str(tmp_jsonl)]
        try:
            proc = subprocess.run(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
            output = proc.stdout or ""
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="ignore")
            status.update(
                {
                    "status": "timeout",
                    "returncode": 124,
                    "output": output[-12000:],
                    "finished_at": utc_now(),
                    "duration_sec": round(time.time() - started, 3),
                }
            )
            atomic_write_json(status_path, status)
            return status

        if proc.returncode != 0:
            status.update(
                {
                    "status": "error",
                    "returncode": proc.returncode,
                    "output": output[-12000:],
                    "finished_at": utc_now(),
                    "duration_sec": round(time.time() - started, 3),
                }
            )
            atomic_write_json(status_path, status)
            return status

        lines = (
            [
                line
                for line in tmp_jsonl.read_text(errors="ignore").splitlines()
                if line.strip()
            ]
            if tmp_jsonl.exists()
            else []
        )
        if not lines:
            status.update(
                {
                    "status": "error",
                    "returncode": proc.returncode,
                    "error": "inventory output was empty",
                    "output": output[-12000:],
                    "finished_at": utc_now(),
                    "duration_sec": round(time.time() - started, 3),
                }
            )
            atomic_write_json(status_path, status)
            return status
        inventory = json.loads(lines[0])
        inventory["artifact_dir"] = str(artifact_dir)
        atomic_write_json(inventory_path, inventory)
        with contextlib.suppress(OSError):
            tmp_jsonl.unlink()

        apkid_result = None
        if include_apkid:
            apkid_result = run_apkid(apk, apkid_path, timeout=min(timeout, 120))
            if apkid_result:
                inventory["apkid_status"] = apkid_result.get("status")
                inventory["apkid_path"] = str(apkid_path)
                atomic_write_json(inventory_path, inventory)

        androguard_path = artifact_dir / "androguard.json"
        androguard_result = run_androguard(
            apk, androguard_path, timeout=min(timeout, 180)
        )
        if androguard_result:
            inventory["androguard_status"] = androguard_result.get("status") or (
                "error" if androguard_result.get("error") else "ok"
            )
            inventory["androguard_path"] = str(androguard_path)
            inventory.setdefault("package", androguard_result.get("package"))
            inventory.setdefault("version_name", androguard_result.get("version_name"))
            inventory.setdefault("permissions", androguard_result.get("permissions"))
            ag_schemes = androguard_result.get("schemes") or []
            ag_hosts = androguard_result.get("hosts") or []
            ag_browsable = androguard_result.get("browsable_components") or []
            ag_components = androguard_result.get("components") or []
            if ag_schemes:
                inventory["schemes"] = ag_schemes
            if ag_hosts:
                inventory["hosts"] = ag_hosts
            if ag_browsable:
                inventory["browsable_components"] = ag_browsable
            if ag_components:
                inventory["components"] = ag_components
            atomic_write_json(inventory_path, inventory)

        # Re-rank with APKiD packer/protector signal applied.
        # extract_attack_surface.summarize_packers + rank consume `apkid_summary`
        # and apply heavy/medium/ambiguous penalties. Reading the apkid.json on
        # disk is the canonical source (handles resume runs where apkid_result
        # is None because the per-APK invocation was skipped earlier).
        if _eas is not None:
            apkid_disk: dict[str, Any] | None = None
            if apkid_path.exists():
                try:
                    apkid_disk = json.loads(apkid_path.read_text(errors="ignore"))
                except json.JSONDecodeError:
                    apkid_disk = None
            try:
                inventory["apkid_summary"] = _eas.summarize_packers(
                    apkid_disk or apkid_result
                )
                inventory = _eas.rank(inventory)
            except (AttributeError, TypeError, ValueError) as exc:
                # Ranking is a refinement; never block on a malformed apkid
                # record. Surface the cause so a real summarize_packers /
                # rank bug doesn't hide silently.
                inventory.setdefault("rank_warnings", []).append(
                    f"apkid_rank_failed: {exc}"
                )
            atomic_write_json(inventory_path, inventory)

        status.update(
            {
                "status": "ok",
                "returncode": proc.returncode,
                "output": output[-4000:],
                "finished_at": utc_now(),
                "duration_sec": round(time.time() - started, 3),
                "inventory_path": str(inventory_path),
            }
        )
        atomic_write_json(status_path, status)
        return {**status, "inventory": inventory}
    except Exception as exc:
        artifact_dir = out_root / "apks" / sha if sha else out_root / "errors"
        status.update(
            {
                "status": "error",
                "error": str(exc),
                "finished_at": utc_now(),
                "duration_sec": round(time.time() - started, 3),
            }
        )
        atomic_write_json(artifact_dir / "status.json", status)
        return status


def compact_preview(record: dict[str, Any]) -> dict[str, Any]:
    inv = (
        record.get("inventory") if isinstance(record.get("inventory"), dict) else record
    )
    return {
        "status": record.get("status"),
        "apk": inv.get("apk") or record.get("apk"),
        "sha256": inv.get("sha256") or record.get("sha256"),
        "package": inv.get("package"),
        "size": inv.get("size") or record.get("size"),
        "semantic_priority": inv.get("semantic_priority"),
        "schemes_count": len(
            inv.get("schemes")
            or inv.get("manifest_string_hints", {}).get("scheme_hints", [])
            or []
        ),
        "hosts_count": len(
            inv.get("hosts")
            or inv.get("manifest_string_hints", {}).get("host_hints", [])
            or []
        ),
        "urls_count": len(inv.get("urls") or []),
        "artifact_dir": inv.get("artifact_dir") or record.get("artifact_dir"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run parallel resumable first-pass APK corpus inventory"
    )
    ap.add_argument(
        "paths", nargs="+", type=Path, help="APK files or directories containing APKs"
    )
    ap.add_argument("--out-dir", type=Path, required=True, help="Output run directory")
    ap.add_argument(
        "--jobs",
        type=int,
        default=max(1, min(4, (os.cpu_count() or 2) // 2)),
        help="Parallel worker count",
    )
    ap.add_argument(
        "--resume", action="store_true", help="Skip APKs with existing ok status"
    )
    ap.add_argument(
        "--timeout", type=int, default=180, help="Per-APK inventory timeout in seconds"
    )
    ap.add_argument("--limit", type=int, help="Limit number of APKs for smoke testing")
    ap.add_argument(
        "--include-apkid", action="store_true", help="Run APKiD when installed"
    )
    ap.add_argument(
        "--preview",
        type=int,
        default=20,
        help="Number of compact preview records in summary",
    )
    args = ap.parse_args()

    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve().with_name("extract_attack_surface.py")
    apks = iter_apks(args.paths, limit=args.limit)
    run_started = time.time()
    summary: dict[str, Any] = {
        "started_at": utc_now(),
        "out_dir": str(out_dir),
        "apk_count": len(apks),
        "jobs": args.jobs,
        "resume": args.resume,
        "timeout_sec": args.timeout,
        "include_apkid": args.include_apkid,
        "tools": {
            "aapt": shutil.which("aapt"),
            "aapt2": shutil.which("aapt2"),
            "apkid": shutil.which("apkid"),
            "uv": shutil.which("uv"),
            "androguard_inventory_script": str(
                Path(__file__).resolve().with_name("androguard_inventory.py")
            ),
        },
    }
    atomic_write_json(out_dir / "run_status.json", {**summary, "status": "running"})

    task_args = [
        (
            str(apk),
            str(out_dir),
            str(script),
            args.resume,
            args.timeout,
            args.include_apkid,
        )
        for apk in apks
    ]

    # Stream JSONL output to disk as workers finish so resident memory stays at
    # O(jobs * one_inventory) instead of O(corpus_size). Keep only a bounded heap
    # of compact previews; full records live on disk.
    surface_path = out_dir / "attack_surface.jsonl"
    status_path = out_dir / "status.jsonl"
    surface_tmp = surface_path.with_suffix(surface_path.suffix + f".tmp.{os.getpid()}")
    status_tmp = status_path.with_suffix(status_path.suffix + f".tmp.{os.getpid()}")
    surface_path.parent.mkdir(parents=True, exist_ok=True)

    import heapq

    counts: dict[str, int] = {}
    top_heap: list[tuple[int, int, int, dict[str, Any]]] = []
    preview_n = max(1, args.preview)
    idx = 0

    def _drain(fut_result: dict[str, Any], surface_fh, status_fh) -> None:
        nonlocal idx
        idx += 1
        st = fut_result.get("status")
        counts[str(st)] = counts.get(str(st), 0) + 1
        inventory = (
            fut_result.get("inventory")
            if isinstance(fut_result.get("inventory"), dict)
            else None
        )
        if inventory:
            surface_fh.write(json.dumps(inventory, sort_keys=True))
            surface_fh.write("\n")
            score = int(((inventory.get("semantic_priority") or {}).get("score")) or 0)
            urls_n = len(inventory.get("urls") or [])
            preview = compact_preview({"status": "ok", "inventory": inventory})
            heapq.heappush(top_heap, (score, urls_n, -idx, preview))
            if len(top_heap) > preview_n:
                heapq.heappop(top_heap)
        status_only = {k: v for k, v in fut_result.items() if k != "inventory"}
        status_fh.write(json.dumps(status_only, sort_keys=True))
        status_fh.write("\n")
        apk = fut_result.get("apk") or (inventory or {}).get("apk")
        print(f"{st}\t{apk}", file=sys.stderr, flush=True)

    with (
        surface_tmp.open("w") as surface_fh,
        status_tmp.open("w") as status_fh,
        cf.ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool,
    ):
        in_flight: dict[Any, Any] = {}
        max_inflight = max(args.jobs * 2, args.jobs + 2)
        it = iter(task_args)
        for t in it:
            in_flight[pool.submit(analyze_one, t)] = t
            if len(in_flight) >= max_inflight:
                break
        while in_flight:
            done_set, _ = cf.wait(in_flight.keys(), return_when=cf.FIRST_COMPLETED)
            for fut in done_set:
                in_flight.pop(fut, None)
                _drain(fut.result(), surface_fh, status_fh)
            for t in it:
                in_flight[pool.submit(analyze_one, t)] = t
                if len(in_flight) >= max_inflight:
                    break

    surface_tmp.replace(surface_path)
    status_tmp.replace(status_path)

    top_sorted = sorted(top_heap, key=lambda x: (-x[0], -x[1]))
    final_summary = {
        **summary,
        "status": "done",
        "finished_at": utc_now(),
        "duration_sec": round(time.time() - run_started, 3),
        "counts": counts,
        "attack_surface_jsonl": str(surface_path),
        "status_jsonl": str(status_path),
        "preview": [item[3] for item in top_sorted],
    }
    atomic_write_json(out_dir / "run_status.json", final_summary)
    print(json.dumps(final_summary, indent=2, sort_keys=True))
    return 0 if counts.get("error", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
