#!/usr/bin/env python3
"""Rank APK/source targets by backend richness summaries.

Accepts one or more `backend_richness.json` files from extract_api_map.py and
emits a sorted JSONL/Markdown inbox.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_summary(path: Path) -> dict[str, Any] | None:
    try:
        obj = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    obj["summary_path"] = str(path)
    # Best-effort package/target inference from parent dir.
    obj.setdefault("target", path.parent.name)
    return obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "summaries", nargs="+", type=Path, help="backend_richness.json files"
    )
    ap.add_argument("--out-jsonl", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, default=None)
    args = ap.parse_args()

    rows = [s for p in args.summaries if (s := load_summary(p))]
    rows.sort(key=lambda r: (-int(r.get("total_score") or 0), r.get("target") or ""))

    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.out_jsonl.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# Backend-rich APK ranking\n"]
        lines.append(
            f"Ranked {len(rows)} targets by `extract_api_map.py` summary score.\n"
        )
        for i, r in enumerate(rows, 1):
            lines.append(
                f"{i}. **{r.get('target')}** — score={r.get('total_score')} "
                f"richness={r.get('backend_richness')} rows={r.get('row_count')} "
                f"summary=`{r.get('summary_path')}`"
            )
            counts = r.get("unique_value_counts") or {}
            if counts:
                compact = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
                lines.append(f"   - unique: {compact}")
            flags = r.get("synergy_flags") or {}
            hot = [k for k, v in sorted(flags.items()) if v]
            if hot:
                lines.append(f"   - synergy: {', '.join(hot)}")
        args.out_md.write_text("\n".join(lines) + "\n")

    print(f"wrote {len(rows)} rows to {args.out_jsonl}")
    if args.out_md:
        print(f"wrote markdown to {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
