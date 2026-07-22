#!/usr/bin/env python3
"""Append one measured reconnaissance phase to a JSON coverage ledger."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _non_negative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", action="append", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument(
        "--status", choices=("completed", "partial", "failed"), required=True
    )
    parser.add_argument("--targets-scheduled", type=_non_negative)
    parser.add_argument("--targets-completed", type=_non_negative)
    parser.add_argument("--ports-scheduled", type=_non_negative)
    parser.add_argument("--responsive-hosts", type=_non_negative)
    parser.add_argument("--facts-produced", type=_non_negative)
    parser.add_argument("--artifact")
    parser.add_argument("--deferred", action="append", default=[])
    parser.add_argument("--note")
    return parser


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [])}


def main() -> None:
    args = _parser().parse_args()
    if (
        args.targets_scheduled is not None
        and args.targets_completed is not None
        and args.targets_completed > args.targets_scheduled
    ):
        raise SystemExit("targets-completed cannot exceed targets-scheduled")

    if args.output.exists():
        ledger = json.loads(args.output.read_text())
    else:
        ledger = {
            "schema_version": "web-security-coverage-v1",
            "scope": args.scope,
            "started_at": datetime.now(UTC).isoformat(),
            "phases": [],
        }

    if sorted(ledger.get("scope", [])) != sorted(args.scope):
        raise SystemExit("scope does not match the existing ledger")

    phase = _compact(
        {
            "name": args.phase,
            "tool": args.tool,
            "status": args.status,
            "recorded_at": datetime.now(UTC).isoformat(),
            "targets_scheduled": args.targets_scheduled,
            "targets_completed": args.targets_completed,
            "ports_scheduled": args.ports_scheduled,
            "address_port_checks": (
                args.targets_completed * args.ports_scheduled
                if args.targets_completed is not None
                and args.ports_scheduled is not None
                else None
            ),
            "responsive_hosts": args.responsive_hosts,
            "facts_produced": args.facts_produced,
            "artifact": args.artifact,
            "deferred": args.deferred,
            "note": args.note,
        }
    )
    ledger.setdefault("phases", []).append(phase)
    ledger["updated_at"] = phase["recorded_at"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
