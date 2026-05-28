#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["androguard==4.1.3"]
# ///
"""Extract authoritative APK metadata via Androguard.

Single-APK extractor invoked by the corpus runner. Uses Androguard's public APK
API instead of reimplementing manifest parsing. PEP 723 inline metadata lets
`uv run` resolve dependencies on the fly without polluting the active venv.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _androguard_version() -> str | None:
    try:
        import androguard  # type: ignore[import-not-found]

        return getattr(androguard, "__version__", None)
    except Exception:
        return None


def _silence_androguard_logging() -> None:
    try:
        from loguru import logger as _logger  # type: ignore[import-not-found]

        _logger.remove()
    except Exception:
        pass
    import logging

    for noisy in (
        "androguard",
        "androguard.core",
        "androguard.core.axml",
        "androguard.core.apk",
    ):
        logging.getLogger(noisy).setLevel(logging.ERROR)


def extract(apk_path: Path) -> dict[str, Any]:
    _silence_androguard_logging()
    try:
        from androguard.core.apk import APK  # type: ignore[import-not-found]
    except ImportError:
        from androguard.core.bytecodes.apk import APK  # type: ignore[import-not-found]

    apk = APK(str(apk_path))
    package = apk.get_package() or None
    permissions = sorted(apk.get_permissions() or [])

    component_kinds = [
        ("activity", apk.get_activities),
        ("service", apk.get_services),
        ("receiver", apk.get_receivers),
        ("provider", apk.get_providers),
    ]

    components: list[dict[str, Any]] = []
    schemes: set[str] = set()
    hosts: set[str] = set()
    browsable_components: list[str] = []

    for kind, getter in component_kinds:
        try:
            names = getter() or []
        except Exception:
            names = []
        for name in names:
            full_name = (
                name
                if "." in name
                else f"{package}.{name.lstrip('.')}"
                if package
                else name
            )
            entry: dict[str, Any] = {
                "type": kind,
                "name": full_name,
                "raw_name": name,
                "exported": None,
                "permission": None,
                "intent_filters": [],
                "browsable": False,
                "view": False,
            }
            try:
                exported_attr = apk.get_element(kind, "exported", name)
                if exported_attr is not None:
                    entry["exported"] = str(exported_attr).lower() == "true"
            except Exception:
                pass
            try:
                entry["permission"] = apk.get_element(kind, "permission", name) or None
            except Exception:
                pass
            try:
                raw_filters = apk.get_intent_filters(kind, name) or {}
            except Exception:
                raw_filters = {}
            if isinstance(raw_filters, dict) and raw_filters:
                filt_record: dict[str, Any] = {
                    "actions": sorted(raw_filters.get("action", []) or []),
                    "categories": sorted(raw_filters.get("category", []) or []),
                    "data": list(raw_filters.get("data", []) or []),
                }
                filt_record["browsable"] = (
                    "android.intent.category.BROWSABLE" in filt_record["categories"]
                )
                filt_record["view"] = (
                    "android.intent.action.VIEW" in filt_record["actions"]
                )
                if filt_record["browsable"]:
                    entry["browsable"] = True
                if filt_record["view"]:
                    entry["view"] = True
                for data in filt_record["data"]:
                    if not isinstance(data, dict):
                        continue
                    if data.get("scheme"):
                        schemes.add(data["scheme"])
                    if data.get("host"):
                        hosts.add(data["host"])
                entry["intent_filters"] = [filt_record]
            if entry["browsable"] and entry["name"]:
                browsable_components.append(entry["name"])
            components.append(entry)

    return {
        "tool": "androguard",
        "tool_version": _androguard_version(),
        "package": package,
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "app_label": apk.get_app_name() or None,
        "permissions": permissions,
        "components": components,
        "browsable_components": sorted(set(browsable_components)),
        "schemes": sorted(schemes),
        "hosts": sorted(hosts),
        "is_valid_apk": bool(apk.is_valid_APK()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract APK manifest facts via Androguard"
    )
    ap.add_argument("apk", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    try:
        record = extract(args.apk.expanduser().resolve())
    except Exception as exc:
        record = {"tool": "androguard", "status": "error", "error": str(exc)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
