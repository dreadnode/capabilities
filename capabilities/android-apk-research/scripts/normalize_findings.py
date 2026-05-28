#!/usr/bin/env python3
"""Normalize semantic Android finding hypotheses into JSONL/CSV/Markdown."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

RISK_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
CONF_ORDER = {
    "confirmed_dynamic": 5,
    "strong_static_chain": 4,
    "high": 3,
    "needs_backend_validation": 3,
    "needs_route_map_validation": 3,
    "medium": 2,
    "hardening_only": 1,
    "low": 1,
    "generic_library_noise": 0,
    "unknown": 0,
}
REQUIRED = [
    "title",
    "apk",
    "package",
    "entrypoint",
    "source",
    "trust_boundary",
    "sink",
    "impact",
    "evidence",
    "validation_plan",
    "confidence",
]
CONFIDENCE_TIERS = {
    "confirmed_dynamic",
    "strong_static_chain",
    "needs_backend_validation",
    "needs_route_map_validation",
    "hardening_only",
    "generic_library_noise",
}

# Default CWE / MASWE / MASVS mappings per `class` value, so an LLM that
# emits only `class` still produces well-tagged reports. The taxonomy lives
# in `skills/android-semantic-vuln-hunting/references/output-schema.md`;
# update both when a new class is introduced.
#
# MASWE ID grounding (verified against https://mas.owasp.org/MASWE/, beta):
#   MASWE-0058 Insecure Deep Links            (MASVS-PLATFORM)
#   MASWE-0064 Insecure Content Providers      (MASVS-PLATFORM)
#   MASWE-0066 Insecure Intents                (MASVS-PLATFORM)
#   MASWE-0068 JavaScript Bridges in WebViews  (MASVS-PLATFORM)
# Where no current MASWE cleanly maps (Dirty Stream, client-side trust,
# backend API abuse, request-signing replay, leaked host gates), leave
# `maswe` empty rather than asserting an unrelated ID — the CWE and MASVS
# columns carry the grounding instead. OWASP API Security Top 10 is the
# right backend-side framework for `apk_discovered_backend_*` once those
# get a separate `api_top10` column.
CLASS_TAXONOMY: dict[str, dict[str, list[str]]] = {
    "deep_link_to_authenticated_webview": {
        "cwe": ["CWE-939", "CWE-749"],
        "maswe": ["MASWE-0058"],
        "masvs": ["MASVS-PLATFORM", "MASVS-NETWORK"],
    },
    "deep_link_to_js_bridge": {
        "cwe": ["CWE-749", "CWE-829"],
        "maswe": ["MASWE-0058", "MASWE-0068"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "custom_scheme_arbitrary_webview": {
        "cwe": ["CWE-939", "CWE-079"],
        "maswe": ["MASWE-0058"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "intent_redirection_private_component": {
        "cwe": ["CWE-926", "CWE-940"],
        "maswe": ["MASWE-0066"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "intent_redirection_uri_grant_leak": {
        "cwe": ["CWE-926", "CWE-200"],
        "maswe": ["MASWE-0066"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "dirty_stream_file_overwrite": {
        "cwe": ["CWE-22", "CWE-73"],
        "maswe": [],
        "masvs": ["MASVS-PLATFORM", "MASVS-STORAGE"],
    },
    "share_target_path_traversal": {
        "cwe": ["CWE-22"],
        "maswe": [],
        "masvs": ["MASVS-PLATFORM", "MASVS-STORAGE"],
    },
    "exported_provider_sqli": {
        "cwe": ["CWE-89", "CWE-926"],
        "maswe": ["MASWE-0064"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "exported_provider_private_file_read": {
        "cwe": ["CWE-200", "CWE-926"],
        "maswe": ["MASWE-0064"],
        "masvs": ["MASVS-PLATFORM", "MASVS-STORAGE"],
    },
    "provider_uri_grant_confusion": {
        "cwe": ["CWE-441", "CWE-926"],
        "maswe": ["MASWE-0064", "MASWE-0066"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "deep_link_auto_account_state_change": {
        "cwe": ["CWE-352", "CWE-862"],
        "maswe": ["MASWE-0058"],
        "masvs": ["MASVS-AUTH", "MASVS-PLATFORM"],
    },
    "client_state_auth_bypass": {
        "cwe": ["CWE-602", "CWE-287"],
        "maswe": [],
        "masvs": ["MASVS-AUTH"],
    },
    "apk_discovered_backend_bola": {
        "cwe": ["CWE-639"],
        "maswe": [],
        "masvs": ["MASVS-AUTH", "MASVS-NETWORK"],
    },
    "apk_discovered_backend_workflow_bypass": {
        "cwe": ["CWE-841", "CWE-863"],
        "maswe": [],
        "masvs": ["MASVS-AUTH", "MASVS-NETWORK"],
    },
    "apk_discovered_backend_mass_assignment": {
        "cwe": ["CWE-915"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK"],
    },
    "apk_discovered_backend_ssrf_or_open_redirect": {
        "cwe": ["CWE-918", "CWE-601"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK"],
    },
    "apk_discovered_graphql_operation_abuse": {
        "cwe": ["CWE-639", "CWE-863"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK"],
    },
    "apk_discovered_grpc_operation_abuse": {
        "cwe": ["CWE-639", "CWE-863"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK"],
    },
    "webview_bridge_to_mobile_api_action": {
        "cwe": ["CWE-749", "CWE-829"],
        "maswe": ["MASWE-0068"],
        "masvs": ["MASVS-PLATFORM"],
    },
    "mobile_request_signing_replay_or_confusion": {
        "cwe": ["CWE-345", "CWE-294"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK", "MASVS-CRYPTO"],
    },
    "leaked_host_feature_flag_gated": {
        "cwe": ["CWE-1188"],
        "maswe": [],
        "masvs": ["MASVS-NETWORK", "MASVS-CODE"],
    },
    "leaked_host_intent_extra_gated": {
        "cwe": ["CWE-1188", "CWE-926"],
        "maswe": ["MASWE-0066"],
        "masvs": ["MASVS-NETWORK", "MASVS-PLATFORM"],
    },
}


def load_records(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        text = path.read_text()
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                records.extend(x for x in obj if isinstance(x, dict))
            elif isinstance(obj, dict):
                records.append(obj)
            continue
        except json.JSONDecodeError:
            pass
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"skip invalid JSONL line in {path}: {exc}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                records.append(obj)
    return records


def normalize(rec: dict[str, Any]) -> dict[str, Any]:
    out = {k: rec.get(k) for k in REQUIRED}
    for k, v in rec.items():
        out.setdefault(k, v)
    out["confidence"] = str(out.get("confidence") or "unknown").lower()
    out["risk"] = str(
        out.get("risk") or infer_risk(str(out.get("impact") or ""))
    ).lower()
    out["confidence_tier"] = str(
        out.get("confidence_tier") or infer_confidence_tier(out)
    ).lower()
    out["validation_tier"] = str(
        out.get("validation_tier") or infer_validation_tier(out)
    ).lower()
    # Tag classes against MASVS / CWE / MASWE. If the record carries explicit
    # tags, those win; otherwise we fill defaults from CLASS_TAXONOMY so an
    # LLM that emits only `class` still produces well-tagged output.
    cls = str(out.get("class") or "").strip()
    defaults = CLASS_TAXONOMY.get(cls, {})
    out["masvs"] = listify(out.get("masvs")) or list(defaults.get("masvs", []))
    out["cwe"] = listify(out.get("cwe")) or list(defaults.get("cwe", []))
    out["maswe"] = listify(out.get("maswe")) or list(defaults.get("maswe", []))
    out["evidence"] = listify(out.get("evidence"))
    out["validation_plan"] = listify(out.get("validation_plan"))
    out["missing_evidence"] = listify(out.get("missing_evidence"))
    out["dedupe_key"] = out.get("dedupe_key") or "|".join(
        str(out.get(k) or "")
        for k in ["package", "entrypoint", "source", "sink", "impact"]
    )
    out["missing_fields"] = [k for k in REQUIRED if not out.get(k)]
    return out


def listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]


def infer_confidence_tier(rec: dict[str, Any]) -> str:
    text = " ".join(
        str(rec.get(k) or "")
        for k in ["impact", "trust_boundary", "scanner_gap", "source", "sink"]
    ).lower()
    if str(rec.get("confirmed") or "").lower() in {"true", "yes", "1"}:
        return "confirmed_dynamic"
    if (
        rec.get("needs_backend_validation") is True
        or "backend" in text
        or "server" in text
    ):
        return "needs_backend_validation"
    if "route" in text or "deeplink" in text or "deep link" in text:
        return "needs_route_map_validation"
    if "generic" in text or "library" in text:
        return "generic_library_noise"
    if rec.get("evidence") and rec.get("source") and rec.get("sink"):
        return "strong_static_chain"
    return "hardening_only"


def infer_validation_tier(rec: dict[str, Any]) -> str:
    text = " ".join(
        listify(rec.get("validation_plan"))
        + [str(rec.get("impact") or ""), str(rec.get("trust_boundary") or "")]
    ).lower()
    if "production" in text or "prod" in text:
        return "tier3_explicit_production_authorization"
    if "test account" in text or "qa" in text or "backend" in text or "server" in text:
        return "tier2_test_account_or_qa_backend"
    if "adb" in text or "device" in text or "emulator" in text:
        return "tier1_local_device_no_live_backend"
    return "tier0_static_only"


def infer_risk(impact: str) -> str:
    impact_l = impact.lower()
    if any(
        x in impact_l
        for x in [
            "account takeover",
            "auth bypass",
            "token theft",
            "password reset",
            "privilege escalation",
        ]
    ):
        return "high"
    if any(
        x in impact_l
        for x in ["data exposure", "file disclosure", "private component", "pii"]
    ):
        return "medium"
    return "unknown"


def dedupe(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: dict[str, dict[str, Any]] = {}
    for rec in records:
        key = rec["dedupe_key"]
        old = chosen.get(key)
        if old is None or score(rec) > score(old):
            chosen[key] = rec
    return list(chosen.values())


def score(rec: dict[str, Any]) -> tuple[int, int, int]:
    return (
        RISK_ORDER.get(rec.get("risk", "unknown"), 0),
        CONF_ORDER.get(rec.get("confidence", "unknown"), 0),
        -len(rec.get("missing_fields", [])),
    )


def write_jsonl(records: list[dict[str, Any]], out: Path | None) -> None:
    data = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    (out.write_text(data) if out else sys.stdout.write(data))


def write_csv(records: list[dict[str, Any]], out: Path | None) -> None:
    fields = [
        "risk",
        "confidence",
        "confidence_tier",
        "validation_tier",
        "title",
        "package",
        "apk",
        "class",
        "masvs",
        "cwe",
        "maswe",
        "entrypoint",
        "source",
        "sink",
        "impact",
        "scanner_gap",
        "missing_evidence",
        "missing_fields",
    ]
    fh = out.open("w", newline="") if out else sys.stdout
    try:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            row = dict(r)
            row["missing_fields"] = ",".join(r.get("missing_fields", []))
            row["missing_evidence"] = ",".join(r.get("missing_evidence", []))
            row["masvs"] = ",".join(r.get("masvs", []))
            row["cwe"] = ",".join(r.get("cwe", []))
            row["maswe"] = ",".join(r.get("maswe", []))
            writer.writerow(row)
    finally:
        if out:
            fh.close()


def write_markdown(records: list[dict[str, Any]], out: Path | None) -> None:
    lines = [
        "# Android semantic vulnerability hypotheses",
        "",
        f"Total deduplicated findings: {len(records)}",
        "",
    ]
    for i, r in enumerate(records, start=1):
        lines.append(f"## {i}. {r.get('title') or 'Untitled finding'}")
        lines.append("")
        lines.append(
            f"- Risk / confidence: **{r.get('risk')} / {r.get('confidence')}**"
        )
        lines.append(f"- Confidence tier: `{r.get('confidence_tier')}`")
        lines.append(f"- Validation tier: `{r.get('validation_tier')}`")
        lines.append(f"- APK/package: `{r.get('apk')}` / `{r.get('package')}`")
        lines.append(f"- MASVS: {', '.join(r.get('masvs') or []) or 'unmapped'}")
        lines.append(f"- CWE: {', '.join(r.get('cwe') or []) or 'unmapped'}")
        lines.append(f"- MASWE: {', '.join(r.get('maswe') or []) or 'unmapped'}")
        lines.append(f"- Entrypoint: `{r.get('entrypoint')}`")
        lines.append(f"- Source: `{r.get('source')}`")
        lines.append(f"- Trust boundary: {r.get('trust_boundary')}")
        lines.append(f"- Sink: `{r.get('sink')}`")
        lines.append(f"- Impact: {r.get('impact')}")
        if r.get("scanner_gap"):
            lines.append(f"- Scanner gap: {r.get('scanner_gap')}")
        if r.get("missing_fields"):
            lines.append(f"- Missing fields: {', '.join(r.get('missing_fields'))}")
        lines.append("")
        if r.get("missing_evidence"):
            lines.append("Missing evidence:")
            for e in r.get("missing_evidence", []):
                lines.append(f"- {e}")
            lines.append("")
        lines.append("Evidence:")
        for e in r.get("evidence", []):
            lines.append(f"- {e}")
        lines.append("")
        lines.append("Validation plan:")
        for step in r.get("validation_plan", []):
            lines.append(f"- {step}")
        lines.append("")
    data = "\n".join(lines)
    (out.write_text(data) if out else sys.stdout.write(data))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Normalize Android semantic vulnerability hypotheses"
    )
    ap.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="JSON or JSONL files containing finding hypotheses",
    )
    ap.add_argument(
        "--format", choices=["jsonl", "csv", "markdown"], default="markdown"
    )
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    records = [normalize(r) for r in load_records(args.inputs)]
    records = dedupe(records)
    records.sort(key=score, reverse=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "jsonl":
        write_jsonl(records, args.out)
    elif args.format == "csv":
        write_csv(records, args.out)
    else:
        write_markdown(records, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
