#!/usr/bin/env python3
"""Extract a lightweight API/backend map from decompiled APK sources or bundle text.

This is intentionally regex-based and dependency-free. It does not prove
vulnerabilities; it produces a target map for APK -> backend/API hypotheses.

Outputs:
  - JSONL rows with category/kind/value/file/line/context
  - Optional summary JSON with backend-richness scores and top terms

Usage:
  python3 scripts/extract_api_map.py \
    --src findings/decompiled/com.example/sources \
    --out findings/com.example/api_map.jsonl \
    --summary findings/com.example/backend_richness.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Iterator, Any

TEXT_EXTS = {
    ".java",
    ".kt",
    ".kts",
    ".xml",
    ".json",
    ".properties",
    ".gradle",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".graphql",
    ".gql",
    ".proto",
    ".txt",
    ".smali",
    ".dart",
}
SKIP_DIRS = {
    ".git",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    ".gradle",
    "androidx",
    "kotlin",
    "kotlinx",
}
MAX_FILE_BYTES = 2_000_000

PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("endpoint", "url", re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")),
    (
        "endpoint",
        "api_path",
        re.compile(
            r"(?<![A-Za-z0-9_])/(?:api|v\d+|graphql|grpc|rpc|gateway|mobile|internal|rest|oauth|auth|users?|accounts?|orgs?|tenants?|devices?|orders?|payments?|rooms?|messages?)[A-Za-z0-9_./{}?=&:%+-]*"
        ),
    ),
    (
        "graphql",
        "graphql_keyword",
        re.compile(
            r"\b(?:ApolloClient|GraphQL|operationName|persistedQuery|sha256Hash|__typename|mutation\s+\w+|query\s+\w+)\b"
        ),
    ),
    (
        "grpc",
        "grpc_keyword",
        re.compile(
            r"\b(?:io\.grpc|ManagedChannel|MethodDescriptor|GeneratedMessageLite|parseFrom|toByteArray|proto3|service\s+\w+|rpc\s+\w+)\b"
        ),
    ),
    (
        "transport",
        "realtime",
        re.compile(
            r"\b(?:WebSocket|Socket\.IO|SignalR|EventSource|SSE|MQTT|MqttClient|FirebaseFirestore|FirebaseDatabase|Firestore|RealtimeDatabase)\b"
        ),
    ),
    (
        "client",
        "http_client",
        re.compile(
            r"\b(?:Retrofit|OkHttpClient|Request\.Builder|HttpUrl|Volley|Ktor|ApolloClient|GraphQLClient|Dio\(|axios|fetch\()\b"
        ),
    ),
    (
        "auth",
        "auth_header",
        re.compile(
            r"\b(?:Authorization|Bearer|X-Api-Key|apiKey|x-device|X-Device|deviceId|installationId|sessionId|refreshToken|accessToken|idToken)\b"
        ),
    ),
    (
        "signing",
        "request_signing",
        re.compile(
            r"\b(?:Hmac|Mac\.getInstance|SHA256|SHA-256|Signature|signRequest|signature|X-Signature|nonce|timestamp|canonical|stringToSign|attestation|SafetyNet|PlayIntegrity|IntegrityManager|CertificatePinner)\b"
        ),
    ),
    (
        "object_id",
        "object_id",
        re.compile(
            r"\b(?:tenantId|orgId|organizationId|accountId|userId|ownerId|familyId|childId|vaultId|itemId|deviceId|orderId|paymentId|bookingId|tripId|ticketId|roomId|messageId|attachmentId|subscriptionId|inviteId|teamId|groupId|channelId)\b"
        ),
    ),
    (
        "workflow",
        "workflow_verb",
        re.compile(
            r"\b(?:accept|approve|complete|activate|claim|redeem|recover|reset|verify|bind|pair|link|migrate|transfer|cancel|refund|share|invite|provision|checkout|unlock|disarm|arm)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "mass_assignment",
        "privilege_field",
        re.compile(
            r"\b(?:role|isAdmin|admin|verified|entitlement|premium|subscription|scope|permissions|status|state|price|amount|discount|ownerId|tenantId|plan|tier|limit)\b"
        ),
    ),
    (
        "url_fetch",
        "url_parameter",
        re.compile(
            r"\b(?:callback|redirect_uri|redirectUri|returnUrl|webhook|avatarUrl|imageUrl|preview|unfurl|importUrl|sourceUrl|targetUrl|nextUrl|url)\b"
        ),
    ),
    (
        "feature_flag",
        "flag_system",
        re.compile(
            r"\b(?:LaunchDarkly|LDClient|FirebaseRemoteConfig|RemoteConfig|SplitClient|Optimizely|Statsig|Unleash|featureFlag|feature_flag|experiment|variant|treatment|isEnabled|checkGate|rollout|killSwitch)\b"
        ),
    ),
    (
        "bridge",
        "native_bridge",
        re.compile(
            r"\b(?:addJavascriptInterface|JavascriptInterface|postWebMessage|WebMessagePort|MethodChannel|EventChannel|BasicMessageChannel|ReactContextBaseJavaModule|ReactMethod|NativeModules|CordovaPlugin|CapacitorPlugin|PluginMethod)\b"
        ),
    ),
]

RISK_WEIGHTS = {
    "endpoint": 2,
    "graphql": 4,
    "grpc": 4,
    "transport": 3,
    "client": 2,
    "auth": 2,
    "signing": 5,
    "object_id": 3,
    "workflow": 3,
    "mass_assignment": 3,
    "url_fetch": 3,
    "feature_flag": 4,
    "bridge": 4,
}


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix and p.suffix not in TEXT_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None


def clean_value(value: str) -> str:
    return value.strip().strip("\"'`,);")[:500]


def extract(root: Path) -> Iterator[dict[str, Any]]:
    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = str(path.relative_to(root)) if root.is_dir() else str(path)
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            for category, kind, pattern in PATTERNS:
                for match in pattern.finditer(line):
                    value = clean_value(match.group(0))
                    if not value or value in {"url", "URL"}:
                        continue
                    yield {
                        "category": category,
                        "kind": kind,
                        "value": value,
                        "file": rel,
                        "line": lineno,
                        "context": line.strip()[:1000],
                    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_category = Counter(r["category"] for r in rows)
    unique_values_by_category: dict[str, set[str]] = defaultdict(set)
    top_terms_by_category: dict[str, Counter[str]] = defaultdict(Counter)
    files_by_category: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        cat = r["category"]
        val = r["value"]
        unique_values_by_category[cat].add(val)
        top_terms_by_category[cat][val] += 1
        files_by_category[cat].add(r["file"])

    scores = {
        cat: len(vals) * RISK_WEIGHTS.get(cat, 1)
        for cat, vals in unique_values_by_category.items()
    }
    total = sum(scores.values())
    if {"object_id", "workflow"}.issubset(unique_values_by_category):
        total += 20
    if {"bridge", "auth"}.issubset(unique_values_by_category):
        total += 15
    if {"signing", "endpoint"}.issubset(unique_values_by_category):
        total += 15
    if {"feature_flag", "workflow"}.issubset(unique_values_by_category):
        total += 10
    if {"url_fetch", "endpoint"}.issubset(unique_values_by_category):
        total += 10

    richness = "low"
    if total >= 180:
        richness = "very_high"
    elif total >= 100:
        richness = "high"
    elif total >= 45:
        richness = "medium"

    return {
        "backend_richness": richness,
        "total_score": total,
        "row_count": len(rows),
        "category_counts": dict(sorted(by_category.items())),
        "unique_value_counts": {
            cat: len(vals) for cat, vals in sorted(unique_values_by_category.items())
        },
        "category_file_counts": {
            cat: len(vals) for cat, vals in sorted(files_by_category.items())
        },
        "scores": dict(sorted(scores.items())),
        "top_terms": {
            cat: terms.most_common(25)
            for cat, terms in sorted(top_terms_by_category.items())
        },
        "synergy_flags": {
            "object_workflow_pair": {"object_id", "workflow"}.issubset(
                unique_values_by_category
            ),
            "bridge_auth_pair": {"bridge", "auth"}.issubset(unique_values_by_category),
            "signing_endpoint_pair": {"signing", "endpoint"}.issubset(
                unique_values_by_category
            ),
            "feature_workflow_pair": {"feature_flag", "workflow"}.issubset(
                unique_values_by_category
            ),
            "url_fetch_endpoint_pair": {"url_fetch", "endpoint"}.issubset(
                unique_values_by_category
            ),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--src",
        required=True,
        type=Path,
        help="source tree, JS analysis dir, Dart analysis dir, or text file",
    )
    ap.add_argument("--out", required=True, type=Path, help="output JSONL path")
    ap.add_argument(
        "--summary", type=Path, default=None, help="optional summary JSON path"
    )
    ap.add_argument(
        "--dedupe",
        action="store_true",
        help="dedupe exact category/kind/value/file/line rows",
    )
    args = ap.parse_args()

    rows = list(extract(args.src))
    if args.dedupe:
        seen: set[tuple[str, str, str, str, int]] = set()
        deduped = []
        for r in rows:
            key = (r["category"], r["kind"], r["value"], r["file"], r["line"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)
        rows = deduped

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    summary = summarize(rows)
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    print(f"wrote {len(rows)} rows to {args.out}")
    print(
        f"backend_richness={summary['backend_richness']} total_score={summary['total_score']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
