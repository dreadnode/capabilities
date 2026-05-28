#!/usr/bin/env python3
"""Extract a lightweight attack-surface inventory from Android APKs.

The script is intentionally dependency-free. It uses Python zip/string parsing plus
optional local Android tooling (`aapt`, `aapt2`, `apkanalyzer`) when available. It
produces JSONL records suitable for ranking APKs before deeper semantic slicing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
DOMAIN_RE = re.compile(
    rb"\b(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|co|app|dev|me|xyz|cloud|firebaseio|googleapis|amazonaws|azurewebsites)\b"
)
CUSTOM_SCHEME_RE = re.compile(
    r"scheme\(0x[0-9a-f]+\)=\"([^\"]+)\"|android:scheme\(.*?\)=\"([^\"]+)\""
)
HOST_RE = re.compile(
    r"host\(0x[0-9a-f]+\)=\"([^\"]+)\"|android:host\(.*?\)=\"([^\"]+)\""
)
PACKAGE_RE = re.compile(r"package: name='([^']+)'.*?versionName='([^']*)'", re.S)
SDK_RE = re.compile(r"sdkVersion:'([^']+)'|targetSdkVersion:'([^']+)'")
PERM_RE = re.compile(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'")

HIGH_VALUE_LIB_HINTS = {
    "oauth": ["oauth", "openid", "appauth"],
    "firebase": ["firebase", "google-services", "firebaseremoteconfig"],
    "payment": [
        "stripe",
        "braintree",
        "adyen",
        "paypal",
        "checkout",
        "paytm",
        "razorpay",
    ],
    "webview_bridge": ["javascriptinterface", "addjavascriptinterface"],
    "react_native": ["reactnative", "com.facebook.react"],
    "flutter": ["flutter", "io.flutter"],
}

# Binary AndroidManifest.xml is hard to decode correctly without Android build
# tools, but package names and component/link strings often survive in the string
# pool. These regexes provide a dependency-free fallback so target ranking is not
# blind when aapt/aapt2 is unavailable.
PACKAGE_BYTES_RE = re.compile(
    rb"\b[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){2,}\b"
)
DEEP_LINK_HOST_HINT_RE = re.compile(
    rb"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|app|dev|me|xyz|cloud|br|vn|th|id|in)\b"
)
SCHEME_HINT_RE = re.compile(rb"\b[a-z][a-z0-9+.-]{2,24}://")
ANDROID_COMPONENT_HINTS = [b"Activity", b"Service", b"Receiver", b"Provider"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str], timeout: int = 20) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return None
    return proc.stdout if proc.stdout else None


def iter_apks(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(x for x in p.rglob("*.apk") if x.is_file()))
        elif p.is_file() and p.suffix.lower() == ".apk":
            out.append(p)
    return sorted(set(out))


def printable_ascii_runs(data: bytes, min_len: int = 4) -> list[bytes]:
    runs = re.findall(rb"[ -~]{%d,}" % min_len, data)
    # Binary XML UTF-16LE string pools often appear as ASCII bytes separated by NULs.
    nul_stripped = data.replace(b"\x00", b"")
    if nul_stripped != data:
        runs.extend(re.findall(rb"[ -~]{%d,}" % min_len, nul_stripped))
    return runs


def manifest_string_hints(data: bytes) -> dict[str, Any]:
    runs = printable_ascii_runs(data)
    joined = b"\n".join(runs)
    packages = sorted(
        {x.decode("utf-8", "ignore") for x in PACKAGE_BYTES_RE.findall(joined)}
    )
    component_like = [
        p for p in packages if any(h.decode() in p for h in ANDROID_COMPONENT_HINTS)
    ]
    schemes = sorted(
        {
            m.group(0)[:-3].decode("utf-8", "ignore")
            for m in SCHEME_HINT_RE.finditer(joined)
        }
    )
    hosts = sorted(
        {x.decode("utf-8", "ignore") for x in DEEP_LINK_HOST_HINT_RE.findall(joined)}
    )
    lower = joined.lower()
    return {
        "package_like_strings": packages[:200],
        "component_like_strings": component_like[:200],
        "scheme_hints": schemes[:100],
        "host_hints": hosts[:200],
        "mentions_browsable": b"android.intent.category.browsable" in lower
        or b"browsable" in lower,
        "mentions_view_action": b"android.intent.action.view" in lower,
        "mentions_exported": b"exported" in lower,
    }


def zip_inventory(apk: Path, max_bytes_per_file: int = 2_000_000) -> dict[str, Any]:
    """Stream per-file content through regex/substring matchers.

    The previous implementation buffered the lowercased concatenation of every
    interesting file (up to 80 × 2 MB = 160 MB per APK) into a bytearray, then
    ran four passes over the full blob. That made resident memory scale with
    APK content size and multiplied by the worker count. We now process one
    file at a time, accumulating only small bounded result sets (capped URL,
    domain, and library-hint collections).
    """
    info: dict[str, Any] = {
        "zip_entries": 0,
        "dex_files": [],
        "native_libs": [],
        "interesting_files": [],
        "urls": [],
        "domains": [],
        "library_hints": {},
        "manifest_string_hints": {},
    }
    manifest_bytes = b""
    url_set: set[str] = set()
    domain_set: set[str] = set()
    lib_hits: dict[str, set[str]] = {label: set() for label in HIGH_VALUE_LIB_HINTS}
    url_cap, domain_cap, hit_cap = 200, 300, 8
    needles_lc = {
        label: [n.lower().encode("latin1") for n in needles]
        for label, needles in HIGH_VALUE_LIB_HINTS.items()
    }

    def absorb(buf: bytes) -> None:
        # Cheap: enrich bounded sets, stop scanning if both caps reached.
        if len(url_set) < url_cap:
            for m in URL_RE.findall(buf):
                if len(url_set) >= url_cap:
                    break
                url_set.add(m.decode("utf-8", "ignore"))
        if len(domain_set) < domain_cap:
            for m in DOMAIN_RE.findall(buf):
                if len(domain_set) >= domain_cap:
                    break
                domain_set.add(m.decode("utf-8", "ignore"))
        lc = buf.lower()
        for label, needles in needles_lc.items():
            if len(lib_hits[label]) >= hit_cap:
                continue
            for needle in needles:
                if needle in lc:
                    lib_hits[label].add(needle.decode("latin1"))

    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            info["zip_entries"] = len(names)
            info["dex_files"] = [
                n for n in names if re.fullmatch(r"classes\d*\.dex", Path(n).name)
            ]
            info["native_libs"] = [
                n for n in names if n.startswith("lib/") and n.endswith(".so")
            ][:500]
            interesting_suffixes = (
                ".xml",
                ".json",
                ".properties",
                ".txt",
                ".html",
                ".js",
                ".dex",
            )
            interesting_names = [
                n
                for n in names
                if n.endswith(interesting_suffixes)
                or "firebase" in n.lower()
                or "google" in n.lower()
            ]
            info["interesting_files"] = interesting_names[:500]
            if "AndroidManifest.xml" in names:
                try:
                    manifest_bytes = zf.read("AndroidManifest.xml")[:max_bytes_per_file]
                    absorb(manifest_bytes)
                except Exception:
                    manifest_bytes = b""
            for n in interesting_names[:80]:
                try:
                    with zf.open(n) as fh:
                        data = fh.read(max_bytes_per_file)
                    absorb(data)
                    del data
                except Exception:
                    continue
    except zipfile.BadZipFile:
        info["error"] = "bad_zip"
        return info

    info["urls"] = sorted(url_set)
    info["domains"] = sorted(domain_set)
    if manifest_bytes:
        info["manifest_string_hints"] = manifest_string_hints(manifest_bytes)
    info["library_hints"] = {
        label: sorted(hits) for label, hits in lib_hits.items() if hits
    }
    return info


def parse_aapt_badging(output: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {"permissions": [], "sdk": {}}
    if not output:
        return parsed
    m = PACKAGE_RE.search(output)
    if m:
        parsed["package"] = m.group(1)
        parsed["version_name"] = m.group(2)
    parsed["permissions"] = sorted(set(PERM_RE.findall(output)))
    for m in SDK_RE.finditer(output):
        if m.group(1):
            parsed["sdk"]["min"] = m.group(1)
        if m.group(2):
            parsed["sdk"]["target"] = m.group(2)
    app_label = re.search(r"application-label(?:-[a-zA-Z0-9_]+)?:'([^']+)'", output)
    if app_label:
        parsed["app_label"] = app_label.group(1)
    return parsed


def parse_aapt_xmltree(output: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "schemes": [],
        "hosts": [],
        "manifest_xmltree_available": bool(output),
    }
    if not output:
        return parsed
    schemes = []
    for m in CUSTOM_SCHEME_RE.finditer(output):
        schemes.append(next(g for g in m.groups() if g))
    hosts = []
    for m in HOST_RE.finditer(output):
        hosts.append(next(g for g in m.groups() if g))
    parsed["schemes"] = sorted(set(schemes))
    parsed["hosts"] = sorted(set(hosts))
    parsed["browsable_mentions"] = output.count("android.intent.category.BROWSABLE")
    parsed["view_action_mentions"] = output.count("android.intent.action.VIEW")
    parsed["exported_true_mentions"] = output.count("exported") and output.count(
        "0xffffffff"
    )
    return parsed


# APKiD signal categories. Anything in HEAVY blocks static review almost entirely
# (encrypted strings, reflective dispatch, packed dex). Anything in MEDIUM
# (DexGuard 5-8 generations) reduces but does not prevent useful triage.
# The capability prefers reading source over reading bytecode, so we down-weight
# both, harder for HEAVY.
APKID_HEAVY_PACKERS = {
    "DexProtector",
    "Bangcle",
    "Tencent's Legu",
    "Tencent Legu",
    "ApkProtect",
    "APKProtect",
    "Promon SHIELD",
    "Liapp",
    "AppSolid",
    "Qihoo 360",
    "Baidu",
    "NQShield",
    "Ijiami",
    "Kiro",
    "Jiagu",
}
APKID_MEDIUM_PACKERS = {
    "DexGuard",  # historically 5.x-8.x are visible
    "DexGuard 9.x",
    "Allatori",
    "ProGuard",
    "Stringer Java Obfuscator",
}
# Signals that something protector-ish is going on without naming it
APKID_AMBIGUOUS_HINTS = {
    "unreadable field names",
    "unreadable method names",
    "illegal class name",
    "anti_disassembly",
}


def summarize_packers(apkid_result: dict[str, Any] | None) -> dict[str, Any]:
    """Reduce an APKiD result blob to a small, comparable shape.

    Returns a dict with:
      hits: sorted unique list of non-noise APKiD strings
      heavy: True if a known anti-static commercial packer is present
      medium: True if a name-mangling obfuscator is present
      ambiguous: True if APKiD flagged class/method-name oddities
      tier: "heavy" | "medium" | "ambiguous" | "clean"
    """
    out = {
        "hits": [],
        "heavy": False,
        "medium": False,
        "ambiguous": False,
        "tier": "clean",
    }
    if not apkid_result or not isinstance(apkid_result, dict):
        return out
    result = apkid_result.get("result") or {}
    files = result.get("files") or []
    hits: set[str] = set()
    NOISE = {
        "android sdk (dx)",
        "android sdk (dx since v35)",
        "android sdk (r8)",
        "android sdk (dexlib 2.x)",
        "android sdk (dexlib 1.x)",
    }
    for fmatch in files:
        m = fmatch.get("matches") or {}
        for cat in (
            "packer",
            "obfuscator",
            "protector",
            "anti_disassembly",
            "anti_vm",
            "anti_debug",
        ):
            for h in m.get(cat) or []:
                if h and h not in NOISE:
                    hits.add(h)
    out["hits"] = sorted(hits)

    def _matches(needle: str, haystack: set[str]) -> bool:
        nl = needle.lower()
        return any(nl in h.lower() for h in haystack)

    for known in APKID_HEAVY_PACKERS:
        if _matches(known, hits):
            out["heavy"] = True
            break
    for known in APKID_MEDIUM_PACKERS:
        if _matches(known, hits):
            out["medium"] = True
            break
    for ambig in APKID_AMBIGUOUS_HINTS:
        if _matches(ambig, hits):
            out["ambiguous"] = True
            break
    if out["heavy"]:
        out["tier"] = "heavy"
    elif out["medium"]:
        out["tier"] = "medium"
    elif out["ambiguous"]:
        out["tier"] = "ambiguous"
    return out


def rank(record: dict[str, Any]) -> dict[str, Any]:
    """Score an inventory record for static-analysis priority.

    Higher is better. Negative reasons (packers, obfuscators) are recorded as
    `reasons` entries prefixed with ``penalty:`` and subtract from the score.
    """
    score = 0
    reasons: list[str] = []
    manifest_hints = record.get("manifest_string_hints", {}) or {}
    schemes = record.get("schemes") or manifest_hints.get("scheme_hints") or []
    hosts = record.get("hosts") or manifest_hints.get("host_hints") or []
    if schemes:
        score += 3
        reasons.append("custom_or_app_link_schemes")
    if hosts:
        score += 2
        reasons.append("declared_or_manifest_hint_link_hosts")
    if record.get("browsable_mentions", 0) or manifest_hints.get("mentions_browsable"):
        score += 3
        reasons.append("browsable_entrypoints")
    if manifest_hints.get("component_like_strings"):
        score += min(4, len(manifest_hints["component_like_strings"]) // 5 + 1)
        reasons.append("manifest_component_string_hints")
    hints = record.get("library_hints", {})
    for key, weight in [
        ("oauth", 4),
        ("payment", 4),
        ("webview_bridge", 4),
        ("firebase", 2),
        ("react_native", 1),
        ("flutter", 1),
    ]:
        if key in hints:
            score += weight
            reasons.append(f"library_hint:{key}")
    if len(record.get("urls", [])) > 20:
        score += 2
        reasons.append("many_embedded_urls")
    if len(record.get("domains", [])) > 20:
        score += 2
        reasons.append("many_embedded_domains")

    # Packer / obfuscator penalty. Applied here when the runner has already
    # merged an `apkid_summary` block into the record. Default behaviour is
    # unchanged for records without packer data — the rank stays comparable
    # with prior runs.
    pk = record.get("apkid_summary") or {}
    tier = pk.get("tier")
    if tier == "heavy":
        score -= 12
        reasons.append("penalty:heavy_packer")
    elif tier == "medium":
        score -= 5
        reasons.append("penalty:medium_obfuscator")
    elif tier == "ambiguous":
        score -= 2
        reasons.append("penalty:ambiguous_obfuscation")

    record["semantic_priority"] = {"score": score, "reasons": sorted(set(reasons))}
    return record


def analyze_apk(apk: Path) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "apk": str(apk),
        "file_name": apk.name,
        "size": apk.stat().st_size,
        "sha256": sha256_file(apk),
    }
    rec.update(zip_inventory(apk))
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        rec.update(parse_aapt_badging(run_cmd([aapt, "dump", "badging", str(apk)])))
        rec.update(
            parse_aapt_xmltree(
                run_cmd([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"])
            )
        )
    else:
        rec["tool_warnings"] = [
            "aapt/aapt2 not found; package/component/link metadata uses binary-manifest string-pool fallback and is partial"
        ]
    return rank(rec)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract semantic attack-surface inventory from APKs"
    )
    ap.add_argument(
        "paths", nargs="+", type=Path, help="APK files or directories containing APKs"
    )
    ap.add_argument(
        "--out", type=Path, help="Write JSONL output to this path; defaults to stdout"
    )
    ap.add_argument(
        "--json", action="store_true", help="Emit a single JSON array instead of JSONL"
    )
    args = ap.parse_args()

    apks = iter_apks(args.paths)
    # Stream one record at a time so memory stays at O(one record), not O(corpus).
    # JSON-array mode still buffers (it has to write a single array), but the JSONL
    # path — which is what the corpus runner uses — is fully streaming.
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.out.open("w") if args.out else sys.stdout
    try:
        if args.json:
            out_fh.write("[\n")
            for idx, apk in enumerate(apks):
                if idx:
                    out_fh.write(",\n")
                out_fh.write(json.dumps(analyze_apk(apk), sort_keys=True))
            out_fh.write("\n]\n")
        else:
            for apk in apks:
                out_fh.write(json.dumps(analyze_apk(apk), sort_keys=True))
                out_fh.write("\n")
    finally:
        if args.out:
            out_fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
