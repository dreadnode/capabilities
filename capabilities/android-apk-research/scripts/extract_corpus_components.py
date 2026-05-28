#!/usr/bin/env python3
"""Stream every per-APK androguard.json under a corpus inventory dir and emit
one JSONL row per component, with the manifest facts joined to APK-level info.

Falls back to `aapt2 dump xmltree` for APKs whose androguard.json errored out
(empirically: multi-dex APKs with >=22 classes*.dex break Androguard 4.1.3 with
`unpack requires a buffer of 2 bytes`).

Output schema (one JSON object per line):

  {
    "apk_sha256":   "...",                  # SHA256 of the .apk
    "apk_path":     "...",                  # corpus relative path (if known)
    "package":      "com.example",
    "version_name": "...",
    "version_code": 42,
    "min_sdk":      29,
    "target_sdk":   34,
    "apkid_tier":   "clean|ambiguous|medium|heavy",
    "runtime_kind": "native|react_native_hermes|...",  # if available
    "impact_class": "C_wallet",             # if joined from triage manifest
    "type":         "activity|service|receiver|provider",
    "name":         "com.example.X",
    "exported":     true,
    "permission":   "...",                  # the android:permission on the component
    "perm_protection": "signature|normal|...", # joined from manifest perm decls
    "browsable":    true,
    "schemes":      ["dashlane", "otpauth"],
    "hosts":        ["*"],
    "paths":        ["/vault", "/mplesslogin", ...],
    "actions":      ["android.intent.action.VIEW", ...],
    "categories":   ["android.intent.category.BROWSABLE", ...],
    "mime_types":   ["image/*"],
    "grant_uri":    null,                   # provider-only
    "source":       "androguard|aapt2"
  }

Usage:
  python3 extract_corpus_components.py \
    --inventory-dir findings/corpus-2/inventory/apks \
    --triage-manifest findings/corpus-2/triage/manifest.jsonl \
    --out findings/corpus-2/triage/components.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

ANS = "http://schemas.android.com/apk/res/android:"


def strip_ns(k: str) -> str:
    return k.replace(ANS, "android:")


def parse_aapt2_manifest(apk_path: Path) -> dict[str, Any] | None:
    """Return a dict shaped like androguard.json from `aapt2 dump xmltree`.

    Fallback for APKs that broke Androguard. Best-effort; only fills the
    fields this script consumes.
    """
    try:
        proc = subprocess.run(
            [
                "aapt2",
                "dump",
                "xmltree",
                "--file",
                "AndroidManifest.xml",
                str(apk_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"aapt2 failed on {apk_path}: {exc}", file=sys.stderr)
        return None
    if proc.returncode != 0:
        print(f"aapt2 nonzero on {apk_path}: {proc.stderr[:200]}", file=sys.stderr)
        return None
    out = proc.stdout

    elem_re = re.compile(r"^(\s*)E: (\w+)")
    attr_re = re.compile(r"^(\s*)A: (\S+?)(?:\([^)]*\))?=(.*?)$")
    raw_re = re.compile(r'\(Raw: "([^"]*)"\)')

    stack: list[list[Any]] = []
    events: list[list[Any]] = []
    for line in out.splitlines():
        em = elem_re.match(line)
        if em:
            indent, name = len(em.group(1)), em.group(2)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            node = [indent, name, {}]
            stack.append(node)
            events.append(node)
            continue
        am = attr_re.match(line)
        if am and stack:
            indent = len(am.group(1))
            key = strip_ns(am.group(2))
            value = am.group(3).strip()
            rm = raw_re.search(value)
            value = rm.group(1) if rm else value.strip('"')
            for s in reversed(stack):
                if s[0] < indent:
                    s[2][key] = value
                    break

    # package
    package = None
    for ev in events:
        if ev[1] == "manifest":
            package = ev[2].get("package")
            break

    # permissions declared at top level → name -> protectionLevel
    declared_perms: dict[str, str] = {}
    for ev in events:
        if ev[1] == "permission":
            n = ev[2].get("android:name")
            if n:
                declared_perms[n] = ev[2].get("android:protectionLevel", "")

    components: list[dict[str, Any]] = []
    for idx, ev in enumerate(events):
        if ev[1] not in ("activity", "service", "receiver", "provider"):
            continue
        base = ev[0]
        exported_raw = ev[2].get("android:exported", "")
        exported_norm = None
        if exported_raw in ("0xffffffff", "true", "-1"):
            exported_norm = True
        elif exported_raw in ("0x0", "false", "0"):
            exported_norm = False
        intent_filters: list[dict[str, Any]] = []
        cur_filter: dict[str, Any] | None = None
        j = idx + 1
        while j < len(events) and events[j][0] > base:
            child = events[j]
            if child[1] == "intent-filter":
                cur_filter = {
                    "actions": [],
                    "categories": [],
                    "data": [],
                    "browsable": False,
                    "view": False,
                }
                intent_filters.append(cur_filter)
            elif cur_filter is not None and child[1] == "action":
                name = child[2].get("android:name")
                if name:
                    cur_filter["actions"].append(name)
                    if name == "android.intent.action.VIEW":
                        cur_filter["view"] = True
            elif cur_filter is not None and child[1] == "category":
                name = child[2].get("android:name")
                if name:
                    cur_filter["categories"].append(name)
                    if name == "android.intent.category.BROWSABLE":
                        cur_filter["browsable"] = True
            elif cur_filter is not None and child[1] == "data":
                d: dict[str, Any] = {}
                for k in (
                    "android:scheme",
                    "android:host",
                    "android:port",
                    "android:path",
                    "android:pathPrefix",
                    "android:pathPattern",
                    "android:mimeType",
                ):
                    if k in child[2]:
                        d[k.split(":", 1)[1]] = child[2][k]
                if d:
                    cur_filter["data"].append(d)
            j += 1
        any_browsable = any(f["browsable"] for f in intent_filters)
        components.append(
            {
                "type": ev[1],
                "name": ev[2].get("android:name", ""),
                "raw_name": ev[2].get("android:name", ""),
                "exported": exported_norm,
                "permission": ev[2].get("android:permission"),
                "browsable": any_browsable,
                "view": any(f["view"] for f in intent_filters),
                "grantUriPermissions": ev[2].get("android:grantUriPermissions"),
                "intent_filters": intent_filters,
            }
        )

    return {
        "package": package,
        "components": components,
        "_declared_perms": declared_perms,
        "_source": "aapt2",
    }


def normalize_androguard_data(g: dict[str, Any]) -> dict[str, Any]:
    """Normalize an androguard.json into the same shape the consumer expects.

    Adds `_declared_perms` as empty (androguard didn't capture protection
    levels here; we keep the field for shape parity).
    """
    g.setdefault("_declared_perms", {})
    g["_source"] = "androguard"
    return g


def gather_intent_filter_facts(comp: dict[str, Any]) -> dict[str, Any]:
    schemes: list[str] = []
    hosts: list[str] = []
    paths: list[str] = []
    actions: list[str] = []
    categories: list[str] = []
    mimes: list[str] = []
    for f in comp.get("intent_filters", []) or []:
        for a in f.get("actions") or []:
            if a not in actions:
                actions.append(a)
        for c in f.get("categories") or []:
            if c not in categories:
                categories.append(c)
        for d in f.get("data") or []:
            if "scheme" in d and d["scheme"] not in schemes:
                schemes.append(d["scheme"])
            if "host" in d and d["host"] not in hosts:
                hosts.append(d["host"])
            for pk in ("path", "pathPrefix", "pathPattern"):
                if pk in d:
                    paths.append(f"{pk}={d[pk]}")
            if "mimeType" in d and d["mimeType"] not in mimes:
                mimes.append(d["mimeType"])
    return {
        "schemes": schemes,
        "hosts": hosts,
        "paths": paths,
        "actions": actions,
        "categories": categories,
        "mime_types": mimes,
    }


def load_triage_index(path: Path | None) -> dict[str, dict[str, Any]]:
    if not path or not path.exists():
        return {}
    idx: dict[str, dict[str, Any]] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        sha = obj.get("sha256")
        if sha:
            idx[sha] = obj
    return idx


def load_runtime_kind_index(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    idx: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # The runtime_kind sweep is keyed by apk path; we keep package + kind.
        apk = obj.get("apk", "")
        # Strip dir
        stem = Path(apk).stem
        # Map package-version stem -> kind. We'll join via apk_path basename match.
        idx[stem] = obj.get("runtime_kind", "")
    return idx


def iter_components(
    inventory_dir: Path,
    triage_idx: dict[str, dict[str, Any]],
    runtime_idx: dict[str, str],
) -> Iterator[dict[str, Any]]:
    for sha_dir in sorted(inventory_dir.iterdir()):
        if not sha_dir.is_dir():
            continue
        sha = sha_dir.name
        ag_path = sha_dir / "androguard.json"
        if not ag_path.exists():
            continue
        try:
            ag = json.loads(ag_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"bad androguard.json for {sha}: {exc}", file=sys.stderr)
            continue

        triage = triage_idx.get(sha, {})
        apk_path = triage.get("apk_path")
        used_fallback = False

        if ag.get("status") == "error" or not ag.get("components"):
            if apk_path and Path(apk_path).exists():
                fb = parse_aapt2_manifest(Path(apk_path))
                if fb:
                    ag = fb
                    used_fallback = True
                else:
                    continue
            else:
                continue
        else:
            ag = normalize_androguard_data(ag)

        package = ag.get("package") or triage.get("package")
        declared_perms = ag.get("_declared_perms") or {}

        # APK-level metadata
        apkid_tier = triage.get("apkid_tier")
        impact_class = triage.get("impact_class")
        version_name = ag.get("version_name") or triage.get("version_name")
        version_code = ag.get("version_code") or triage.get("version_code")
        min_sdk = ag.get("min_sdk")
        target_sdk = ag.get("target_sdk")

        # Runtime kind via apk basename stem (best-effort)
        runtime_kind = ""
        if apk_path:
            runtime_kind = runtime_idx.get(Path(apk_path).stem, "")

        for comp in ag.get("components", []) or []:
            facts = gather_intent_filter_facts(comp)
            perm = comp.get("permission")
            yield {
                "apk_sha256": sha,
                "apk_path": apk_path,
                "package": package,
                "version_name": version_name,
                "version_code": version_code,
                "min_sdk": min_sdk,
                "target_sdk": target_sdk,
                "apkid_tier": apkid_tier,
                "runtime_kind": runtime_kind,
                "impact_class": impact_class,
                "type": comp.get("type"),
                "name": comp.get("name"),
                "exported": comp.get("exported"),
                "permission": perm,
                "perm_protection": declared_perms.get(perm or "", ""),
                "browsable": comp.get("browsable", False),
                "view": comp.get("view", False),
                "grant_uri": comp.get("grantUriPermissions"),
                "source": ag.get("_source")
                or ("aapt2" if used_fallback else "androguard"),
                **facts,
            }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory-dir", required=True, type=Path)
    ap.add_argument(
        "--triage-manifest",
        type=Path,
        default=None,
        help="optional triage manifest JSONL keyed by sha256 for apk_path / impact_class / apkid_tier joins",
    )
    ap.add_argument(
        "--runtime-kind",
        type=Path,
        default=None,
        help="optional runtime_kind JSONL from detect_runtime_kind.sh sweep",
    )
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    triage_idx = load_triage_index(args.triage_manifest)
    runtime_idx = load_runtime_kind_index(args.runtime_kind)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    n_rows = 0
    n_fallback = 0
    seen_sha: set[str] = set()
    with args.out.open("w") as f:
        for row in iter_components(args.inventory_dir, triage_idx, runtime_idx):
            f.write(json.dumps(row, sort_keys=True) + "\n")
            n_rows += 1
            if row["source"] == "aapt2":
                n_fallback += 1
            seen_sha.add(row["apk_sha256"])
    print(f"wrote {n_rows} components from {len(seen_sha)} APKs to {args.out}")
    if n_fallback:
        print(f"  ({n_fallback} rows used aapt2 fallback)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
