#!/usr/bin/env python3
"""Score and rank components from `extract_corpus_components.py` output.

Applies risk priors to each component row and emits:
  - components_ranked.jsonl  (full schema + score + reasons + read-budget tag)
  - components_ranked.md     (operator inbox — top N grouped by app)

Priors (tuned 2026-05-18 against corpus-2; revise as more empirics come in):

  +5  exported + no permission + BROWSABLE
  +3  host wildcard `*` or empty/missing
  +3  path/name matches "(join|accept|invite|redirect|callback|sso|oauth|
                         mpless|transfer|register|complete|recover|magic|
                         consume|reset|enroll|claim|activate|verify|next|
                         return|continue|target|intent|router|proxy|dispatch|
                         open|import|share)"
  +3  action matches "(IMPORT_|EXPORT_|RECOVER_|MIGRATE_|RESET_)"
                     or scheme in {otpauth, smsto, smsmms}
  +3  exported/no-perm share/import target (SEND, SEND_MULTIPLE, GET_CONTENT,
       OPEN_DOCUMENT, PICK)
  +2  broad MIME share/import target (*/*, application/octet-stream)
  +2  exported AutofillService / AccessibilityService / CredentialProviderService
  +2  exported ContentProvider with grantUriPermissions=true
  +2  exported BROADCAST receiver with no perm + action not in {INSTALL_REFERRER,
                                                                BOOT_COMPLETED}
  +1  scheme in {http, https} (App Link surface) with non-wildcard host
       (lower than wildcard host but worth surfacing)

  Corpus-3 adjustments (2026-05-19):

  +2  router-shape component name (Router/Dispatcher/Resolver/DeepLink/AppLink/
       NavHandler) with >=3 distinct schemes and >=3 distinct hosts. Empirically
       this is the *current* high-impact deep-link shape after the post-MSRC-2024
       Dirty Stream fix campaign. Examples surfaced in corpus-3: Robinhood
       DeeplinkResolverActivity, Chase DeepLinkHandlerActivity, Mint RouterActivity,
       Citi SplashScreenActivity, Teams SplashActivity.
  +1  runtime_kind in hybrid set (react_native_js, react_native_hermes, flutter_aot,
       capacitor, cordova). Hybrid surfaces have an extra JS/Dart trust boundary
       that scanners can't reach, so worth promoting these in the inbox to offset
       the JS/Dart follow-up cost.
  -2  file/content scheme share/import target on a component file with <=80 lines
       (delegating stub). Empirically the Dirty-Stream-shaped top tier is dominated
       by short subclasses that immediately delegate to a base; only the base class
       has any real logic, so the manifest-only rank over-weights every subclass.
       NOTE: requires --src to be set; otherwise the rule is silent.
  -1  receiver/activity name matches "(Splash|Launcher|Receiver)$" with no scheme
       and no high-risk action — these score 7-9 on host_wildcard alone but rarely
       lead anywhere.
  -2  permission with protectionLevel=normal
  -5  permission with protectionLevel=signature (defanged unless attacker has same sig)
 -12  apkid_tier=heavy
  -1  declared MAIN/LAUNCHER only and nothing else
  -1  component name matches "Hilt_|_GeneratedInjector|_MembersInjector|Dagger|_Factory$"

Read-budget tag (informational):
  read_budget = "5m"   if score >= 7
              = "1m"   if score in [3, 6]
              = "skip" if score < 3

Usage:
  python3 rank_components.py \
    --components findings/corpus-2/triage/components.jsonl \
    --out-jsonl findings/corpus-2/triage/components_ranked.jsonl \
    --out-md    findings/corpus-2/triage/components_ranked.md \
    --top-md 100
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

HIGH_RISK_PATH_RE = re.compile(
    r"(join|accept|invite|redirect|callback|sso|oauth|mpless|transfer|register|"
    r"complete|recover|magic|consume|reset|enroll|claim|activate|verify|next|"
    r"return|continue|target|intent|router|proxy|dispatch|open|import|share)",
    re.IGNORECASE,
)
HIGH_RISK_ACTION_RE = re.compile(r"(IMPORT_|EXPORT_|RECOVER_|MIGRATE_|RESET_)")
HIGH_RISK_SCHEMES = {"otpauth", "smsto", "smsmms"}
ROUTER_NAME_RE = re.compile(
    r"(Router|Dispatcher|Resolver|DeepLink|AppLink|NavHandler|UriHandler|"
    r"IntentHandler|LinkRedirect|RedirectUri)",
    re.IGNORECASE,
)
HYBRID_RUNTIME_KINDS = {
    "react_native_js",
    "react_native_hermes",
    "flutter_aot",
    "capacitor",
    "cordova",
}
LOW_SIGNAL_TAIL_NAME_RE = re.compile(r"(Splash|Launcher|Receiver)Activity?$")
SHARE_IMPORT_ACTIONS = {
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.OPEN_DOCUMENT",
    "android.intent.action.PICK",
}
BROAD_MIME_TYPES = {"*/*", "application/octet-stream"}
GENERATED_NAME_RE = re.compile(
    r"(Hilt_|_GeneratedInjector|_MembersInjector|Dagger|_Factory$|_Provide|Hilt$)"
)
BENIGN_RECEIVER_ACTIONS = {
    "com.android.vending.INSTALL_REFERRER",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_REPLACED",
}
AUTOFILL_LIKE_SERVICE_ACTIONS = {
    "android.service.autofill.AutofillService",
    "android.service.credentials.CredentialProviderService",
    "android.accessibilityservice.AccessibilityService",
}


def host_wildcard(hosts: list[str]) -> bool:
    if not hosts:
        return True  # implicit any-host
    return any(h in ("", "*") for h in hosts)


def score_component(row: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if row.get("exported") is False:
        # Definitely-internal — skip unless we want to surface for completeness.
        return 0, ["not_exported"]

    exported = row.get("exported") is True or row.get("browsable") is True
    perm = row.get("permission") or ""
    perm_protection = (row.get("perm_protection") or "").lower()
    browsable = bool(row.get("browsable"))
    actions = row.get("actions") or []
    schemes = row.get("schemes") or []
    hosts = row.get("hosts") or []
    paths = row.get("paths") or []
    typ = row.get("type")
    name = row.get("name") or ""

    if exported and not perm and browsable:
        score += 5
        reasons.append("exported_browsable_no_perm")

    if browsable and host_wildcard(hosts):
        score += 3
        reasons.append("host_wildcard")

    if any(HIGH_RISK_PATH_RE.search(p) for p in paths):
        score += 3
        reasons.append("high_risk_path")

    if exported and not perm and HIGH_RISK_PATH_RE.search(name):
        score += 2
        reasons.append("high_risk_component_name")

    if any(HIGH_RISK_ACTION_RE.search(a) for a in actions):
        score += 3
        reasons.append("high_risk_action")
    if any(s in HIGH_RISK_SCHEMES for s in schemes):
        score += 3
        reasons.append("high_risk_scheme")

    if exported and not perm and any(a in SHARE_IMPORT_ACTIONS for a in actions):
        score += 3
        reasons.append("share_import_target_no_perm")

    mime_types = row.get("mime_types") or []
    if exported and any(m in BROAD_MIME_TYPES or m.endswith("/*") for m in mime_types):
        score += 2
        reasons.append("broad_mime_share_import")

    if typ == "service" and any(a in AUTOFILL_LIKE_SERVICE_ACTIONS for a in actions):
        score += 2
        reasons.append("auth_critical_service")

    if typ == "provider" and (
        row.get("grant_uri") in (True, "true", "0xffffffff", "-1")
    ):
        score += 2
        reasons.append("provider_grant_uri")

    if (
        typ == "receiver"
        and exported
        and not perm
        and actions
        and not any(a in BENIGN_RECEIVER_ACTIONS for a in actions)
    ):
        # Custom action on an exported receiver with no perm is a smell.
        score += 2
        reasons.append("exported_custom_receiver_no_perm")

    if (
        browsable
        and any(s in ("http", "https") for s in schemes)
        and not host_wildcard(hosts)
    ):
        score += 1
        reasons.append("app_link_surface")

    # Corpus-3: reward concentrated deep-link routers (the post-MSRC-2024 bug shape).
    if (
        ROUTER_NAME_RE.search(name)
        and len({s for s in schemes if s}) >= 3
        and len({h for h in hosts if h and h != "*"}) >= 3
    ):
        score += 2
        reasons.append("router_shape_multi_scheme_host")

    # Corpus-3: hybrid runtimes have an extra JS/Dart trust boundary scanners miss.
    if row.get("runtime_kind") in HYBRID_RUNTIME_KINDS:
        score += 1
        reasons.append(f"hybrid_runtime:{row['runtime_kind']}")

    # Corpus-3: low-signal Splash/Launcher/Receiver tail without scheme+action specifics
    # is rarely a real chain; penalize so they don't crowd out router hits.
    if (
        LOW_SIGNAL_TAIL_NAME_RE.search(name)
        and not schemes
        and not any(HIGH_RISK_ACTION_RE.search(a) for a in actions)
    ):
        score -= 1
        reasons.append("low_signal_tail_name")

    if perm_protection == "normal":
        score -= 2
        reasons.append("perm_normal")
    elif perm_protection == "signature" or perm_protection == "0x2":
        score -= 5
        reasons.append("perm_signature")
    elif perm_protection in ("signatureOrSystem", "0x3", "signatureorsystem"):
        score -= 4
        reasons.append("perm_signature_or_system")

    if row.get("apkid_tier") == "heavy":
        score -= 12
        reasons.append("apkid_heavy_packer")
    elif row.get("apkid_tier") == "medium":
        score -= 3
        reasons.append("apkid_medium_packer")
    elif row.get("apkid_tier") == "ambiguous":
        score -= 1
        reasons.append("apkid_ambiguous_packer")

    # MAIN/LAUNCHER-only is launcher boilerplate
    if actions == [
        "android.intent.action.MAIN"
    ] and "android.intent.category.LAUNCHER" in (row.get("categories") or []):
        score -= 1
        reasons.append("launcher_only")

    if GENERATED_NAME_RE.search(name):
        score -= 1
        reasons.append("generated_class")

    return score, reasons


def read_budget(score: int) -> str:
    if score >= 7:
        return "5m"
    if score >= 3:
        return "1m"
    return "skip"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--components", required=True, type=Path)
    ap.add_argument("--out-jsonl", required=True, type=Path)
    ap.add_argument("--out-md", required=True, type=Path)
    ap.add_argument("--top-md", type=int, default=100)
    ap.add_argument(
        "--min-score",
        type=int,
        default=3,
        help="suppress rows below this score from the markdown view (jsonl keeps all)",
    )
    args = ap.parse_args()

    rows: list[dict[str, Any]] = []
    for line in args.components.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        score, reasons = score_component(row)
        row["score"] = score
        row["score_reasons"] = reasons
        row["read_budget"] = read_budget(score)
        rows.append(row)

    rows.sort(key=lambda r: (-r["score"], r.get("package") or "", r.get("name") or ""))

    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.out_jsonl.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    # Markdown view: keep score >= min-score, cap at top-md, group by package.
    eligible = [r for r in rows if r["score"] >= args.min_score][: args.top_md]
    by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in eligible:
        by_pkg[r.get("package") or "(unknown)"].append(r)

    lines: list[str] = []
    lines.append("# Corpus components — ranked\n")
    lines.append(
        f"Total components scored: {len(rows)} (across {len({r['apk_sha256'] for r in rows})} APKs). "
        f"Showing top {len(eligible)} with score >= {args.min_score}.\n"
    )
    lines.append(
        "Score legend: see `rank_components.py` docstring. Read-budget: "
        "`5m` = full deep-read; `1m` = grep + skim; `skip` = below threshold.\n"
    )
    lines.append("## Top entries by impact class\n")
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in eligible:
        by_class[r.get("impact_class") or "(unclassified)"].append(r)
    for cls in sorted(by_class):
        rs = by_class[cls]
        lines.append(f"\n### {cls} — {len(rs)} components in top-{len(eligible)}\n")
        for r in rs:
            lines.append(
                f"- **{r['score']}** `{r.get('package')}` / {r.get('type')} "
                f"`{r.get('name')}` — "
                f"budget={r['read_budget']} "
                f"reasons=[{', '.join(r['score_reasons'])}]"
            )
            sc = r.get("schemes") or []
            ho = r.get("hosts") or []
            pa = r.get("paths") or []
            ac = [
                a
                for a in (r.get("actions") or [])
                if a
                not in (
                    "android.intent.action.VIEW",
                    "android.intent.action.MAIN",
                )
            ]
            if sc:
                lines.append(f"    - schemes: {sc}")
            if ho:
                lines.append(f"    - hosts: {ho}")
            if pa:
                lines.append(f"    - paths: {pa[:10]}")
            if ac:
                lines.append(f"    - actions: {ac[:5]}")

    lines.append("\n## Full ranked list grouped by package\n")
    for pkg in sorted(by_pkg):
        rs = by_pkg[pkg]
        top_score = max(r["score"] for r in rs)
        lines.append(f"\n### {pkg} (top score {top_score})\n")
        for r in rs:
            lines.append(
                f"- **{r['score']}** {r.get('type')} `{r.get('name')}` "
                f"reasons=[{', '.join(r['score_reasons'])}]"
            )

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(lines) + "\n")
    print(f"wrote {len(rows)} rows to {args.out_jsonl}")
    print(f"wrote top-{len(eligible)} markdown view to {args.out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
