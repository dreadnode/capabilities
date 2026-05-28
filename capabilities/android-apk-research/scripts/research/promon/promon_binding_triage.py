#!/usr/bin/env python3
"""Extract Promon Java/native binding callsites from smali.

This script specializes the Java triage result into a binding map for methods
such as:
  Lgms/e;->a(I)Ljava/lang/String;
  Lgms/e;->a(Ljava/lang/Class;I)V

It does not recover plaintext values. It maps hidden IDs to callsites and
immediate use context so the next recovery step can target the right native
lookup table or dynamic dump points.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CLASS_RE = re.compile(r"^\.class\s+.*?\s+(L[^;]+;)")
METHOD_RE = re.compile(r"^\.method\s+.*?\s+([^\s]+)$")
INVOKE_RE = re.compile(
    r"^(?P<op>invoke-\S+)\s+\{(?P<regs>[^}]*)\},\s+(?P<target>\S+;->\S+)$"
)
CONST_RE = re.compile(
    r"^const(?:/\S+)?\s+(?P<reg>[vp]\d+),\s+(?P<value>[-+]?0x[0-9a-fA-F]+|[-+]?\d+)"
)
CONST_CLASS_RE = re.compile(r"^const-class\s+(?P<reg>[vp]\d+),\s+(?P<class>L[^;]+;)")
MOVE_RESULT_RE = re.compile(r"^move-result-object\s+(?P<reg>[vp]\d+)")

DEFAULT_STRING_TARGET_RE = ""
DEFAULT_CLASS_TARGET_RE = ""
METHOD_RE_FULL = re.compile(r"^\.method\s+(?P<decl>.+)$")
NATIVE_DECL_RE = re.compile(r"(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<ret>\S+)$")

SINK_PATTERNS = [
    (
        "url_or_uri",
        [
            "Ljava/net/URL;",
            "Ljava/net/URI;",
            "Landroid/net/Uri;",
            "parse(Ljava/lang/String;)",
        ],
    ),
    (
        "webview",
        [
            "Landroid/webkit/WebView;",
            "loadUrl",
            "evaluateJavascript",
            "addJavascriptInterface",
        ],
    ),
    ("intent", ["Landroid/content/Intent;", "setAction", "putExtra", "getStringExtra"]),
    ("json", ["Lorg/json/", "put(Ljava/lang/String;", "optString", "getString"]),
    ("shared_preferences", ["SharedPreferences", "getString", "putString"]),
    ("file_path", ["Ljava/io/File;", "FileInputStream", "FileOutputStream"]),
    ("crypto", ["Ljavax/crypto/", "MessageDigest", "KeyStore", "Certificate"]),
    (
        "react_native",
        [
            "Lcom/facebook/react/",
            "WritableMap",
            "ReadableMap",
            "Promise",
            "ReactMethod",
        ],
    ),
    (
        "log",
        ["Landroid/util/Log;", "Ljava/lang/Exception;-><init>(Ljava/lang/String;)"],
    ),
]


@dataclass
class BindingCall:
    file: str
    class_name: str | None
    method_name: str | None
    line: int
    binding_type: str
    target: str
    id_value: int | None
    id_hex: str | None
    class_argument: str | None
    argument_registers: list[str]
    result_register: str | None
    immediate_uses: list[dict[str, Any]]
    sink_hints: list[str]
    context: list[str]

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)


def smali_files(root: Path) -> list[Path]:
    if root.is_file() and root.suffix == ".smali":
        return [root]
    return sorted(p for p in root.rglob("*.smali") if p.is_file())


def parse_regs(text: str) -> list[str]:
    if ".." in text:
        return []
    return [x.strip() for x in text.split(",") if x.strip()]


def parse_int(s: str) -> int | None:
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        return None


def class_at(lines: list[str]) -> str | None:
    for line in lines:
        m = CLASS_RE.match(line.strip())
        if m:
            return m.group(1)
    return None


def method_at(lines: list[str], idx: int) -> str | None:
    for j in range(idx, -1, -1):
        s = lines[j].strip()
        if s == ".end method":
            return None
        m = METHOD_RE.match(s)
        if m:
            return m.group(1)
    return None


def collect_native_binding_targets(
    files: list[Path], root: Path
) -> tuple[set[str], set[str]]:
    string_targets: set[str] = set()
    class_targets: set[str] = set()
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        cls = class_at(lines)
        if not cls:
            continue
        for raw in lines:
            m = METHOD_RE_FULL.match(raw.strip())
            if not m:
                continue
            parts = m.group("decl").split()
            if "native" not in parts or not parts:
                continue
            sig = parts[-1]
            sm = NATIVE_DECL_RE.match(sig)
            if not sm:
                continue
            args = sm.group("args")
            ret = sm.group("ret")
            full = f"{cls}->{sig}"
            if ret == "Ljava/lang/String;" and args in {"I", "II"}:
                string_targets.add(full)
            if ret == "V" and args == "Ljava/lang/Class;I":
                class_targets.add(full)
    return string_targets, class_targets


def previous_const_int(
    lines: list[str], idx: int, reg: str, max_back: int = 40
) -> int | None:
    for j in range(idx - 1, max(-1, idx - max_back - 1), -1):
        m = CONST_RE.match(lines[j].strip())
        if m and m.group("reg") == reg:
            return parse_int(m.group("value"))
    return None


def previous_const_class(
    lines: list[str], idx: int, reg: str, max_back: int = 40
) -> str | None:
    for j in range(idx - 1, max(-1, idx - max_back - 1), -1):
        m = CONST_CLASS_RE.match(lines[j].strip())
        if m and m.group("reg") == reg:
            return m.group("class")
    return None


def result_register_after(lines: list[str], idx: int) -> str | None:
    for j in range(idx + 1, min(len(lines), idx + 5)):
        m = MOVE_RESULT_RE.match(lines[j].strip())
        if m:
            return m.group("reg")
        if (
            lines[j].strip()
            and not lines[j].strip().startswith(":")
            and not lines[j].strip().startswith(".line")
        ):
            # keep looking through blank/label/line noise only
            continue
    return None


def context_window(lines: list[str], idx: int, radius: int = 8) -> list[str]:
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return [f"{i+1}: {lines[i]}" for i in range(start, end)]


def classify_sinks(texts: list[str]) -> list[str]:
    hints = []
    joined = "\n".join(texts)
    for name, pats in SINK_PATTERNS:
        if any(p in joined for p in pats):
            hints.append(name)
    return sorted(set(hints))


def immediate_uses(
    lines: list[str], idx: int, result_reg: str | None, max_forward: int = 16
) -> list[dict[str, Any]]:
    if not result_reg:
        return []
    uses: list[dict[str, Any]] = []
    for j in range(idx + 1, min(len(lines), idx + max_forward + 1)):
        s = lines[j].strip()
        if not s or s.startswith(".line") or s.startswith(":"):
            continue
        if result_reg not in s:
            continue
        inv = INVOKE_RE.match(s)
        uses.append(
            {
                "line": j + 1,
                "text": s,
                "invoke_target": inv.group("target") if inv else None,
                "invoke_op": inv.group("op") if inv else None,
            }
        )
        if len(uses) >= 8:
            break
    return uses


def scan_file(
    path: Path,
    root: Path,
    string_targets: set[str],
    class_targets: set[str],
    string_re: re.Pattern[str] | None,
    class_re: re.Pattern[str] | None,
) -> list[BindingCall]:
    rel = str(path.relative_to(root))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cls = class_at(lines)
    calls: list[BindingCall] = []
    for i, raw in enumerate(lines):
        s = raw.strip()
        inv = INVOKE_RE.match(s)
        if not inv:
            continue
        target = inv.group("target")
        regs = parse_regs(inv.group("regs"))
        binding_type = None
        id_value = None
        class_arg = None
        if target in string_targets or (
            string_re is not None and string_re.search(target)
        ):
            binding_type = "string"
            if regs:
                id_value = previous_const_int(lines, i, regs[-1])
        elif target in class_targets or (
            class_re is not None and class_re.search(target)
        ):
            binding_type = "class_or_field"
            if regs:
                id_value = previous_const_int(lines, i, regs[-1])
            if len(regs) >= 2:
                class_arg = previous_const_class(lines, i, regs[-2])
                if class_arg is None and regs[-2].startswith("p"):
                    class_arg = cls
        else:
            continue
        result_reg = (
            result_register_after(lines, i) if binding_type == "string" else None
        )
        uses = immediate_uses(lines, i, result_reg)
        ctx = context_window(lines, i)
        sink_hints = classify_sinks([u["text"] for u in uses] + ctx)
        calls.append(
            BindingCall(
                file=rel,
                class_name=cls,
                method_name=method_at(lines, i),
                line=i + 1,
                binding_type=binding_type,
                target=target,
                id_value=id_value,
                id_hex=hex(id_value) if id_value is not None else None,
                class_argument=class_arg,
                argument_registers=regs,
                result_register=result_reg,
                immediate_uses=uses,
                sink_hints=sink_hints,
                context=ctx,
            )
        )
    return calls


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input", type=Path, help="apktool-decoded smali directory or .smali file"
    )
    ap.add_argument(
        "-o", "--out", type=Path, required=True, help="bindings JSONL output"
    )
    ap.add_argument("--summary", type=Path, default=None, help="markdown summary path")
    ap.add_argument(
        "--json", type=Path, default=None, help="aggregate JSON output path"
    )
    ap.add_argument(
        "--string-target-regex",
        default=DEFAULT_STRING_TARGET_RE,
        help="regex for string binding native target",
    )
    ap.add_argument(
        "--class-target-regex",
        default=DEFAULT_CLASS_TARGET_RE,
        help="regex for class/field binding native target",
    )
    args = ap.parse_args()

    root = args.input.resolve()
    scan_root = root if root.is_dir() else root.parent
    files = smali_files(root)
    native_string_targets, native_class_targets = collect_native_binding_targets(
        files, scan_root
    )
    string_re = (
        re.compile(args.string_target_regex) if args.string_target_regex else None
    )
    class_re = re.compile(args.class_target_regex) if args.class_target_regex else None
    calls: list[BindingCall] = []
    for f in files:
        calls.extend(
            scan_file(
                f,
                scan_root,
                native_string_targets,
                native_class_targets,
                string_re,
                class_re,
            )
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "\n".join(c.to_json() for c in calls) + ("\n" if calls else ""),
        encoding="utf-8",
    )

    by_type: dict[str, int] = {}
    by_target: dict[str, int] = {}
    by_sink: dict[str, int] = {}
    ids_by_target: dict[str, set[int]] = {}
    for c in calls:
        by_type[c.binding_type] = by_type.get(c.binding_type, 0) + 1
        by_target[c.target] = by_target.get(c.target, 0) + 1
        if c.id_value is not None:
            ids_by_target.setdefault(c.target, set()).add(c.id_value)
        for hint in c.sink_hints:
            by_sink[hint] = by_sink.get(hint, 0) + 1

    aggregate = {
        "input": str(args.input),
        "files_scanned": len(files),
        "binding_calls": len(calls),
        "native_string_targets": sorted(native_string_targets),
        "native_class_targets": sorted(native_class_targets),
        "by_type": by_type,
        "by_target_top20": dict(
            sorted(by_target.items(), key=lambda kv: kv[1], reverse=True)[:20]
        ),
        "unique_ids_by_target": {k: len(v) for k, v in sorted(ids_by_target.items())},
        "by_sink_hint": dict(
            sorted(by_sink.items(), key=lambda kv: kv[1], reverse=True)
        ),
        "examples": [c.__dict__ for c in calls[:50]],
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(aggregate, indent=2, sort_keys=True), encoding="utf-8"
        )

    if args.summary:
        lines = [
            "# Promon binding triage summary",
            "",
            f"Input: `{args.input}`",
            f"Smali files scanned: {len(files)}",
            f"Binding callsites: {len(calls)}",
            "",
            "## By type",
            "",
        ]
        for k, v in sorted(by_type.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"- {k}: {v}")
        lines += ["", "## Top targets", ""]
        for target, count in sorted(
            by_target.items(), key=lambda kv: kv[1], reverse=True
        )[:20]:
            uid = len(ids_by_target.get(target, set()))
            lines.append(f"- `{target}`: {count} calls, {uid} unique IDs")
        lines += ["", "## Sink hints", ""]
        if by_sink:
            for sink, count in sorted(
                by_sink.items(), key=lambda kv: kv[1], reverse=True
            ):
                lines.append(f"- {sink}: {count}")
        else:
            lines.append("- none")
        lines += ["", "## Examples", ""]
        for c in calls[:50]:
            sinks = ",".join(c.sink_hints) if c.sink_hints else "none"
            lines.append(
                f"- `{c.file}:{c.line}` {c.binding_type} `{c.target}` id={c.id_hex or 'unknown'} result={c.result_register or 'n/a'} sinks={sinks}"
            )
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "files_scanned": len(files),
                "binding_calls": len(calls),
                "out": str(args.out),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
