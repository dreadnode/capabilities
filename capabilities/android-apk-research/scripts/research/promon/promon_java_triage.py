#!/usr/bin/env python3
"""Java/smali-side triage for Promon-protected APKs.

Input is an apktool-decoded smali directory (or one .smali file). The goal is
not deobfuscation; it is to map how Java code interacts with native code and
whether Promon-style string/class binding appears to be present.

Outputs:
  - java-triage.json: aggregate counters and examples
  - native-methods.jsonl: native declarations
  - native-call-sites.jsonl: calls into declared native methods
  - load-library-sites.jsonl: System.loadLibrary callsites + local context
  - promon-java-summary.md: human-readable summary
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CLASS_RE = re.compile(r"^\.class\s+(?P<flags>.*?)\s*(?P<class>L[^;]+;)")
SUPER_RE = re.compile(r"^\.super\s+(?P<super>L[^;]+;)")
METHOD_RE = re.compile(r"^\.method\s+(?P<decl>.+)$")
FIELD_RE = re.compile(r"^\.field\s+(?P<decl>.+)$")
INVOKE_RE = re.compile(
    r"^(?P<op>invoke-\S+)\s+\{(?P<regs>[^}]*)\},\s+(?P<target>\S+;->\S+)$"
)
CONST_STRING_RE = re.compile(
    r"^const-string(?:/jumbo)?\s+(?P<reg>[vp]\d+),\s+\"(?P<value>.*)\"$"
)
CONST_RE = re.compile(
    r"^const(?:/\S+)?\s+(?P<reg>[vp]\d+),\s+(?P<value>[-+]?0x[0-9a-fA-F]+|[-+]?\d+)"
)
NATIVE_DECL_RE = re.compile(r"(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<ret>\S+)$")

FRAMEWORK_HINTS = {
    "react_native": [
        "Lcom/facebook/react/",
        "Lcom/facebook/soloader/SoLoader;",
        "Lcom/facebook/hermes/",
        "libreactnativejni",
        "libjscexecutor",
    ],
    "flutter": ["Lio/flutter/", "libflutter.so", "FlutterActivity"],
    "cordova": ["Lorg/apache/cordova/", "CordovaActivity"],
    "webview": ["Landroid/webkit/WebView;", "WebViewClient", "addJavascriptInterface"],
    "xamarin": ["Lmono/", "libmonodroid", "Xamarin"],
}

STARTUP_CLASS_HINTS = (
    "Application;",
    "Activity;",
    "Service;",
    "BroadcastReceiver;",
    "ContentProvider;",
)


@dataclass
class MethodCtx:
    class_name: str | None
    method_decl: str | None
    method_name: str | None
    start_line: int
    access_flags: list[str] = field(default_factory=list)


@dataclass
class NativeMethod:
    file: str
    class_name: str | None
    method_name: str
    descriptor: str
    args: str
    ret: str
    flags: list[str]
    line: int
    namespace: str
    likely_role: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)

    @property
    def full_ref(self) -> str:
        return (
            f"{self.class_name}->{self.descriptor}"
            if self.class_name
            else self.descriptor
        )


@dataclass
class NativeCallSite:
    file: str
    class_name: str | None
    method_name: str | None
    line: int
    invoke: str
    target: str
    target_role: str
    target_namespace: str
    argument_registers: list[str]
    int_argument_hints: list[int]
    context: list[str]

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)


@dataclass
class LoadLibrarySite:
    file: str
    class_name: str | None
    method_name: str | None
    line: int
    invoke: str
    argument_registers: list[str]
    recovered_library: str | None
    recovery: str
    context: list[str]
    namespace: str
    startup_related: bool

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


def class_namespace(cls: str | None) -> str:
    if not cls:
        return "unknown"
    s = cls.strip("L;").replace("/", ".")
    parts = s.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else s


def likely_native_role(cls: str | None, method: str, ret: str, args: str) -> str:
    c = cls or ""
    if (
        c.startswith("Lcom/facebook/")
        or c.startswith("Lcom/google/")
        or c.startswith("Lokhttp")
        or c.startswith("Lokio")
    ):
        return "third_party_framework"
    if ret == "Ljava/lang/String;" and args in {"I", "II", "Ljava/lang/String;"}:
        return "possible_string_binding"
    if "Ljava/lang/Class;" in args or ret == "V" and "I" in args:
        return "possible_class_or_field_binding"
    if method.lower() in {"init", "initialize", "nativeinit", "register"}:
        return "possible_native_bootstrap"
    return "app_or_library_native"


def parse_method_decl(decl: str) -> tuple[list[str], str, str, str, str] | None:
    parts = decl.split()
    if not parts:
        return None
    sig = parts[-1]
    flags = parts[:-1]
    m = NATIVE_DECL_RE.match(sig)
    if not m:
        return None
    name = m.group("name")
    args = m.group("args")
    ret = m.group("ret")
    return flags, name, sig, args, ret


def previous_const_string(
    lines: list[str], idx: int, reg: str, max_back: int = 40
) -> tuple[str | None, str]:
    for j in range(idx - 1, max(-1, idx - max_back - 1), -1):
        s = lines[j].strip()
        m = CONST_STRING_RE.match(s)
        if m and m.group("reg") == reg:
            return m.group("value"), "const-string"
        # Common SoLoader pattern: const-string then invoke-static {vX}, SoLoader->loadLibrary
    return None, "unresolved"


def previous_const_int(
    lines: list[str], idx: int, reg: str, max_back: int = 20
) -> int | None:
    for j in range(idx - 1, max(-1, idx - max_back - 1), -1):
        s = lines[j].strip()
        m = CONST_RE.match(s)
        if m and m.group("reg") == reg:
            try:
                return int(m.group("value"), 0)
            except ValueError:
                return None
    return None


def find_method_at(lines: list[str], idx: int, cls: str | None) -> MethodCtx:
    for j in range(idx, -1, -1):
        s = lines[j].strip()
        if s == ".end method":
            return MethodCtx(cls, None, None, 0)
        m = METHOD_RE.match(s)
        if m:
            parsed = parse_method_decl(m.group("decl"))
            if parsed:
                flags, name, sig, _args, _ret = parsed
                return MethodCtx(cls, sig, name, j + 1, flags)
            return MethodCtx(cls, m.group("decl"), None, j + 1)
    return MethodCtx(cls, None, None, 0)


def context_window(lines: list[str], idx: int, radius: int = 8) -> list[str]:
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return [f"{i+1}: {lines[i]}" for i in range(start, end)]


def is_startup_related(
    cls: str | None, super_cls: str | None, method: str | None
) -> bool:
    text = " ".join(x or "" for x in [cls, super_cls, method])
    return any(h in text for h in STARTUP_CLASS_HINTS) or (
        method
        in {
            "<clinit>()V",
            "onCreate()V",
            "attachBaseContext(Landroid/content/Context;)V",
        }
    )


def scan_file(
    path: Path, root: Path
) -> tuple[list[NativeMethod], list[LoadLibrarySite], dict[str, Any]]:
    rel = str(path.relative_to(root))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cls = None
    super_cls = None
    class_flags: list[str] = []
    native_methods: list[NativeMethod] = []
    load_sites: list[LoadLibrarySite] = []
    counters = {
        "string_intern": 0,
        "new_array_char_files": 0,
        "methods_returning_char_array_from_int": 0,
        "native_string_int_methods": 0,
        "load_library_calls": 0,
        "so_loader_calls": 0,
        "framework_hits": {k: 0 for k in FRAMEWORK_HINTS},
    }
    full_text = "\n".join(lines)
    for fw, hints in FRAMEWORK_HINTS.items():
        counters["framework_hits"][fw] = sum(1 for h in hints if h in full_text)
    if "Ljava/lang/String;->intern()" in full_text:
        counters["string_intern"] = full_text.count("Ljava/lang/String;->intern()")
    if "new-array" in full_text and "[C" in full_text:
        counters["new_array_char_files"] = 1

    for i, raw in enumerate(lines):
        s = raw.strip()
        m = CLASS_RE.match(s)
        if m:
            cls = m.group("class")
            class_flags = m.group("flags").split()
            continue
        m = SUPER_RE.match(s)
        if m:
            super_cls = m.group("super")
            continue
        m = METHOD_RE.match(s)
        if m:
            parsed = parse_method_decl(m.group("decl"))
            if parsed:
                flags, name, sig, args, ret = parsed
                if "native" in flags:
                    role = likely_native_role(cls, name, ret, args)
                    native_methods.append(
                        NativeMethod(
                            file=rel,
                            class_name=cls,
                            method_name=name,
                            descriptor=sig,
                            args=args,
                            ret=ret,
                            flags=flags,
                            line=i + 1,
                            namespace=class_namespace(cls),
                            likely_role=role,
                        )
                    )
                    if ret == "Ljava/lang/String;" and args in {"I", "II"}:
                        counters["native_string_int_methods"] += 1
                if sig.endswith("(I)[C"):
                    counters["methods_returning_char_array_from_int"] += 1
            continue

        inv = INVOKE_RE.match(s)
        if not inv:
            continue
        target = inv.group("target")
        if (
            "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V" in target
            or "Lcom/facebook/soloader/SoLoader;->loadLibrary" in target
        ):
            regs = parse_regs(inv.group("regs"))
            arg_reg = regs[-1] if regs else None
            lib = None
            recovery = "unresolved"
            if arg_reg:
                lib, recovery = previous_const_string(lines, i, arg_reg)
            method_ctx = find_method_at(lines, i, cls)
            is_so_loader = "SoLoader;->loadLibrary" in target
            counters["load_library_calls"] += 1
            if is_so_loader:
                counters["so_loader_calls"] += 1
            load_sites.append(
                LoadLibrarySite(
                    file=rel,
                    class_name=cls,
                    method_name=method_ctx.method_name,
                    line=i + 1,
                    invoke=target,
                    argument_registers=regs,
                    recovered_library=lib,
                    recovery=recovery,
                    context=context_window(lines, i),
                    namespace=class_namespace(cls),
                    startup_related=is_startup_related(
                        cls, super_cls, method_ctx.method_name
                    ),
                )
            )
    return native_methods, load_sites, counters


def scan_native_calls(
    path: Path, root: Path, native_map: dict[str, NativeMethod]
) -> list[NativeCallSite]:
    rel = str(path.relative_to(root))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cls = None
    calls: list[NativeCallSite] = []
    for i, raw in enumerate(lines):
        s = raw.strip()
        m = CLASS_RE.match(s)
        if m:
            cls = m.group("class")
            continue
        inv = INVOKE_RE.match(s)
        if not inv:
            continue
        target = inv.group("target")
        native = native_map.get(target)
        if not native:
            continue
        regs = parse_regs(inv.group("regs"))
        int_hints = []
        for r in regs:
            v = previous_const_int(lines, i, r)
            if v is not None:
                int_hints.append(v)
        method_ctx = find_method_at(lines, i, cls)
        calls.append(
            NativeCallSite(
                file=rel,
                class_name=cls,
                method_name=method_ctx.method_name,
                line=i + 1,
                invoke=inv.group("op"),
                target=target,
                target_role=native.likely_role,
                target_namespace=native.namespace,
                argument_registers=regs,
                int_argument_hints=int_hints,
                context=context_window(lines, i),
            )
        )
    return calls


def merge_counters(total: dict[str, Any], add: dict[str, Any]) -> None:
    for k, v in add.items():
        if isinstance(v, dict):
            total.setdefault(k, {})
            for kk, vv in v.items():
                total[k][kk] = total[k].get(kk, 0) + vv
        else:
            total[k] = total.get(k, 0) + v


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input", type=Path, help="apktool-decoded smali directory or .smali file"
    )
    ap.add_argument(
        "-o", "--out", type=Path, required=True, help="aggregate JSON output path"
    )
    ap.add_argument(
        "--native-methods-out",
        type=Path,
        default=None,
        help="native methods JSONL path",
    )
    ap.add_argument(
        "--native-calls-out",
        type=Path,
        default=None,
        help="native callsites JSONL path",
    )
    ap.add_argument(
        "--load-sites-out", type=Path, default=None, help="loadLibrary sites JSONL path"
    )
    ap.add_argument("--summary", type=Path, default=None, help="markdown summary path")
    args = ap.parse_args()

    root = args.input.resolve()
    scan_root = root if root.is_dir() else root.parent
    files = smali_files(root)
    all_native: list[NativeMethod] = []
    all_loads: list[LoadLibrarySite] = []
    counters: dict[str, Any] = {}
    for f in files:
        native, loads, c = scan_file(f, scan_root)
        all_native.extend(native)
        all_loads.extend(loads)
        merge_counters(counters, c)

    native_map = {n.full_ref: n for n in all_native}
    all_native_calls: list[NativeCallSite] = []
    for f in files:
        all_native_calls.extend(scan_native_calls(f, scan_root, native_map))

    native_by_role: dict[str, int] = {}
    native_by_namespace: dict[str, int] = {}
    for n in all_native:
        native_by_role[n.likely_role] = native_by_role.get(n.likely_role, 0) + 1
        native_by_namespace[n.namespace] = native_by_namespace.get(n.namespace, 0) + 1

    load_libs: dict[str, int] = {}
    unresolved_loads = 0
    for site in all_loads:
        if site.recovered_library:
            load_libs[site.recovered_library] = (
                load_libs.get(site.recovered_library, 0) + 1
            )
        else:
            unresolved_loads += 1

    native_calls_by_target: dict[str, int] = {}
    native_calls_by_role: dict[str, int] = {}
    for call in all_native_calls:
        native_calls_by_target[call.target] = (
            native_calls_by_target.get(call.target, 0) + 1
        )
        native_calls_by_role[call.target_role] = (
            native_calls_by_role.get(call.target_role, 0) + 1
        )

    result = {
        "input": str(args.input),
        "files_scanned": len(files),
        "counters": counters,
        "native_methods": {
            "count": len(all_native),
            "by_role": native_by_role,
            "by_namespace_top20": dict(
                sorted(native_by_namespace.items(), key=lambda kv: kv[1], reverse=True)[
                    :20
                ]
            ),
            "examples": [n.__dict__ for n in all_native[:50]],
        },
        "native_call_sites": {
            "count": len(all_native_calls),
            "by_role": native_calls_by_role,
            "by_target_top50": dict(
                sorted(
                    native_calls_by_target.items(), key=lambda kv: kv[1], reverse=True
                )[:50]
            ),
            "by_target_top50_list": [
                {"target": target, "count": count}
                for target, count in sorted(
                    native_calls_by_target.items(), key=lambda kv: kv[1], reverse=True
                )[:50]
            ],
            "examples": [c.__dict__ for c in all_native_calls[:50]],
        },
        "load_library_sites": {
            "count": len(all_loads),
            "recovered_libraries": load_libs,
            "unresolved": unresolved_loads,
            "examples": [s.__dict__ for s in all_loads[:50]],
        },
        "framework_hints": counters.get("framework_hits", {}),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    native_out = args.native_methods_out or args.out.with_name("native-methods.jsonl")
    native_out.parent.mkdir(parents=True, exist_ok=True)
    native_out.write_text(
        "\n".join(n.to_json() for n in all_native) + ("\n" if all_native else ""),
        encoding="utf-8",
    )

    native_calls_out = args.native_calls_out or args.out.with_name(
        "native-call-sites.jsonl"
    )
    native_calls_out.parent.mkdir(parents=True, exist_ok=True)
    native_calls_out.write_text(
        "\n".join(c.to_json() for c in all_native_calls)
        + ("\n" if all_native_calls else ""),
        encoding="utf-8",
    )

    load_out = args.load_sites_out or args.out.with_name("load-library-sites.jsonl")
    load_out.parent.mkdir(parents=True, exist_ok=True)
    load_out.write_text(
        "\n".join(s.to_json() for s in all_loads) + ("\n" if all_loads else ""),
        encoding="utf-8",
    )

    if args.summary:
        lines = [
            "# Promon Java/smali triage summary",
            "",
            f"Input: `{args.input}`",
            f"Smali files scanned: {len(files)}",
            "",
            "## Coverage hints",
            "",
            f"- `String.intern()` calls: {counters.get('string_intern', 0)}",
            f"- files with `new-array [C`: {counters.get('new_array_char_files', 0)}",
            f"- methods returning `(I)[C`: {counters.get('methods_returning_char_array_from_int', 0)}",
            f"- native String/int methods: {counters.get('native_string_int_methods', 0)}",
            f"- native method callsites: {len(all_native_calls)}",
            f"- loadLibrary calls: {counters.get('load_library_calls', 0)}",
            f"- SoLoader loadLibrary calls: {counters.get('so_loader_calls', 0)}",
            "",
            "## Framework hints",
            "",
        ]
        for fw, count in sorted((counters.get("framework_hits") or {}).items()):
            lines.append(f"- {fw}: {count}")
        lines += ["", "## Native methods by role", ""]
        for role, count in sorted(
            native_by_role.items(), key=lambda kv: kv[1], reverse=True
        ):
            lines.append(f"- {role}: {count}")
        lines += ["", "## Native callsites by role", ""]
        for role, count in sorted(
            native_calls_by_role.items(), key=lambda kv: kv[1], reverse=True
        ):
            lines.append(f"- {role}: {count}")
        lines += ["", "## Top native call targets", ""]
        for target, count in sorted(
            native_calls_by_target.items(), key=lambda kv: kv[1], reverse=True
        )[:20]:
            lines.append(f"- `{target}`: {count}")
        lines += ["", "## Recovered load libraries", ""]
        if load_libs:
            for lib, count in sorted(
                load_libs.items(), key=lambda kv: kv[1], reverse=True
            ):
                lines.append(f"- `{lib}`: {count}")
        else:
            lines.append("- none")
        lines += ["", "## LoadLibrary examples", ""]
        for site in all_loads[:25]:
            lines.append(
                f"- `{site.file}:{site.line}` `{site.class_name or 'unknown'}` `{site.method_name or 'unknown'}` -> `{site.recovered_library or 'unresolved'}` via {site.recovery}"
            )
        lines += ["", "## Native method examples", ""]
        for n in all_native[:25]:
            lines.append(
                f"- `{n.file}:{n.line}` `{n.class_name}->{n.descriptor}` role={n.likely_role}"
            )
        lines += ["", "## Native callsite examples", ""]
        for c in all_native_calls[:25]:
            hints = (
                ", ".join(hex(x) for x in c.int_argument_hints)
                if c.int_argument_hints
                else "none"
            )
            lines.append(
                f"- `{c.file}:{c.line}` `{c.target}` role={c.target_role} int_hints={hints}"
            )
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "files_scanned": len(files),
                "native_methods": len(all_native),
                "native_call_sites": len(all_native_calls),
                "load_library_sites": len(all_loads),
                "out": str(args.out),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
