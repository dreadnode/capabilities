#!/usr/bin/env python3
"""Recover Promon-style smali string constants without rebuilding an APK.

This is a research-pipeline friendly port of the public Promon string
recovery approach: scan apktool-decoded smali, evaluate narrow char-array
obfuscation patterns, emit JSONL evidence, and optionally write patched smali.

Supported first-pass patterns:
  1. Inline char-array construction followed by java.lang.String->intern().
  2. Helper methods returning [C from an int parameter, followed by call sites
     that pass an integer, create a String, then intern it.

The evaluator intentionally supports only simple integer/char operations seen in
Promon-protected apps. It does not execute arbitrary smali or Python generated
from smali.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REG = r"[vp]\d+"
INT_LIT_RE = re.compile(r"[-+]?((0x[0-9a-fA-F]+)|\d+)")
CLASS_RE = re.compile(r"^\.class\s+.*?\s+(L[^;]+;)")
METHOD_RE = re.compile(r"^\.method\s+.*?\s+([^\s]+)$")
INVOKE_RE = re.compile(r"^(invoke-\S+)\s+\{([^}]*)\},\s+(\S+;->\S+)$")


@dataclass
class Recovery:
    file: str
    class_name: str | None
    method_name: str | None
    start_line: int
    end_line: int
    pattern: str
    plaintext: str
    replacement_register: str | None
    confidence: str = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False, sort_keys=True)


@dataclass
class CharArrayHelper:
    file: str
    class_name: str
    method_name: str
    descriptor: str
    start_line: int
    end_line: int
    param_register: str
    lines: list[str]

    @property
    def full_ref(self) -> str:
        return f"{self.class_name}->{self.method_name}"


def parse_int(token: str) -> int | None:
    token = token.rstrip(",").strip()
    m = INT_LIT_RE.fullmatch(token)
    if not m:
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


def parse_register_list(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    # Minimal support for explicit register lists. Range invokes are uncommon in
    # the targeted string patterns; leave them unresolved for now.
    if ".." in text:
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def java_escape(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)[1:-1]


def read_smali(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def write_smali(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def find_class_name(lines: list[str]) -> str | None:
    for line in lines:
        m = CLASS_RE.match(line.strip())
        if m:
            return m.group(1)
    return None


def line_method_at(lines: list[str], idx: int) -> str | None:
    for j in range(idx, -1, -1):
        s = lines[j].strip()
        m = METHOD_RE.match(s)
        if m:
            return m.group(1)
        if s == ".end method":
            return None
    return None


def method_bounds_at(lines: list[str], idx: int) -> tuple[int, int] | None:
    start = None
    for j in range(idx, -1, -1):
        s = lines[j].strip()
        if METHOD_RE.match(s):
            start = j
            break
        if s == ".end method":
            return None
    if start is None:
        return None
    for j in range(idx, len(lines)):
        if lines[j].strip() == ".end method":
            return start, j
    return start, len(lines) - 1


def method_ranges(lines: list[str]) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    start = None
    name = None
    for i, line in enumerate(lines):
        s = line.strip()
        m = METHOD_RE.match(s)
        if m:
            start = i
            name = m.group(1)
        elif s == ".end method" and start is not None and name is not None:
            ranges.append((start, i, name))
            start = None
            name = None
    return ranges


def eval_char_array_lines(
    lines: list[str], param_value: int | None = None
) -> tuple[str | None, dict[str, Any]]:
    """Evaluate a narrow smali char-array string construction.

    Returns (plaintext, evidence). Supports const/new-array, xor/add/sub/rsub,
    int-to-char, aput-char, aget-char, move-result-object from String ctor, and
    return-object. If param_value is provided, p0/p1 are initialized with it so
    helper methods returning [C can be evaluated at call sites.
    """
    regs: dict[str, Any] = {}
    arrays: dict[str, list[Any]] = {}
    result: str | None = None
    returned_array: list[Any] | None = None
    ops_seen: list[str] = []
    if param_value is not None:
        regs["p0"] = param_value
        regs["p1"] = param_value

    def val(tok: str) -> Any:
        tok = tok.rstrip(",")
        if tok in regs:
            return regs[tok]
        lit = parse_int(tok)
        if lit is not None:
            return lit
        raise KeyError(tok)

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("."):
            continue
        parts = line.replace(",", "").split()
        if not parts:
            continue
        op = parts[0]
        try:
            if (
                op.startswith("const")
                and len(parts) >= 3
                and re.fullmatch(REG, parts[1])
            ):
                parsed = parse_int(parts[2])
                if parsed is not None:
                    regs[parts[1]] = parsed
                    ops_seen.append(op)
            elif op == "new-array" and len(parts) >= 4 and parts[3] == "[C":
                size = int(val(parts[2]))
                arrays[parts[1]] = [None] * size
                regs[parts[1]] = arrays[parts[1]]
                ops_seen.append(op)
            elif op == "xor-int/lit16" and len(parts) >= 4:
                regs[parts[1]] = int(val(parts[2])) ^ int(val(parts[3]))
                ops_seen.append(op)
            elif op == "xor-int" and len(parts) >= 4:
                regs[parts[1]] = int(val(parts[2])) ^ int(val(parts[3]))
                ops_seen.append(op)
            elif op in {"add-int", "add-int/2addr"}:
                if op == "add-int/2addr" and len(parts) >= 3:
                    regs[parts[1]] = int(val(parts[1])) + int(val(parts[2]))
                elif len(parts) >= 4:
                    regs[parts[1]] = int(val(parts[2])) + int(val(parts[3]))
                ops_seen.append(op)
            elif op.startswith("add-int/lit") and len(parts) >= 4:
                regs[parts[1]] = int(val(parts[2])) + int(val(parts[3]))
                ops_seen.append(op)
            elif op in {"sub-int", "sub-int/2addr"}:
                if op == "sub-int/2addr" and len(parts) >= 3:
                    regs[parts[1]] = int(val(parts[1])) - int(val(parts[2]))
                elif len(parts) >= 4:
                    regs[parts[1]] = int(val(parts[2])) - int(val(parts[3]))
                ops_seen.append(op)
            elif op.startswith("rsub-int") and len(parts) >= 4:
                regs[parts[1]] = int(val(parts[3])) - int(val(parts[2]))
                ops_seen.append(op)
            elif op == "int-to-char" and len(parts) >= 3:
                regs[parts[1]] = chr(int(val(parts[2])) & 0x10FFFF)
                ops_seen.append(op)
            elif op == "aput-char" and len(parts) >= 4:
                ch = val(parts[1])
                arr = regs.get(parts[2])
                idx = int(val(parts[3]))
                if isinstance(ch, int):
                    ch = chr(ch & 0x10FFFF)
                if isinstance(arr, list) and 0 <= idx < len(arr):
                    arr[idx] = ch
                ops_seen.append(op)
            elif op == "aget-char" and len(parts) >= 4:
                arr = regs.get(parts[2])
                idx = int(val(parts[3]))
                if isinstance(arr, list) and 0 <= idx < len(arr):
                    regs[parts[1]] = arr[idx]
                ops_seen.append(op)
            elif (
                op.startswith("invoke-direct")
                and "Ljava/lang/String;-><init>([C)V" in line
            ):
                m = INVOKE_RE.match(line)
                if not m:
                    continue
                regs_list = parse_register_list(m.group(2))
                if len(regs_list) >= 2 and isinstance(regs.get(regs_list[1]), list):
                    arr = regs[regs_list[1]]
                    if all(isinstance(c, str) for c in arr):
                        regs[regs_list[0]] = "".join(arr)
                ops_seen.append("String.<init>([C)")
            elif op == "move-result-object" and len(parts) >= 2:
                # If the previous invoke was String.intern(), the receiver is
                # already the string; the scan window resolves replacement via
                # the move-result register. Keep existing result if present.
                ops_seen.append(op)
            elif op == "return-object" and len(parts) >= 2:
                obj = regs.get(parts[1])
                if isinstance(obj, list) and all(isinstance(c, str) for c in obj):
                    returned_array = obj
                    result = "".join(obj)
                elif isinstance(obj, str):
                    result = obj
                ops_seen.append(op)
        except (KeyError, ValueError, TypeError, IndexError, OverflowError):
            continue

    if result is None:
        # Fallback: any completed char array in the window is a likely inline
        # string if String.intern() was seen by the caller.
        for arr in arrays.values():
            if arr and all(isinstance(c, str) for c in arr):
                result = "".join(arr)
                returned_array = arr
                break
    evidence = {
        "ops_seen": sorted(set(ops_seen)),
        "returned_array_len": len(returned_array or []),
    }
    return result, evidence


def collect_helpers(
    file_path: Path, root: Path, lines: list[str]
) -> dict[str, CharArrayHelper]:
    helpers: dict[str, CharArrayHelper] = {}
    cls = find_class_name(lines)
    if not cls:
        return helpers
    rel = str(file_path.relative_to(root))
    for start, end, method_name in method_ranges(lines):
        if not method_name.endswith("(I)[C"):
            continue
        window = lines[start : end + 1]
        if not any("new-array" in l and "[C" in l for l in window):
            continue
        # p0 for static methods, p1 for instance methods. Promon examples are
        # usually static, but keep both in evaluator.
        param_register = (
            "p0"
            if " static " in lines[start] or lines[start].startswith(".method static")
            else "p1"
        )
        helper = CharArrayHelper(
            file=rel,
            class_name=cls,
            method_name=method_name,
            descriptor=method_name,
            start_line=start + 1,
            end_line=end + 1,
            param_register=param_register,
            lines=window,
        )
        helpers[helper.full_ref] = helper
    return helpers


def find_inline_recoveries(
    file_path: Path, root: Path, lines: list[str]
) -> list[Recovery]:
    recs: list[Recovery] = []
    cls = find_class_name(lines)
    rel = str(file_path.relative_to(root))
    helper_ranges = [
        (s, e) for s, e, name in method_ranges(lines) if name.endswith("(I)[C")
    ]
    for i, line in enumerate(lines):
        if "Ljava/lang/String;->intern()" not in line:
            continue
        bounds = method_bounds_at(lines, i)
        if bounds is None:
            continue
        method_start, _method_end = bounds
        if any(s <= i <= e for s, e in helper_ranges):
            continue
        new_array_idx = i
        while new_array_idx > method_start and i - new_array_idx < 80:
            if "new-array" in lines[new_array_idx] and "[C" in lines[new_array_idx]:
                break
            new_array_idx -= 1
        if not ("new-array" in lines[new_array_idx] and "[C" in lines[new_array_idx]):
            continue
        # Include a few instructions before new-array so the size register's
        # const assignment is available to the evaluator.
        eval_start = max(method_start + 1, new_array_idx - 4)
        patch_start = new_array_idx
        if new_array_idx > method_start + 1 and lines[
            new_array_idx - 1
        ].strip().startswith("const"):
            patch_start = new_array_idx - 1
        move_result_idx = i
        for j in range(i + 1, min(len(lines), i + 4)):
            s = lines[j].strip().replace(",", "")
            parts = s.split()
            if len(parts) >= 2 and parts[0] == "move-result-object":
                move_result_idx = j
                break
        end = move_result_idx
        plaintext, evidence = eval_char_array_lines(lines[eval_start : end + 1])
        if plaintext is None:
            continue
        repl_reg = None
        for j in range(i + 1, min(len(lines), i + 4)):
            s = lines[j].strip().replace(",", "")
            parts = s.split()
            if len(parts) >= 2 and parts[0] == "move-result-object":
                repl_reg = parts[1]
                break
        recs.append(
            Recovery(
                file=rel,
                class_name=cls,
                method_name=line_method_at(lines, i),
                start_line=patch_start + 1,
                end_line=end + 1,
                pattern="inline_char_array_intern",
                plaintext=plaintext,
                replacement_register=repl_reg,
                confidence="high" if repl_reg else "medium",
                evidence=evidence,
            )
        )
    return recs


def find_helper_call_recoveries(
    file_path: Path,
    root: Path,
    lines: list[str],
    helpers: dict[str, CharArrayHelper],
) -> list[Recovery]:
    recs: list[Recovery] = []
    cls = find_class_name(lines)
    rel = str(file_path.relative_to(root))
    consts: dict[str, int] = {}
    pending_helper: tuple[CharArrayHelper, int, int] | None = None
    pending_string: tuple[str, int, int, str] | None = (
        None  # plaintext,start,end,helper_ref
    )

    for i, raw in enumerate(lines):
        line = raw.strip()
        parts = line.replace(",", "").split()
        if (
            parts
            and parts[0].startswith("const")
            and len(parts) >= 3
            and re.fullmatch(REG, parts[1])
        ):
            parsed = parse_int(parts[2])
            if parsed is not None:
                consts[parts[1]] = parsed
        m = INVOKE_RE.match(line)
        if m:
            regs = parse_register_list(m.group(2))
            target = m.group(3)
            helper = helpers.get(target)
            if helper and regs:
                arg_reg = regs[-1]
                if arg_reg in consts:
                    plaintext, evidence = eval_char_array_lines(
                        helper.lines, consts[arg_reg]
                    )
                    if plaintext is not None:
                        pending_helper = (helper, consts[arg_reg], i)
                        pending_string = (plaintext, i, i, helper.full_ref)
            elif "Ljava/lang/String;-><init>([C)V" in target and pending_string:
                pending_string = (
                    pending_string[0],
                    pending_string[1],
                    i,
                    pending_string[3],
                )
            elif "Ljava/lang/String;->intern()" in target and pending_string:
                move_result_idx = i
                repl_reg = None
                for j in range(i + 1, min(len(lines), i + 4)):
                    s = lines[j].strip().replace(",", "")
                    p = s.split()
                    if len(p) >= 2 and p[0] == "move-result-object":
                        repl_reg = p[1]
                        move_result_idx = j
                        break
                end = move_result_idx
                helper, arg_value, helper_call_line = (
                    pending_helper if pending_helper else (None, None, None)
                )  # type: ignore[misc]
                recs.append(
                    Recovery(
                        file=rel,
                        class_name=cls,
                        method_name=line_method_at(lines, i),
                        start_line=(pending_string[1] + 1),
                        end_line=end + 1,
                        pattern="helper_char_array_intern",
                        plaintext=pending_string[0],
                        replacement_register=repl_reg,
                        confidence="high" if repl_reg else "medium",
                        evidence={
                            "helper": pending_string[3],
                            "helper_file": helper.file if helper else None,
                            "helper_line": helper.start_line if helper else None,
                            "arg_value": arg_value,
                            "helper_call_line": (helper_call_line + 1)
                            if helper_call_line is not None
                            else None,
                        },
                    )
                )
                pending_helper = None
                pending_string = None
        if line.startswith(".end method"):
            consts = {}
            pending_helper = None
            pending_string = None
    return recs


def patch_lines(lines: list[str], recs: list[Recovery]) -> list[str]:
    patched = list(lines)
    for rec in sorted(
        [r for r in recs if r.replacement_register],
        key=lambda r: r.start_line,
        reverse=True,
    ):
        indent = ""
        if 0 <= rec.start_line - 1 < len(lines):
            indent = lines[rec.start_line - 1][
                : len(lines[rec.start_line - 1])
                - len(lines[rec.start_line - 1].lstrip())
            ]
        replacement = f'{indent}const-string {rec.replacement_register}, "{java_escape(rec.plaintext)}"'
        start = rec.start_line - 1
        end = rec.end_line
        patched[start:end] = [replacement]
    return patched


def iter_smali_files(root: Path) -> list[Path]:
    if root.is_file() and root.suffix == ".smali":
        return [root]
    return sorted(p for p in root.rglob("*.smali") if p.is_file())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input", type=Path, help="apktool-decoded directory or a .smali file"
    )
    ap.add_argument("-o", "--out", type=Path, required=True, help="JSONL output path")
    ap.add_argument(
        "--patched-out",
        type=Path,
        default=None,
        help="optional directory for patched smali tree",
    )
    ap.add_argument(
        "--summary", type=Path, default=None, help="optional markdown summary path"
    )
    args = ap.parse_args()

    root = args.input.resolve()
    files = iter_smali_files(root)
    all_lines: dict[Path, list[str]] = {}
    helpers: dict[str, CharArrayHelper] = {}
    for f in files:
        lines = read_smali(f)
        all_lines[f] = lines
        helpers.update(
            collect_helpers(f, root if root.is_dir() else root.parent, lines)
        )

    scan_root = root if root.is_dir() else root.parent
    recoveries: list[Recovery] = []
    by_file: dict[Path, list[Recovery]] = {}
    for f, lines in all_lines.items():
        recs = find_inline_recoveries(f, scan_root, lines)
        recs.extend(find_helper_call_recoveries(f, scan_root, lines, helpers))
        # Dedupe same line/plaintext/pattern in case an inline helper body is
        # also seen as a call-site pattern.
        seen: set[tuple[int, str, str]] = set()
        unique: list[Recovery] = []
        for r in recs:
            key = (r.start_line, r.pattern, r.plaintext)
            if key in seen:
                continue
            seen.add(key)
            unique.append(r)
        recoveries.extend(unique)
        if unique:
            by_file[f] = unique

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "\n".join(r.to_json() for r in recoveries) + ("\n" if recoveries else ""),
        encoding="utf-8",
    )

    if args.patched_out:
        out_root = args.patched_out
        if out_root.exists():
            shutil.rmtree(out_root)
        if root.is_dir():
            shutil.copytree(root, out_root)
            for f, recs in by_file.items():
                rel = f.relative_to(scan_root)
                write_smali(out_root / rel, patch_lines(all_lines[f], recs))
        else:
            out_root.mkdir(parents=True, exist_ok=True)
            out_file = out_root / root.name
            write_smali(out_file, patch_lines(all_lines[root], by_file.get(root, [])))

    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        top = sorted(recoveries, key=lambda r: (r.file, r.start_line))[:50]
        body = [
            "# Promon string recovery summary",
            "",
            f"Input: `{args.input}`",
            f"Smali files scanned: {len(files)}",
            f"Helpers discovered: {len(helpers)}",
            f"Strings recovered: {len(recoveries)}",
            "",
            "## First recovered strings",
            "",
        ]
        for r in top:
            body.append(f"- `{r.file}:{r.start_line}` `{r.pattern}` -> `{r.plaintext}`")
        args.summary.write_text("\n".join(body) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "files_scanned": len(files),
                "helpers": len(helpers),
                "strings_recovered": len(recoveries),
                "out": str(args.out),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
