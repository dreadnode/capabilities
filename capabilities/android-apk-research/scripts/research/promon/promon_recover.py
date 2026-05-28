#!/usr/bin/env python3
"""Run the static Promon Shield coverage-restoration workflow.

This wrapper orchestrates the implemented static stages:
  1. protector_detect.py -> protector.json
  2. optional apktool decode -> smali-raw/
  3. promon_string_recover.py -> strings.jsonl + patched smali + summary
  4. promon_elf_triage.py -> native ELF profile outputs
  5. RECOVERY_SUMMARY.md roll-up

It is intentionally static. It does not bypass Promon, instrument a device, or
attempt native section decryption.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[1]
PROTECTOR_DETECT = SCRIPTS_ROOT / "protector_detect.py"
PROMON_STRING_RECOVER = SCRIPT_DIR / "promon_string_recover.py"
PROMON_ELF_TRIAGE = SCRIPT_DIR / "promon_elf_triage.py"
PROMON_JAVA_TRIAGE = SCRIPT_DIR / "promon_java_triage.py"
PROMON_BINDING_TRIAGE = SCRIPT_DIR / "promon_binding_triage.py"


def run(
    cmd: list[str], *, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    )


def find_apktool(apktool_arg: str | None) -> str | None:
    if apktool_arg:
        return apktool_arg
    return shutil.which("apktool")


def run_apktool_decode(apktool: str, apk: Path, out_dir: Path, force: bool) -> bool:
    if out_dir.exists() and not force:
        print(f"apktool output exists, reusing: {out_dir}")
        return True
    if out_dir.exists() and force:
        shutil.rmtree(out_dir)
    proc = run([apktool, "d", "-f", str(apk), "-o", str(out_dir)], check=False)
    if proc.returncode != 0:
        print("apktool decode failed; continuing with native/protector outputs only")
        return False
    return True


def write_summary(
    out_dir: Path, input_path: Path, apktool_ran: bool, apktool_ok: bool
) -> None:
    protector = load_json(out_dir / "protector.json")
    elf_triage = load_json(out_dir / "elf-triage.json")
    java_triage = load_json(out_dir / "java-triage.json")
    binding_triage = load_json(out_dir / "promon-bindings.json")
    strings_count = count_jsonl(out_dir / "strings.jsonl")
    native_calls_count = count_jsonl(out_dir / "native-call-sites.jsonl")
    binding_count = count_jsonl(out_dir / "promon-bindings.jsonl")
    syscall_count = count_jsonl(out_dir / "syscall-sites.jsonl")
    section_count = count_jsonl(out_dir / "elf-sections.jsonl")
    libs = elf_triage.get("libraries", [])

    lines = [
        "# Promon static recovery summary",
        "",
        f"Input: `{input_path}`",
        "",
        "## Stage status",
        "",
        f"- Protector detection: {'ok' if protector else 'missing'}",
        f"- apktool decode: {'skipped' if not apktool_ran else 'ok' if apktool_ok else 'failed'}",
        f"- Java/smali triage: {'ok' if java_triage else 'missing'}",
        f"- String recovery: {strings_count} strings recovered",
        f"- Native method callsites mapped: {native_calls_count}",
        f"- Promon binding callsites mapped: {binding_count}",
        f"- ELF triage: {len(libs)} candidate libraries triaged",
        f"- ELF sections recorded: {section_count}",
        f"- AArch64 syscall sites recorded: {syscall_count}",
        "",
    ]

    if protector:
        lines += [
            "## Protector routing",
            "",
            f"- Protector: `{protector.get('protector')}`",
            f"- Confidence: `{protector.get('confidence')}`",
            f"- Triage strategy: `{protector.get('triage_strategy')}`",
            "",
        ]
        notes = protector.get("notes") or []
        if notes:
            lines += ["Notes:", ""]
            lines += [f"- {n}" for n in notes]
            lines.append("")

    if libs:
        lines += ["## Native candidates", ""]
        for lib in libs:
            lines += [
                f"### `{lib.get('path')}`",
                "",
                f"- ABI: `{lib.get('abi') or 'n/a'}`",
                f"- SHA-256: `{lib.get('sha256')}`",
                f"- Machine: `{lib.get('machine')}` / `{lib.get('elf_class')}`",
                f"- Candidate reasons: {', '.join(lib.get('candidate_reasons') or []) or 'bare input'}",
                f"- Promon sections: {', '.join(lib.get('promon_sections') or []) or 'none'}",
                f"- Init array: {', '.join(hex(x) for x in lib.get('init_array') or []) or 'none'}",
                f"- RASP string terms: {', '.join(lib.get('rasp_string_terms') or []) or 'none'}",
                f"- Syscall sites: {lib.get('syscall_site_count')}",
                "",
            ]

    if java_triage:
        counters = java_triage.get("counters", {})
        native_calls = java_triage.get("native_call_sites", {})
        lines += [
            "## Java/smali triage",
            "",
            f"- Smali files scanned: {java_triage.get('files_scanned')}",
            f"- Framework hints: {java_triage.get('framework_hints')}",
            f"- `String.intern()` calls: {counters.get('string_intern', 0)}",
            f"- methods returning `(I)[C`: {counters.get('methods_returning_char_array_from_int', 0)}",
            f"- native String/int methods: {counters.get('native_string_int_methods', 0)}",
            f"- loadLibrary calls: {counters.get('load_library_calls', 0)}",
            f"- native method callsites: {native_calls.get('count', 0)}",
            "",
        ]
        top_targets = native_calls.get("by_target_top50", {})
        top_target_list = native_calls.get("by_target_top50_list") or [
            {"target": target, "count": count} for target, count in top_targets.items()
        ]
        if top_targets:
            lines += ["Top native call targets:", ""]
            for item in top_target_list[:10]:
                lines.append(f"- `{item['target']}`: {item['count']}")
            lines.append("")

    if binding_triage:
        lines += [
            "## Promon binding triage",
            "",
            f"- Binding callsites: {binding_triage.get('binding_calls')}",
            f"- By type: {binding_triage.get('by_type')}",
            f"- Sink hints: {binding_triage.get('by_sink_hint')}",
            "",
        ]
        top_targets = binding_triage.get("by_target_top20", {})
        if top_targets:
            lines += ["Top binding targets:", ""]
            for target, count in list(top_targets.items())[:10]:
                unique = (binding_triage.get("unique_ids_by_target") or {}).get(target)
                suffix = f", {unique} unique IDs" if unique is not None else ""
                lines.append(f"- `{target}`: {count}{suffix}")
            lines.append("")

    lines += [
        "## Artifacts",
        "",
        "- `protector.json`",
        "- `smali-raw/` when apktool decode succeeds",
        "- `strings.jsonl`",
        "- `java-triage.json`",
        "- `native-methods.jsonl`",
        "- `native-call-sites.jsonl`",
        "- `load-library-sites.jsonl`",
        "- `promon-java-summary.md`",
        "- `promon-bindings.jsonl`",
        "- `promon-bindings.json`",
        "- `promon-binding-summary.md`",
        "- `smali-strings-recovered/` when string recovery runs",
        "- `string-recovery-summary.md`",
        "- `elf-triage.json`",
        "- `elf-sections.jsonl`",
        "- `syscall-sites.jsonl`",
        "- `native-imports.txt`",
        "- `promon-elf-summary.md`",
        "- `libs/<abi>/<candidate>.so` for APK inputs with native candidates",
        "",
        "## Interpretation",
        "",
        "This is a static coverage-restoration pass. For Promon-protected APKs, use the union of manifest/JADX output, recovered strings, patched smali, and native ELF triage for vulnerability research. Native sections are not decrypted here; dynamic validation or native unpacking should be separate, explicitly authorized follow-up work.",
        "",
    ]
    (out_dir / "RECOVERY_SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input",
        type=Path,
        help="APK/XAPK, bare ELF .so, inventory dir, or apktool-decoded smali dir",
    )
    ap.add_argument(
        "-o", "--out-dir", type=Path, required=True, help="output directory"
    )
    ap.add_argument(
        "--apktool",
        default=None,
        help="apktool executable path/name (default: PATH lookup)",
    )
    ap.add_argument(
        "--skip-apktool",
        action="store_true",
        help="skip apktool decode/string recovery",
    )
    ap.add_argument("--skip-java", action="store_true", help="skip Java/smali triage")
    ap.add_argument(
        "--skip-bindings",
        action="store_true",
        help="skip Promon binding callsite triage",
    )
    ap.add_argument(
        "--skip-strings",
        action="store_true",
        help="skip string recovery even if smali exists",
    )
    ap.add_argument("--skip-elf", action="store_true", help="skip native ELF triage")
    ap.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing smali decode / patched smali outputs",
    )
    args = ap.parse_args()

    inp = args.input.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Stage 1: detector. It supports APK/XAPK and inventory dirs. Bare .so and
    # decoded smali dirs are outside its contract, so skip those gracefully.
    protector_path = out_dir / "protector.json"
    if inp.suffix.lower() in {".apk", ".xapk"} or inp.is_dir():
        # Avoid running detector on apktool decoded dirs without androguard.json.
        if inp.is_file() or (inp / "androguard.json").exists():
            run(
                [
                    sys.executable,
                    str(PROTECTOR_DETECT),
                    str(inp),
                    "-o",
                    str(protector_path),
                ]
            )
        else:
            print("detector skipped: directory is not an inventory artifact")
    else:
        print("detector skipped: input is not APK/XAPK/inventory")

    # Stage 2: apktool decode if input is an APK/XAPK.
    apktool_ran = False
    apktool_ok = False
    smali_raw = out_dir / "smali-raw"
    if not args.skip_apktool and inp.suffix.lower() in {".apk", ".xapk"}:
        apktool_ran = True
        apktool = find_apktool(args.apktool)
        if apktool is None:
            print("apktool not found; skipping smali decode/string recovery")
        else:
            apktool_ok = run_apktool_decode(apktool, inp, smali_raw, args.force)
    elif inp.is_dir() and any(inp.rglob("*.smali")):
        smali_raw = inp
        apktool_ok = True

    has_smali = apktool_ok and smali_raw.exists() and any(smali_raw.rglob("*.smali"))

    # Stage 3a: Java/smali integration triage.
    if not args.skip_java and has_smali:
        run(
            [
                sys.executable,
                str(PROMON_JAVA_TRIAGE),
                str(smali_raw),
                "-o",
                str(out_dir / "java-triage.json"),
                "--native-methods-out",
                str(out_dir / "native-methods.jsonl"),
                "--native-calls-out",
                str(out_dir / "native-call-sites.jsonl"),
                "--load-sites-out",
                str(out_dir / "load-library-sites.jsonl"),
                "--summary",
                str(out_dir / "promon-java-summary.md"),
            ]
        )
    else:
        print("Java/smali triage skipped")

    # Stage 3b: Promon binding callsite triage. This maps native string and
    # class/field binding IDs even when plaintext recovery is not available.
    if not args.skip_bindings and has_smali:
        run(
            [
                sys.executable,
                str(PROMON_BINDING_TRIAGE),
                str(smali_raw),
                "-o",
                str(out_dir / "promon-bindings.jsonl"),
                "--json",
                str(out_dir / "promon-bindings.json"),
                "--summary",
                str(out_dir / "promon-binding-summary.md"),
            ]
        )
    else:
        print("Promon binding triage skipped")

    # Stage 3c: smali string recovery.
    if not args.skip_strings and has_smali:
        patched = out_dir / "smali-strings-recovered"
        if patched.exists() and args.force:
            shutil.rmtree(patched)
        run(
            [
                sys.executable,
                str(PROMON_STRING_RECOVER),
                str(smali_raw),
                "-o",
                str(out_dir / "strings.jsonl"),
                "--patched-out",
                str(patched),
                "--summary",
                str(out_dir / "string-recovery-summary.md"),
            ]
        )
    else:
        print("string recovery skipped")

    # Stage 4: native ELF triage. Accepts APK/XAPK and bare ELF .so. It also
    # tolerates non-Promon APKs by producing zero library records.
    protector = load_json(protector_path)
    if (
        protector
        and protector.get("protector") not in {"promon_shield", "unknown"}
        and inp.suffix.lower() in {".apk", ".xapk"}
    ):
        print(
            f"ELF triage skipped: detected protector is {protector.get('protector')}, not promon_shield"
        )
    elif not args.skip_elf and (
        inp.is_file()
        and (
            inp.suffix.lower() in {".apk", ".xapk", ".so"}
            or inp.read_bytes()[:4] == b"\x7fELF"
        )
    ):
        run([sys.executable, str(PROMON_ELF_TRIAGE), str(inp), "-o", str(out_dir)])
    else:
        print("ELF triage skipped")

    write_summary(out_dir, inp, apktool_ran, apktool_ok)
    print(f"wrote {out_dir / 'RECOVERY_SUMMARY.md'}")


if __name__ == "__main__":
    main()
