#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Detect Android protectors (DexProtector and Promon Shield today).

Tier-1 of the protector-triage capability. Given an APK or an inventory
artifact tree produced by run_corpus_inventory, emit a normalized
`protector.json` summarizing protector signals and recommending a
triage strategy.

DexProtector signals (any one is enough; multiple raise confidence):
  - manifest <application android:name="Protected*"> -- the bootstrap
    class injected next to the original Application class
  - presence of libdpboot.so + libdexprotector.so (or libdexprotector_h.so)
    in any lib/<abi>/
  - `DPLF` magic inside libdexprotector.so (start of the packed payload
    in modern versions) OR a last PT_LOAD whose contents start with DPLF
  - the protected-asset filenames the post calls out by name:
        se.dat, classes.dex.dat, mm.dat, dp.mp3, resources.dat,
        ic.dat, ct.dat, rcdb.dat, dp.arm-*.so.dat

Promon Shield signals:
  - APKiD packer hit for "Promon Shield" on a native library
  - a native library named libshield.so or random-looking lib[a-z]{10,12}.so
    with Promon ELF sections
  - at least two of the ELF sections .ncu, .ncc, .ncd in the same library
  - historical encrypted config assets: config-encrypt.txt, mappings.bin, pbi.bin

This script is intentionally cheap: it never parses the manifest beyond
a string match and never executes any of the decoded payload. It's the
fast pre-filter before the heavier unpacker (dexprotector_unpack.py) runs.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROTECTED_ASSETS = (
    "se.dat",
    "classes.dex.dat",
    "mm.dat",
    "dp.mp3",
    "resources.dat",
    "ic.dat",
    "ct.dat",
    "rcdb.dat",
    "ict.dat",
)

NATIVE_LIB_NAMES = (
    "libdpboot.so",
    "libdexprotector.so",
    "libdexprotector_h.so",
    "libdp.so",
)

PROMON_HISTORICAL_ASSETS = ("config-encrypt.txt", "mappings.bin", "pbi.bin")
PROMON_SECTION_NAMES = (".ncu", ".ncc", ".ncd")
PROMON_RANDOM_LIB_PATTERN = re.compile(r"^lib[a-z]{10,12}\.so$")

# Permissive: matches "Protected", "ProtectedFoo", "ProtectedLiveNetTV", but
# not "Foo.Protected" lookalikes elsewhere in the manifest binary.
PROTECTED_BOOT_PATTERN = re.compile(rb"Protected[A-Za-z0-9_]*")


CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class ProtectorReport:
    target: str
    package: str | None = None
    is_apk: bool = False
    protector: str = "unknown"
    confidence: str = "none"
    signals: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
    triage_strategy: str = "default"
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=True)


def _find_dplf_in_so(blob: bytes) -> dict[str, Any] | None:
    if b"DPLF" not in blob:
        return None
    idx = blob.find(b"DPLF")
    info: dict[str, Any] = {"dplf_file_offset": idx, "size": len(blob)}
    if blob[:4] != b"\x7fELF":
        info["host"] = "non-elf"
        return info
    try:
        e_phoff = struct.unpack_from("<Q", blob, 0x20)[0]
        e_phnum = struct.unpack_from("<H", blob, 0x38)[0]
        e_phentsize = struct.unpack_from("<H", blob, 0x36)[0]
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, _ = struct.unpack_from("<II", blob, off)
            (
                p_offset,
                p_vaddr,
                _p_paddr,
                p_filesz,
                _p_memsz,
                _p_align,
            ) = struct.unpack_from("<6Q", blob, off + 8)
            if p_type == 1 and p_offset <= idx < p_offset + p_filesz:
                info["in_pt_load_index"] = i
                info["pt_load_offset"] = p_offset
                info["pt_load_size"] = p_filesz
                info["is_last_pt_load"] = i == e_phnum - 1 or all(
                    struct.unpack_from("<I", blob, e_phoff + j * e_phentsize)[0] != 1
                    for j in range(i + 1, e_phnum)
                )
                break
    except struct.error:
        info["host"] = "elf-truncated"
    return info


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if not c:
            continue
        p = c / length
        entropy -= p * __import__("math").log2(p)
    return round(entropy, 4)


def _parse_elf_sections(blob: bytes) -> dict[str, dict[str, Any]]:
    """Return ELF sections keyed by name for 32/64-bit little/big endian ELFs.

    This intentionally parses only the section table fields needed by the
    protector detector. It is safe for zipped APK bytes and never executes code.
    """
    if len(blob) < 0x34 or blob[:4] != b"\x7fELF":
        return {}
    elf_class = blob[4]
    endian_id = blob[5]
    if elf_class not in (1, 2) or endian_id not in (1, 2):
        return {}
    endian = "<" if endian_id == 1 else ">"
    try:
        if elf_class == 1:
            if len(blob) < 0x34:
                return {}
            e_shoff = struct.unpack_from(endian + "I", blob, 0x20)[0]
            e_shentsize = struct.unpack_from(endian + "H", blob, 0x2E)[0]
            e_shnum = struct.unpack_from(endian + "H", blob, 0x30)[0]
            e_shstrndx = struct.unpack_from(endian + "H", blob, 0x32)[0]
            fmt = endian + "10I"
        else:
            if len(blob) < 0x40:
                return {}
            e_shoff = struct.unpack_from(endian + "Q", blob, 0x28)[0]
            e_shentsize = struct.unpack_from(endian + "H", blob, 0x3A)[0]
            e_shnum = struct.unpack_from(endian + "H", blob, 0x3C)[0]
            e_shstrndx = struct.unpack_from(endian + "H", blob, 0x3E)[0]
            fmt = endian + "IIQQQQIIQQ"

        if not e_shoff or not e_shentsize or not e_shnum or e_shstrndx >= e_shnum:
            return {}
        if e_shoff + e_shentsize * e_shnum > len(blob):
            return {}

        raw_sections: list[tuple[int, int, int, int, int, int]] = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            fields = struct.unpack_from(fmt, blob, off)
            if elf_class == 1:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = fields[:6]
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = fields[:6]
            raw_sections.append(
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size)
            )

        shstr = raw_sections[e_shstrndx]
        shstr_off, shstr_size = shstr[4], shstr[5]
        if shstr_off + shstr_size > len(blob):
            return {}
        shstrtab = blob[shstr_off : shstr_off + shstr_size]

        sections: dict[str, dict[str, Any]] = {}
        for idx, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size) in enumerate(
            raw_sections
        ):
            if sh_name >= len(shstrtab):
                name = f"<bad-name-{idx}>"
            else:
                end = shstrtab.find(b"\x00", sh_name)
                if end == -1:
                    end = len(shstrtab)
                name = shstrtab[sh_name:end].decode("utf-8", errors="replace")
            sample = b""
            if sh_size and sh_offset < len(blob):
                sample = blob[
                    sh_offset : min(len(blob), sh_offset + min(sh_size, 65536))
                ]
            sections[name] = {
                "index": idx,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "entropy_sample": _shannon_entropy(sample),
            }
        return sections
    except (struct.error, OverflowError):
        return {}


def _promon_lib_name_kind(base: str) -> str | None:
    if base == "libshield.so":
        return "libshield"
    if base in NATIVE_LIB_NAMES:
        return None
    if PROMON_RANDOM_LIB_PATTERN.match(base):
        return "random_libname"
    return None


def _extract_apkid_packers(apkid_path: Path) -> dict[str, list[str]]:
    if not apkid_path.exists():
        return {}
    try:
        data = json.loads(apkid_path.read_text())
    except json.JSONDecodeError:
        return {}
    hits: dict[str, list[str]] = {}
    for f in data.get("result", {}).get("files", []):
        packers = f.get("matches", {}).get("packer", [])
        promon = [p for p in packers if "promon" in p.lower()]
        if not promon:
            continue
        filename = f.get("filename", "")
        rel = filename.split("!", 1)[-1] if "!" in filename else filename
        hits[rel] = promon
    return hits


def _merge_promon_apkid_hits(
    report: ProtectorReport, hits: dict[str, list[str]]
) -> None:
    if not hits:
        return
    report.signals["apkid_promon"] = hits
    libs = report.signals.setdefault("promon_native_libs", {})
    for rel in hits:
        if not rel.startswith("lib/"):
            continue
        parts = rel.split("/", 2)
        if len(parts) < 3:
            continue
        abi = parts[1]
        libs.setdefault(abi, [])
        if rel not in libs[abi]:
            libs[abi].append(rel)
    for abi, paths in list(libs.items()):
        libs[abi] = sorted(paths)


def _apply_dexprotector_report(report: ProtectorReport) -> None:
    libs = report.signals.get("native_libs", {})
    abis_present = sorted({n.split("/")[1] for ns in libs.values() for n in ns})
    report.artifacts["abis"] = abis_present
    report.artifacts["dexprotector_unpack_supported"] = "arm64-v8a" in abis_present
    report.triage_strategy = "protector_aware"
    report.notes += [
        "JADX output is incomplete: encrypted classes are loaded from assets/classes.dex.dat at runtime",
        "ripgrep/Semgrep on JADX sources will miss the protected first-party code",
        "asset-derived flows (config, certs, keystores) are encrypted on disk; trust JADX strings only for unencrypted classes",
        "if libdexprotector.so contains a DPLF payload in the arm64 build, scripts/dexprotector_unpack.py can recover libdp.so without an Android device",
        "frida hooks against libdp.so trigger the master-key corruption path described in the source post; static unpack avoids this",
    ]


def _apply_promon_report(report: ProtectorReport) -> None:
    libs = report.signals.get("promon_native_libs", {})
    abis_present = sorted(
        {
            p.split("/")[1]
            for paths in libs.values()
            for p in paths
            if p.startswith("lib/")
        }
    )
    report.artifacts["abis"] = abis_present
    report.artifacts["promon_recovery_supported"] = "research"
    report.artifacts["java_string_recovery_supported"] = True
    report.artifacts["static_native_unpack_supported"] = False
    report.triage_strategy = "protector_aware_native_rasp"
    report.notes += [
        "Promon Shield is primarily native RASP/app shielding: do not assume all first-party DEX is encrypted",
        "run normal manifest/JADX attack-surface analysis, but expect strings/class bindings and runtime policy to be hidden behind the shield",
        "first recovery milestone is smali string/constant recovery, followed by Java/native binding maps and native RASP triage",
        "dynamic validation may trigger anti-debug, anti-hook, root/emulator, repackaging, and shield self-integrity checks; establish a clean baseline before instrumentation",
    ]


def _choose_best_report(reports: list[ProtectorReport]) -> ProtectorReport:
    return max(reports, key=lambda r: CONFIDENCE_RANK[r.confidence])


def _merge_reports(
    best: ProtectorReport, reports: list[ProtectorReport], target: str
) -> ProtectorReport:
    for r in reports:
        if r is best:
            continue
        for k, v in r.signals.items():
            if k not in best.signals:
                best.signals[k] = v
            elif isinstance(v, dict) and isinstance(best.signals[k], dict):
                merged = dict(best.signals[k])
                for subk, subv in v.items():
                    if subk not in merged:
                        merged[subk] = subv
                    elif isinstance(subv, list) and isinstance(merged[subk], list):
                        merged[subk] = sorted(set(merged[subk] + subv))
                    elif isinstance(subv, dict) and isinstance(merged[subk], dict):
                        merged[subk] = {**merged[subk], **subv}
                    else:
                        merged[subk] = subv
                best.signals[k] = merged
            elif isinstance(v, list) and isinstance(best.signals[k], list):
                best.signals[k] = sorted(set(best.signals[k] + v))
    best.target = target
    return best


def _scan_apk(path: Path) -> ProtectorReport:
    report = ProtectorReport(target=str(path), is_apk=True)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()

        # manifest probe (do not parse binary AXML; just match string)
        try:
            am = z.read("AndroidManifest.xml")
        except KeyError:
            am = b""
        m = PROTECTED_BOOT_PATTERN.search(am)
        if m:
            report.signals["protected_application_class"] = m.group(0).decode(
                "ascii", errors="replace"
            )

        # native libs
        found_libs: dict[str, list[str]] = {}
        for n in names:
            if not n.startswith("lib/"):
                continue
            base = n.rsplit("/", 1)[-1]
            if base in NATIVE_LIB_NAMES:
                found_libs.setdefault(base, []).append(n)
        if found_libs:
            report.signals["native_libs"] = found_libs

        # assets
        protected_assets: list[str] = []
        for n in names:
            if not n.startswith("assets/"):
                continue
            base = n.rsplit("/", 1)[-1]
            if base in PROTECTED_ASSETS:
                protected_assets.append(n)
            elif base.startswith("dp.arm-") and base.endswith(".so.dat"):
                protected_assets.append(n)
        if protected_assets:
            report.signals["protected_assets"] = protected_assets

        # DPLF watermark scan inside libdexprotector.so (arm64 first, then any)
        dplf_info: dict[str, Any] = {}
        for abi_pref in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            n = f"lib/{abi_pref}/libdexprotector.so"
            if n in names:
                blob = z.read(n)
                info = _find_dplf_in_so(blob)
                if info:
                    dplf_info[abi_pref] = info
                    break
        if dplf_info:
            report.signals["dplf"] = dplf_info

        # Promon Shield: random/libshield native library plus protected ELF
        # sections. Scan all native libs because Promon often renames libshield.
        promon_libs: dict[str, list[str]] = {}
        promon_name_hints: dict[str, str] = {}
        promon_sections: dict[str, dict[str, Any]] = {}
        for n in names:
            if not (n.startswith("lib/") and n.endswith(".so")):
                continue
            base = n.rsplit("/", 1)[-1]
            name_kind = _promon_lib_name_kind(base)
            if name_kind:
                promon_name_hints[n] = name_kind
            # Section parsing is cheap enough for native libs and gives the
            # strongest Promon signal. Avoid reading non-candidates only if a
            # name hint is absent? No: APKiD has a section-only promon_a rule.
            blob = z.read(n)
            sections = _parse_elf_sections(blob)
            section_hits = {
                s: sections[s] for s in PROMON_SECTION_NAMES if s in sections
            }
            if section_hits:
                promon_sections[n] = section_hits
            # A random-looking lib[a-z]{10,12}.so name alone is too noisy in
            # modern APKs (e.g. React Native's libjscexecutor.so). Treat
            # libshield.so as a candidate by name, but require Promon section
            # pairs for random names.
            if name_kind == "libshield" or len(section_hits) >= 2:
                abi = n.split("/", 2)[1]
                promon_libs.setdefault(abi, []).append(n)
        if promon_libs:
            report.signals["promon_native_libs"] = {
                abi: sorted(paths) for abi, paths in promon_libs.items()
            }
        if promon_name_hints:
            candidate_paths = {p for paths in promon_libs.values() for p in paths}
            report.signals["promon_name_hints"] = {
                p: kind
                for p, kind in promon_name_hints.items()
                if p in candidate_paths or kind == "libshield"
            }
        if promon_sections:
            report.signals["promon_elf_sections"] = promon_sections

        promon_assets = []
        for n in names:
            if not n.startswith("assets/"):
                continue
            base = n.rsplit("/", 1)[-1]
            if base in PROMON_HISTORICAL_ASSETS:
                promon_assets.append(n)
        if promon_assets:
            report.signals["promon_assets"] = sorted(promon_assets)

    apkid_sidecar = path.with_suffix(".apkid.json")
    _merge_promon_apkid_hits(report, _extract_apkid_packers(apkid_sidecar))

    dex_score = sum(
        bool(report.signals.get(k))
        for k in (
            "protected_application_class",
            "native_libs",
            "protected_assets",
            "dplf",
        )
    )

    promon_section_pair = any(
        len(section_hits) >= 2
        for section_hits in report.signals.get("promon_elf_sections", {}).values()
    )
    promon_apkid = bool(report.signals.get("apkid_promon"))
    promon_has_lib = bool(report.signals.get("promon_native_libs"))
    promon_has_assets = bool(report.signals.get("promon_assets"))
    if promon_apkid or promon_section_pair:
        promon_confidence = "high"
    elif promon_has_lib and promon_has_assets:
        promon_confidence = "medium"
    elif promon_has_lib or promon_has_assets:
        promon_confidence = "low"
    else:
        promon_confidence = "none"

    dex_confidence = "none"
    if dex_score >= 3:
        dex_confidence = "high"
    elif dex_score >= 1:
        dex_confidence = "medium" if dex_score == 2 else "low"

    if CONFIDENCE_RANK[promon_confidence] > CONFIDENCE_RANK[dex_confidence]:
        report.protector = "promon_shield"
        report.confidence = promon_confidence
    elif dex_confidence != "none":
        report.protector = "dexprotector"
        report.confidence = dex_confidence

    if report.protector == "dexprotector":
        _apply_dexprotector_report(report)
    elif report.protector == "promon_shield":
        _apply_promon_report(report)

    return report


def _scan_inventory_dir(path: Path) -> ProtectorReport:
    """Use an existing run_corpus_inventory artifact directory.

    Expected layout:
        <dir>/androguard.json
        <dir>/inventory.json (optional)
    """
    androguard = path / "androguard.json"
    if not androguard.exists():
        raise SystemExit(f"no androguard.json under {path}")
    data = json.loads(androguard.read_text())
    report = ProtectorReport(target=str(path), is_apk=False)
    pkg = data.get("package")
    report.package = pkg
    app_class = data.get("application_class") or ""
    apkid_hits = _extract_apkid_packers(path / "apkid.json")
    promon_hits = {
        k: v for k, v in apkid_hits.items() if any("promon" in p.lower() for p in v)
    }
    _merge_promon_apkid_hits(report, promon_hits)
    inv = path / "inventory.json"
    if inv.exists():
        try:
            inv_data = json.loads(inv.read_text())
        except json.JSONDecodeError:
            inv_data = {}
        native_libs = inv_data.get("native_libs") or []
        promon_libs: dict[str, list[str]] = {}
        promon_name_hints: dict[str, str] = {}
        for n in native_libs:
            if not isinstance(n, str) or not n.startswith("lib/"):
                continue
            base = n.rsplit("/", 1)[-1]
            kind = _promon_lib_name_kind(base)
            if kind != "libshield" and n not in promon_hits:
                continue
            if kind:
                promon_name_hints[n] = kind
            abi = n.split("/", 2)[1]
            promon_libs.setdefault(abi, []).append(n)
        if promon_libs:
            libs = report.signals.setdefault("promon_native_libs", {})
            for abi, paths in promon_libs.items():
                libs.setdefault(abi, [])
                libs[abi] = sorted(set(libs[abi] + paths))
        if promon_name_hints:
            report.signals["promon_name_hints"] = promon_name_hints
    if "Protected" in app_class:
        report.signals["protected_application_class"] = app_class
    # androguard.json from the existing inventory should already list files.
    if promon_hits:
        report.protector = "promon_shield"
        report.confidence = "high"
        _apply_promon_report(report)
        report.notes.append(
            "inventory-only Promon scan used APKiD/native-lib metadata; re-run with the APK path for ELF section entropy and asset evidence"
        )
    elif app_class and "Protected" in app_class:
        report.protector = "dexprotector"
        report.confidence = "low"
        report.notes.append(
            "inventory-only scan; re-run with the APK path for native-lib / DPLF / asset evidence"
        )
        _apply_dexprotector_report(report)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input",
        type=Path,
        help="APK or directory produced by run_corpus_inventory (apks/<sha>/)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="path to write protector.json (default: alongside input)",
    )
    args = ap.parse_args()

    if args.input.is_dir():
        report = _scan_inventory_dir(args.input)
        default_out = args.input / "protector.json"
    elif args.input.suffix.lower() in {".apk", ".xapk"}:
        if args.input.suffix.lower() == ".xapk":
            # XAPK: scan every embedded APK and merge signals
            reports: list[ProtectorReport] = []
            tmpdir = args.input.with_suffix(".__xapk")
            tmpdir.mkdir(exist_ok=True)
            with zipfile.ZipFile(args.input) as z:
                for n in z.namelist():
                    if not n.lower().endswith(".apk"):
                        continue
                    blob = z.read(n)
                    tmp = tmpdir / n.replace("/", "_")
                    tmp.write_bytes(blob)
                    reports.append(_scan_apk(tmp))
                    tmp.unlink()
            tmpdir.rmdir()
            if not reports:
                raise SystemExit("no APKs inside XAPK")
            report = _merge_reports(
                _choose_best_report(reports), reports, str(args.input)
            )
        else:
            report = _scan_apk(args.input)
        default_out = args.input.with_suffix(".protector.json")
    else:
        raise SystemExit("input must be an APK/XAPK or inventory directory")

    out = args.output or default_out
    out.write_text(report.to_json())
    print(report.to_json())


if __name__ == "__main__":
    main()
