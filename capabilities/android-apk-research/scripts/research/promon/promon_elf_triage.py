#!/usr/bin/env python3
"""Static ELF triage for Promon Shield candidate native libraries.

Accepts either an APK/XAPK or a bare ELF shared object. For APKs, candidate
Promon libraries are selected using the same static indicators as the detector:
libshield.so, random-looking lib[a-z]{10,12}.so with Promon sections, or any ELF
with at least two of .ncu/.ncc/.ncd.

Outputs are intended for vuln-research coverage restoration, not bypassing:
  - elf-triage.json: aggregate library summaries
  - elf-sections.jsonl: section table with entropy samples
  - syscall-sites.jsonl: AArch64 SVC #0 sites and nearby syscall-number hints
  - native-imports.txt: visible dynamic imports / needed libraries
  - promon-elf-summary.md: human-readable summary
  - libs/<abi>/<name>.so: extracted candidate libraries when input is an APK
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

PROMON_SECTION_NAMES = (".ncu", ".ncc", ".ncd")
PROMON_RANDOM_LIB_PATTERN = re.compile(r"^lib[a-z]{10,12}\.so$")
RASP_TERMS = (
    b"frida",
    b"Frida",
    b"xposed",
    b"Xposed",
    b"substrate",
    b"Substrate",
    b"ptrace",
    b"TracerPid",
    b"/proc/self/maps",
    b"/proc/self/status",
    b"/proc/self/mounts",
    b"magisk",
    b"Magisk",
    b"/su",
    b"/system/xbin/su",
    b"base.apk",
    b"ro.kernel.qemu",
    b"ro.debuggable",
    b"ro.secure",
)
AARCH64_SVC0 = b"\x01\x00\x00\xd4"
AARCH64_RET = b"\xc0\x03\x5f\xd6"

AARCH64_SYSCALL_NAMES = {
    56: "openat",
    57: "close",
    63: "read",
    64: "write",
    93: "exit",
    94: "exit_group",
    129: "kill",
    134: "rt_sigaction",
    172: "getpid",
    178: "gettid",
    198: "socket",
    215: "munmap",
    220: "clone",
    221: "execve",
    222: "mmap",
    226: "mprotect",
    260: "wait4",
    270: "process_vm_readv",
    271: "process_vm_writev",
    101: "ptrace",
    167: "prctl",
}

ELF_MACHINES = {
    3: "x86",
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
}


@dataclass
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    entsize: int
    link: int
    info: int
    addralign: int
    entropy_sample: float


@dataclass
class Segment:
    index: int
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    align: int


@dataclass
class ElfInfo:
    path: str
    abi: str | None
    source: str
    size: int
    sha256: str
    elf_class: str
    endian: str
    machine: str
    machine_id: int
    entry: int
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    init_array: list[int] = field(default_factory=list)
    promon_sections: list[str] = field(default_factory=list)
    candidate_reasons: list[str] = field(default_factory=list)
    rasp_strings: dict[str, list[int]] = field(default_factory=dict)
    syscall_sites: list[dict[str, Any]] = field(default_factory=list)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            ent -= p * math.log2(p)
    return round(ent, 4)


def cstring(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end == -1:
        end = len(buf)
    return buf[off:end].decode("utf-8", errors="replace")


def read_cstrings(
    buf: bytes, min_len: int = 5, limit: int = 2000
) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(buf) and len(out) < limit:
        if 32 <= buf[i] <= 126:
            j = i
            while j < len(buf) and 32 <= buf[j] <= 126:
                j += 1
            if j - i >= min_len:
                out.append((i, buf[i:j].decode("ascii", errors="replace")))
            i = j + 1
        else:
            i += 1
    return out


class ElfParser:
    def __init__(self, blob: bytes):
        if len(blob) < 0x34 or blob[:4] != b"\x7fELF":
            raise ValueError("not an ELF")
        self.blob = blob
        self.elf_class_id = blob[4]
        self.endian_id = blob[5]
        if self.elf_class_id not in (1, 2) or self.endian_id not in (1, 2):
            raise ValueError("unsupported ELF class/endian")
        self.is64 = self.elf_class_id == 2
        self.endian = "<" if self.endian_id == 1 else ">"
        self.elf_class = "ELF64" if self.is64 else "ELF32"
        self.endian_name = "little" if self.endian == "<" else "big"
        self.machine_id = struct.unpack_from(self.endian + "H", blob, 0x12)[0]
        if self.is64:
            self.entry = struct.unpack_from(self.endian + "Q", blob, 0x18)[0]
            self.phoff = struct.unpack_from(self.endian + "Q", blob, 0x20)[0]
            self.shoff = struct.unpack_from(self.endian + "Q", blob, 0x28)[0]
            self.phentsize = struct.unpack_from(self.endian + "H", blob, 0x36)[0]
            self.phnum = struct.unpack_from(self.endian + "H", blob, 0x38)[0]
            self.shentsize = struct.unpack_from(self.endian + "H", blob, 0x3A)[0]
            self.shnum = struct.unpack_from(self.endian + "H", blob, 0x3C)[0]
            self.shstrndx = struct.unpack_from(self.endian + "H", blob, 0x3E)[0]
        else:
            self.entry = struct.unpack_from(self.endian + "I", blob, 0x18)[0]
            self.phoff = struct.unpack_from(self.endian + "I", blob, 0x1C)[0]
            self.shoff = struct.unpack_from(self.endian + "I", blob, 0x20)[0]
            self.phentsize = struct.unpack_from(self.endian + "H", blob, 0x2A)[0]
            self.phnum = struct.unpack_from(self.endian + "H", blob, 0x2C)[0]
            self.shentsize = struct.unpack_from(self.endian + "H", blob, 0x2E)[0]
            self.shnum = struct.unpack_from(self.endian + "H", blob, 0x30)[0]
            self.shstrndx = struct.unpack_from(self.endian + "H", blob, 0x32)[0]
        self.sections = self._parse_sections()
        self.segments = self._parse_segments()

    def _parse_sections(self) -> list[Section]:
        if (
            not self.shoff
            or not self.shentsize
            or not self.shnum
            or self.shstrndx >= self.shnum
        ):
            return []
        if self.shoff + self.shentsize * self.shnum > len(self.blob):
            return []
        raw = []
        if self.is64:
            fmt = self.endian + "IIQQQQIIQQ"
        else:
            fmt = self.endian + "10I"
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            fields = struct.unpack_from(fmt, self.blob, off)
            if self.is64:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                ) = fields
            else:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                ) = fields
            raw.append(
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                )
            )
        shstr = raw[self.shstrndx]
        shstr_off, shstr_size = shstr[4], shstr[5]
        if shstr_off + shstr_size > len(self.blob):
            return []
        shstrtab = self.blob[shstr_off : shstr_off + shstr_size]
        sections: list[Section] = []
        for idx, (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) in enumerate(raw):
            name = (
                cstring(shstrtab, sh_name)
                if sh_name < len(shstrtab)
                else f"<bad-name-{idx}>"
            )
            sample = b""
            if sh_size and sh_offset < len(self.blob):
                sample = self.blob[
                    sh_offset : min(len(self.blob), sh_offset + min(sh_size, 65536))
                ]
            sections.append(
                Section(
                    idx,
                    name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_entsize,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    entropy(sample),
                )
            )
        return sections

    def _parse_segments(self) -> list[Segment]:
        if not self.phoff or not self.phentsize or not self.phnum:
            return []
        if self.phoff + self.phentsize * self.phnum > len(self.blob):
            return []
        segs: list[Segment] = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if self.is64:
                p_type, p_flags = struct.unpack_from(self.endian + "II", self.blob, off)
                p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = (
                    struct.unpack_from(self.endian + "6Q", self.blob, off + 8)
                )
            else:
                (
                    p_type,
                    p_offset,
                    p_vaddr,
                    _p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                ) = struct.unpack_from(self.endian + "8I", self.blob, off)
            segs.append(
                Segment(
                    i, p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align
                )
            )
        return segs

    def section_by_name(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_data(self, s: Section) -> bytes:
        if not s.size or s.offset >= len(self.blob):
            return b""
        return self.blob[s.offset : min(len(self.blob), s.offset + s.size)]

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        for seg in self.segments:
            if seg.type != 1:  # PT_LOAD
                continue
            if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return seg.offset + (vaddr - seg.vaddr)
        for s in self.sections:
            if s.addr <= vaddr < s.addr + s.size:
                return s.offset + (vaddr - s.addr)
        return None

    def parse_dynamic(self) -> tuple[list[str], list[str]]:
        dyn = self.section_by_name(".dynamic")
        dynstr = self.section_by_name(".dynstr")
        dynsym = self.section_by_name(".dynsym")
        needed: list[str] = []
        imports: list[str] = []
        dynstr_data = self.section_data(dynstr) if dynstr else b""
        if dyn and dynstr_data:
            data = self.section_data(dyn)
            ent = 16 if self.is64 else 8
            for off in range(0, len(data) - ent + 1, ent):
                if self.is64:
                    tag, val = struct.unpack_from(self.endian + "qQ", data, off)
                else:
                    tag, val = struct.unpack_from(self.endian + "iI", data, off)
                if tag == 0:
                    break
                if tag == 1:  # DT_NEEDED
                    needed.append(cstring(dynstr_data, val))
        if dynsym and dynstr_data and dynsym.entsize:
            data = self.section_data(dynsym)
            for off in range(0, len(data) - dynsym.entsize + 1, dynsym.entsize):
                if self.is64:
                    st_name, st_info, _st_other, st_shndx, st_value, _st_size = (
                        struct.unpack_from(self.endian + "IBBHQQ", data, off)
                    )
                else:
                    st_name, st_value, _st_size, st_info, _st_other, st_shndx = (
                        struct.unpack_from(self.endian + "IIIBBH", data, off)
                    )
                if not st_name:
                    continue
                # Undefined symbols are imports.
                if st_shndx == 0:
                    name = cstring(dynstr_data, st_name)
                    if name:
                        imports.append(name)
        return sorted(set(needed)), sorted(set(imports))

    def parse_init_array(self) -> list[int]:
        s = self.section_by_name(".init_array")
        if not s:
            return []
        data = self.section_data(s)
        ptr_size = 8 if self.is64 else 4
        fmt = self.endian + ("Q" if self.is64 else "I")
        vals = []
        for off in range(0, len(data) - ptr_size + 1, ptr_size):
            val = struct.unpack_from(fmt, data, off)[0]
            if val:
                vals.append(val)
        return vals


def find_rasp_strings(blob: bytes) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    low = blob.lower()
    for term in RASP_TERMS:
        needle = term.lower()
        positions = []
        start = 0
        while True:
            idx = low.find(needle, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + 1
            if len(positions) >= 20:
                break
        if positions:
            hits[term.decode("utf-8", errors="replace")] = positions
    return hits


def decode_movz_w8(insn: int) -> int | None:
    # MOVZ Wd, #imm16, LSL #shift. We only need W8 syscall materialization.
    if (insn & 0x7F800000) != 0x52800000:
        return None
    rd = insn & 0x1F
    if rd != 8:
        return None
    hw = (insn >> 21) & 0x3
    imm16 = (insn >> 5) & 0xFFFF
    return imm16 << (16 * hw)


def decode_movn_w8(insn: int) -> int | None:
    if (insn & 0x7F800000) != 0x12800000:
        return None
    rd = insn & 0x1F
    if rd != 8:
        return None
    hw = (insn >> 21) & 0x3
    imm16 = (insn >> 5) & 0xFFFF
    val = ~(imm16 << (16 * hw)) & 0xFFFFFFFF
    return val


def find_aarch64_syscalls(parser: ElfParser, lib_path: str) -> list[dict[str, Any]]:
    if parser.machine_id != 183:
        return []
    sites: list[dict[str, Any]] = []
    executable_ranges: list[tuple[str, int, int, int]] = []
    for sec in parser.sections:
        # SHF_EXECINSTR catches normal .text and Promon's .ncc when the section
        # table is still meaningful.
        if sec.flags & 0x4:
            executable_ranges.append(
                (sec.name or f"section_{sec.index}", sec.offset, sec.size, sec.addr)
            )
    if not executable_ranges:
        # Some protected ELFs hide useful section flags. Fall back to executable
        # PT_LOAD segments so SVC sites are still visible in packed/protected
        # layouts.
        for seg in parser.segments:
            if seg.type == 1 and (seg.flags & 0x1):  # PT_LOAD + PF_X
                executable_ranges.append(
                    (f"PT_LOAD_{seg.index}", seg.offset, seg.filesz, seg.vaddr)
                )

    seen_offsets: set[int] = set()
    for name, file_offset, size, vaddr_base in executable_ranges:
        if not size or file_offset >= len(parser.blob):
            continue
        data = parser.blob[file_offset : min(len(parser.blob), file_offset + size)]
        start = 0
        while True:
            idx = data.find(AARCH64_SVC0, start)
            if idx == -1:
                break
            file_off = file_offset + idx
            if file_off in seen_offsets:
                start = idx + 4
                continue
            seen_offsets.add(file_off)
            vaddr = vaddr_base + idx
            syscall_no = None
            syscall_source = None
            # Look back up to 8 instructions for MOVZ/MOVN W8, #imm.
            for back in range(4, min(36, idx + 4), 4):
                insn = struct.unpack_from("<I", data, idx - back)[0]
                decoded = decode_movz_w8(insn)
                if decoded is None:
                    decoded = decode_movn_w8(insn)
                if decoded is not None:
                    syscall_no = decoded
                    syscall_source = {
                        "back_bytes": back,
                        "insn_file_offset": file_off - back,
                    }
                    break
            sites.append(
                {
                    "library": lib_path,
                    "section": name,
                    "file_offset": file_off,
                    "vaddr": vaddr,
                    "syscall_number_hint": syscall_no,
                    "syscall_name_hint": AARCH64_SYSCALL_NAMES.get(syscall_no)
                    if syscall_no is not None
                    else None,
                    "hint_source": syscall_source,
                }
            )
            start = idx + 4
    return sites


def abi_from_zip_path(path: str) -> str | None:
    if path.startswith("lib/"):
        parts = path.split("/", 2)
        if len(parts) >= 3:
            return parts[1]
    return None


def candidate_reasons(zip_path: str, parser: ElfParser) -> list[str]:
    base = zip_path.rsplit("/", 1)[-1]
    promon_sections = [
        s.name for s in parser.sections if s.name in PROMON_SECTION_NAMES
    ]
    reasons: list[str] = []
    if base == "libshield.so":
        reasons.append("libshield.so")
    if PROMON_RANDOM_LIB_PATTERN.match(base) and len(promon_sections) >= 2:
        reasons.append("random-libname-with-promon-sections")
    if len(promon_sections) >= 2:
        reasons.append("promon-section-pair")
    return reasons


def triage_blob(blob: bytes, source_path: str, abi: str | None, source: str) -> ElfInfo:
    parser = ElfParser(blob)
    needed, imports = parser.parse_dynamic()
    init_array = parser.parse_init_array()
    promon_sections = [
        s.name for s in parser.sections if s.name in PROMON_SECTION_NAMES
    ]
    info = ElfInfo(
        path=source_path,
        abi=abi,
        source=source,
        size=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(),
        elf_class=parser.elf_class,
        endian=parser.endian_name,
        machine=ELF_MACHINES.get(parser.machine_id, f"machine_{parser.machine_id}"),
        machine_id=parser.machine_id,
        entry=parser.entry,
        sections=parser.sections,
        segments=parser.segments,
        needed=needed,
        imported_symbols=imports,
        init_array=init_array,
        promon_sections=promon_sections,
        candidate_reasons=candidate_reasons(source_path, parser),
        rasp_strings=find_rasp_strings(blob),
        syscall_sites=find_aarch64_syscalls(parser, source_path),
    )
    return info


def info_summary(info: ElfInfo) -> dict[str, Any]:
    return {
        "path": info.path,
        "abi": info.abi,
        "source": info.source,
        "size": info.size,
        "sha256": info.sha256,
        "elf_class": info.elf_class,
        "endian": info.endian,
        "machine": info.machine,
        "machine_id": info.machine_id,
        "entry": info.entry,
        "section_count": len(info.sections),
        "segment_count": len(info.segments),
        "needed": info.needed,
        "imported_symbol_count": len(info.imported_symbols),
        "init_array": info.init_array,
        "promon_sections": info.promon_sections,
        "candidate_reasons": info.candidate_reasons,
        "rasp_string_terms": sorted(info.rasp_strings),
        "syscall_site_count": len(info.syscall_sites),
    }


def section_record(info: ElfInfo, s: Section) -> dict[str, Any]:
    return {
        "library": info.path,
        "abi": info.abi,
        "index": s.index,
        "name": s.name,
        "type": s.type,
        "flags": s.flags,
        "addr": s.addr,
        "offset": s.offset,
        "size": s.size,
        "entsize": s.entsize,
        "link": s.link,
        "info": s.info,
        "addralign": s.addralign,
        "entropy_sample": s.entropy_sample,
        "promon_section": s.name in PROMON_SECTION_NAMES,
    }


def collect_inputs(
    input_path: Path, out_dir: Path
) -> list[tuple[str, str | None, bytes, str]]:
    entries: list[tuple[str, str | None, bytes, str]] = []
    suffix = input_path.suffix.lower()
    if suffix in {".apk", ".xapk"}:
        with zipfile.ZipFile(input_path) as z:
            for name in z.namelist():
                if not (name.startswith("lib/") and name.endswith(".so")):
                    continue
                blob = z.read(name)
                if not blob.startswith(b"\x7fELF"):
                    continue
                try:
                    parser = ElfParser(blob)
                except ValueError:
                    continue
                reasons = candidate_reasons(name, parser)
                if not reasons:
                    continue
                abi = abi_from_zip_path(name)
                extract_path = (
                    out_dir / "libs" / (abi or "unknown") / name.rsplit("/", 1)[-1]
                )
                extract_path.parent.mkdir(parents=True, exist_ok=True)
                extract_path.write_bytes(blob)
                entries.append((name, abi, blob, f"apk:{input_path}"))
    else:
        blob = input_path.read_bytes()
        entries.append((input_path.name, None, blob, str(input_path)))
    return entries


def write_outputs(infos: list[ElfInfo], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    triage = {
        "library_count": len(infos),
        "libraries": [info_summary(i) for i in infos],
    }
    (out_dir / "elf-triage.json").write_text(
        json.dumps(triage, indent=2, sort_keys=True), encoding="utf-8"
    )

    with (out_dir / "elf-sections.jsonl").open("w", encoding="utf-8") as f:
        for info in infos:
            for s in info.sections:
                f.write(json.dumps(section_record(info, s), sort_keys=True) + "\n")

    with (out_dir / "syscall-sites.jsonl").open("w", encoding="utf-8") as f:
        for info in infos:
            for site in info.syscall_sites:
                f.write(json.dumps(site, sort_keys=True) + "\n")

    with (out_dir / "native-imports.txt").open("w", encoding="utf-8") as f:
        for info in infos:
            f.write(f"## {info.path}\n")
            if info.needed:
                f.write("NEEDED:\n")
                for n in info.needed:
                    f.write(f"  {n}\n")
            if info.imported_symbols:
                f.write("IMPORTS:\n")
                for sym in info.imported_symbols:
                    f.write(f"  {sym}\n")
            f.write("\n")

    lines = ["# Promon ELF triage summary", "", f"Libraries triaged: {len(infos)}", ""]
    for info in infos:
        lines += [
            f"## `{info.path}`",
            "",
            f"- ABI: `{info.abi or 'n/a'}`",
            f"- SHA-256: `{info.sha256}`",
            f"- Size: `{info.size}` bytes",
            f"- Machine: `{info.machine}` / {info.elf_class} / {info.endian}-endian",
            f"- Candidate reasons: {', '.join(info.candidate_reasons) if info.candidate_reasons else 'bare input'}",
            f"- Promon sections: {', '.join(info.promon_sections) if info.promon_sections else 'none'}",
            f"- Init array entries: {', '.join(hex(x) for x in info.init_array) if info.init_array else 'none'}",
            f"- Visible imports: {len(info.imported_symbols)} symbols; NEEDED: {', '.join(info.needed) if info.needed else 'none'}",
            f"- AArch64 SVC #0 sites: {len(info.syscall_sites)}",
            f"- RASP string terms: {', '.join(info.rasp_strings) if info.rasp_strings else 'none'}",
            "",
        ]
        promon_secs = [s for s in info.sections if s.name in PROMON_SECTION_NAMES]
        if promon_secs:
            lines += [
                "| Section | Offset | Size | Flags | Entropy sample |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
            for s in promon_secs:
                lines.append(
                    f"| `{s.name}` | `{s.offset:#x}` | {s.size} | `{s.flags:#x}` | {s.entropy_sample} |"
                )
            lines.append("")
        syscall_named = [s for s in info.syscall_sites if s.get("syscall_name_hint")]
        if syscall_named:
            lines += ["First syscall hints:", ""]
            for site in syscall_named[:20]:
                lines.append(
                    f"- `{site['section']}` `{site['file_offset']:#x}` -> {site['syscall_number_hint']} / {site['syscall_name_hint']}"
                )
            lines.append("")
    (out_dir / "promon-elf-summary.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("input", type=Path, help="APK/XAPK or bare ELF .so")
    ap.add_argument(
        "-o", "--out-dir", type=Path, required=True, help="output directory"
    )
    args = ap.parse_args()

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = collect_inputs(args.input, out_dir)
    infos: list[ElfInfo] = []
    for source_path, abi, blob, source in entries:
        try:
            infos.append(triage_blob(blob, source_path, abi, source))
        except ValueError as e:
            print(f"skip {source_path}: {e}")
    write_outputs(infos, out_dir)
    print(json.dumps({"libraries": len(infos), "out_dir": str(out_dir)}, indent=2))


if __name__ == "__main__":
    main()
