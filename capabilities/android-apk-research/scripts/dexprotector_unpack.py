#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["unicorn>=2.1.0", "capstone>=5.0"]
# ///
"""DexProtector libdexprotector.so -> libdp.so static unpacker.

Reproduces the public research in https://www.romainthomas.fr/post/26-01-dexprotector/
without requiring a running Android device.

Tier-2 capability: given a DexProtector-protected APK (or a bare
`libdexprotector.so`), recover the plain libdp.so. Subsequent steps
(master-key derivation, asset decryption, classes.dex.dat unpack) need
further RE on the recovered libdp.so and live in companion scripts.

Approach (validated on com.playnet.androidtv.ads 5.0.1 / arm64-v8a):

1. Map libdexprotector.so into Unicorn. Stub the linker (FUN_001021a0
   returns a fake r_debug whose r_brk points at a synthesized
   rtld_db_dlactivity = single `ret`). Stub Linux syscalls so mmap
   returns our preallocated image buffer and mprotect/memcpy/munmap
   succeed cleanly.
2. Call FUN_0010114c(payload+4, payload_size-4, &segtable). It
   internally runs:
     - the obfuscated 16 KB-bytecode VM at FUN_00100790 -> 32-byte key
       (key bytes 0/4/8/12 are XORed with the first 4 bytes of
       rtld_db_dlactivity, which is the frida-server-persistence check
       described in the post)
     - a counter-mode-style Feistel cipher (FUN_00100c2c) to decrypt
       the 0x24-byte super-header and each segment's dynamic-tag table
     - LZ4 block decompression (FUN_00101b58) of each segment
3. Read the populated segment table to learn {vaddr, size, flags} per
   PT_LOAD, slice the image buffer, and emit a valid AArch64 ET_DYN ELF.

ARM64 is the only target wired today; armeabi-v7a / x86 / x86_64
variants of libdexprotector.so use the same layout but different
function addresses. Adding those is a small port (re-derive
FUN_001021a0 / FUN_00100790 / FUN_0010114c offsets via the DPLF
watermark and INIT_0 disassembly).
"""

from __future__ import annotations

import argparse
import io
import struct
import sys
import zipfile
from pathlib import Path

from unicorn import (
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_ARM,
    UC_PROT_ALL,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W8,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
)

# arm64 build offsets — verified against the LiveNet (com.playnet.androidtv.ads
# 5.0.1) and confirmed identical in Revolut 10.109 by DPLF watermark layout.
ARM64_OFFSETS = {
    "INIT_0": 0x29D4,
    "JNI_OnLoad": 0x2AB4,
    "FUN_resolve_dlactivity": 0x21A0,  # returns DAT_0010b698 (r_debug*)
    "FUN_KDF": 0x00790,  # writes 32-byte key into x0
    "FUN_cipher": 0x00C2C,  # Feistel keystream cipher
    "FUN_payload_header_decrypt": 0x114C,  # parses & expands the payload
    "FUN_lz4_decompress": 0x01B58,
    "PT_LOAD_payload_vaddr": 0xFAC0,  # where the encrypted blob lives
    "DPLF_magic_offset_in_payload": 0x0,
}

PAGE = 0x1000


def align_up(x: int, a: int = PAGE) -> int:
    return (x + a - 1) & ~(a - 1)


def open_libdexprotector(path: Path) -> bytes:
    """Accept either an APK or a bare libdexprotector.so."""
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        return data
    if data[:2] in (b"PK",):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for member in (
                "lib/arm64-v8a/libdexprotector.so",
                "lib/arm64-v8a/libdexprotector_h.so",
            ):
                if member in z.namelist():
                    return z.read(member)
            raise SystemExit(
                "no arm64-v8a libdexprotector.so found inside APK; this unpacker "
                "currently only handles the arm64 variant"
            )
    raise SystemExit("input is neither ELF nor APK")


def find_dplf_payload(lib: bytes) -> tuple[int, int]:
    """Return (file_offset, length) of the encrypted DPLF payload.

    The payload either starts with DPLF magic somewhere in the file, or it
    lives in the last PT_LOAD whose contents happen to start with DPLF.
    """
    idx = lib.find(b"DPLF")
    if idx < 0:
        raise SystemExit("no DPLF magic found in libdexprotector.so")

    e_phoff = struct.unpack_from("<Q", lib, 0x20)[0]
    e_phnum = struct.unpack_from("<H", lib, 0x38)[0]
    e_phentsize = struct.unpack_from("<H", lib, 0x36)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _p_flags = struct.unpack_from("<II", lib, off)
        p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
            "<6Q", lib, off + 8
        )
        if p_type == 1 and p_offset <= idx < p_offset + p_filesz:
            return p_offset, p_filesz
    return idx, len(lib) - idx


def map_lib(uc: Uc, lib: bytes, load_base: int) -> list[tuple[int, int]]:
    e_phoff = struct.unpack_from("<Q", lib, 0x20)[0]
    e_phnum = struct.unpack_from("<H", lib, 0x38)[0]
    mapped: list[tuple[int, int]] = []
    for i in range(e_phnum):
        off = e_phoff + i * 56
        p_type, _ = struct.unpack_from("<II", lib, off)
        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
            "<6Q", lib, off + 8
        )
        if p_type != 1:
            continue
        va = load_base + (p_vaddr & ~(PAGE - 1))
        end = load_base + align_up(p_vaddr + p_memsz)
        if not any(not (end <= a or va >= b) for a, b in mapped):
            uc.mem_map(va, end - va, UC_PROT_ALL)
            mapped.append((va, end))
        uc.mem_write(load_base + p_vaddr, lib[p_offset : p_offset + p_filesz])
    return mapped


def unpack_libdp(lib: bytes, *, verbose: bool = False) -> bytes:
    if lib[:4] != b"\x7fELF":
        raise SystemExit("not an ELF")

    payload_off, _payload_len = find_dplf_payload(lib)
    if verbose:
        print(f"[+] DPLF payload at file offset {payload_off:#x}")

    LOAD_BASE = 0x40000000
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    map_lib(uc, lib, LOAD_BASE)

    # Fake r_debug. FUN_resolve_dlactivity returns a pointer P such that
    # *(uintptr_t*)(P + 0x10) is the address of rtld_db_dlactivity. The first
    # 4 bytes there go straight into the round-key. We synthesize the
    # *unmodified* prologue (single `ret`) — frida-server's persistence
    # trampoline would corrupt these bytes, so emitting a clean `ret` gives us
    # the same key the real loader sees on a clean device.
    FAKE_RDEBUG = 0x30000000
    uc.mem_map(FAKE_RDEBUG, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    RTLD = FAKE_RDEBUG + 0x100
    uc.mem_write(RTLD, struct.pack("<I", 0xD65F03C0))  # ret
    uc.mem_write(FAKE_RDEBUG + 0x10, struct.pack("<Q", RTLD))

    # Destination image. The post says alloc_size is ~0x90000 for LiveNet and
    # similar for Revolut/Kaspersky; we over-provision and let the loader
    # pick the address via our mmap stub.
    IMG_BASE = 0x60000000
    IMG_SIZE = 0x200000  # 2 MB is plenty
    uc.mem_map(IMG_BASE, IMG_SIZE, UC_PROT_ALL)

    mmap_calls = [0]

    def hook_intr(uc, intno, ud):  # noqa: ARG001
        w8 = uc.reg_read(UC_ARM64_REG_W8)
        if w8 == 0xDE:  # mmap
            mmap_calls[0] += 1
            uc.reg_write(UC_ARM64_REG_X0, IMG_BASE + (mmap_calls[0] - 1) * 0x10000)
            return
        # mprotect/munmap/getrandom/etc — pretend success.
        uc.reg_write(UC_ARM64_REG_X0, 0)

    uc.hook_add(UC_HOOK_INTR, hook_intr)

    def hook_code(uc, address, size, ud):  # noqa: ARG001
        if address == LOAD_BASE + ARM64_OFFSETS["FUN_resolve_dlactivity"]:
            uc.reg_write(UC_ARM64_REG_X0, FAKE_RDEBUG)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_code)

    payload = lib[payload_off:]
    IN = 0x50000000
    uc.mem_map(IN, align_up(len(payload) + 0x1000), UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(IN, payload)

    SEGTABLE = 0x10000000
    uc.mem_map(SEGTABLE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    STACK = 0x20000000
    uc.mem_map(STACK, 0x100000, UC_PROT_READ | UC_PROT_WRITE)

    uc.reg_write(UC_ARM64_REG_X0, IN + 4)  # past DPLF magic
    uc.reg_write(UC_ARM64_REG_X1, len(payload) - 4)
    uc.reg_write(UC_ARM64_REG_X2, SEGTABLE)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x80000)
    SENTINEL = 0xDEAD0000
    uc.reg_write(UC_ARM64_REG_LR, SENTINEL)

    try:
        uc.emu_start(
            LOAD_BASE + ARM64_OFFSETS["FUN_payload_header_decrypt"],
            SENTINEL,
            count=500_000_000,
        )
    except Exception as exc:  # noqa: BLE001
        pc = uc.reg_read(UC_ARM64_REG_PC) - LOAD_BASE
        if verbose:
            print(f"[!] emu_start raised {exc!r} at pc={pc:#x} (often benign tail)")

    ret = uc.reg_read(UC_ARM64_REG_X0)
    if verbose:
        print(f"[+] payload header decrypt returned {ret:#x}")
    if ret != 1:
        raise SystemExit("payload header decrypt failed (ret != 1)")

    seg = bytes(uc.mem_read(SEGTABLE, 0x100))
    fields = struct.unpack("<" + "Q" * (0x100 // 8), seg)
    if verbose:
        for i, v in enumerate(fields):
            print(f"    segtable[{i:2d}] = {v:#x}")

    img = bytes(uc.mem_read(IMG_BASE, IMG_SIZE))

    segs: list[tuple[int, int, int]] = []
    for i in range(4):
        base_i = 6 + i * 3
        if base_i + 2 >= len(fields):
            break
        addr, size, flags = fields[base_i : base_i + 3]
        if addr == 0 or size == 0:
            break
        segs.append((addr - IMG_BASE, size, flags))
    if not segs:
        raise SystemExit("no segments parsed; segment table may be invalid")

    return build_elf(img, segs)


def build_elf(img: bytes, segs: list[tuple[int, int, int]]) -> bytes:
    """Wrap the unpacked segments in a synthetic AArch64 ET_DYN ELF."""
    ehdr_size = 0x40
    phdr_size = 0x38

    elf = bytearray()
    elf += b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    elf += struct.pack("<HH", 3, 0xB7)  # ET_DYN, EM_AARCH64
    elf += struct.pack("<I", 1)
    elf += struct.pack("<Q", 0)
    elf += struct.pack("<Q", ehdr_size)
    elf += struct.pack("<Q", 0)
    elf += struct.pack("<I", 0)
    elf += struct.pack("<HHHHHH", ehdr_size, phdr_size, len(segs), 0, 0, 0)

    file_cursor = 0x1000
    seg_records: list[tuple[int, int, int, int]] = []
    for vaddr, size, flags in segs:
        seg_records.append((vaddr, file_cursor, size, flags))
        file_cursor = align_up(file_cursor + size)

    for vaddr, foff, size, flags in seg_records:
        elf += struct.pack(
            "<IIQQQQQQ", 1, flags, foff, vaddr, vaddr, size, size, 0x1000
        )

    elf += b"\x00" * (0x1000 - len(elf))
    for vaddr, foff, size, _flags in seg_records:
        while len(elf) < foff:
            elf += b"\x00"
        elf += img[vaddr : vaddr + size]
    return bytes(elf)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "input",
        type=Path,
        help="APK, XAPK, or bare libdexprotector.so (arm64-v8a only today)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("libdp.so"),
        help="output path (default: libdp.so)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    lib = open_libdexprotector(args.input)
    libdp = unpack_libdp(lib, verbose=args.verbose)
    args.output.write_bytes(libdp)
    print(f"wrote {args.output} ({len(libdp)} bytes)")


if __name__ == "__main__":
    main()
