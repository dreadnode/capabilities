#!/usr/bin/env python3
"""Disassemble a raw shellcode blob with Capstone and identify interesting patterns.

Usage:
    python capstone_disasm.py <file> [--arch x86|x64|arm] [--base 0x0] [--find-xor] [--find-strings]

Features:
    --find-xor      Highlight XOR instructions (potential decode loops)
    --find-strings   Identify push-constructed stack strings
    --find-api-hash  Flag constants that match known API hashes (ROR13)
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

try:
    from capstone import *
except ImportError:
    print("Error: capstone not installed. Run: pip install capstone", file=sys.stderr)
    sys.exit(1)

# Known ROR13 API hashes (Metasploit convention)
KNOWN_ROR13 = {
    0x0726774C: "LoadLibraryA",
    0x7C0DFCAA: "GetProcAddress",
    0x006B8029: "WinExec",
    0x0E8AFE98: "VirtualAlloc",
    0x56A2B5F0: "ExitProcess",
    0x5FC8D902: "WSAStartup",
    0x6737DBC2: "connect",
    0xE0DF0FEA: "WSASocketA",
    0x614D6E75: "InternetOpenA",
    0xA779563A: "InternetOpenUrlA",
    0xE553A458: "VirtualProtect",
    0x160D6838: "CreateThread",
    0x0E4D69F1: "CreateRemoteThread",
    0x91AFCA54: "VirtualAllocEx",
    0x3B2E55EB: "WriteProcessMemory",
    0xCC8E00F4: "WaitForSingleObject",
}


def get_cs(arch: str) -> Cs:
    arch_map = {
        "x86": (CS_ARCH_X86, CS_MODE_32),
        "x64": (CS_ARCH_X86, CS_MODE_64),
        "arm": (CS_ARCH_ARM, CS_MODE_ARM),
        "arm64": (CS_ARCH_ARM64, CS_MODE_ARM),
    }
    if arch not in arch_map:
        print(
            f"Unsupported arch: {arch}. Supported: {', '.join(arch_map)}",
            file=sys.stderr,
        )
        sys.exit(1)
    a, m = arch_map[arch]
    md = Cs(a, m)
    md.detail = True
    return md


def extract_push_immediates(instructions: list) -> list[tuple[int, list[int]]]:
    """Find sequences of push imm32 that likely construct stack strings."""
    sequences = []
    current = []
    current_start = 0

    for insn in instructions:
        if (
            insn.mnemonic == "push" and insn.operands and insn.operands[0].type == 2
        ):  # IMM
            val = insn.operands[0].imm & 0xFFFFFFFF
            if 0x20202020 <= val <= 0x7F7F7F7F or val < 0x100:  # likely ASCII
                if not current:
                    current_start = insn.address
                current.append(val)
                continue
        if len(current) >= 2:
            sequences.append((current_start, current))
        current = []

    if len(current) >= 2:
        sequences.append((current_start, current))

    return sequences


def decode_push_string(values: list[int]) -> str:
    raw = b""
    for val in reversed(values):
        raw += struct.pack("<I", val)
    return raw.rstrip(b"\x00").decode("ascii", errors="replace")


def main():
    parser = argparse.ArgumentParser(
        description="Shellcode disassembler with pattern detection"
    )
    parser.add_argument("file", help="Raw binary / shellcode file")
    parser.add_argument("--arch", default="x86", choices=["x86", "x64", "arm", "arm64"])
    parser.add_argument("--base", default="0x0", help="Base address (hex)")
    parser.add_argument(
        "--find-xor", action="store_true", help="Highlight XOR instructions"
    )
    parser.add_argument(
        "--find-strings", action="store_true", help="Find push-constructed strings"
    )
    parser.add_argument(
        "--find-api-hash", action="store_true", help="Flag known API hash constants"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Max instructions to disassemble (0=all)"
    )
    args = parser.parse_args()

    code = Path(args.file).read_bytes()
    base = int(args.base, 16)
    md = get_cs(args.arch)

    print(f"[*] Disassembling {len(code)} bytes ({args.arch}) at base 0x{base:x}\n")

    instructions = list(md.disasm(code, base))
    if args.limit:
        instructions = instructions[: args.limit]

    xor_sites = []
    api_hash_hits = []

    for insn in instructions:
        annotation = ""

        # XOR detection
        if args.find_xor and insn.mnemonic == "xor":
            ops = insn.operands
            # Skip self-XOR (register zeroing)
            if not (
                len(ops) == 2
                and ops[0].type == 1
                and ops[1].type == 1
                and ops[0].reg == ops[1].reg
            ):
                annotation = "  <<< XOR (potential decode)"
                xor_sites.append(insn.address)

        # API hash detection
        if args.find_api_hash:
            for op in insn.operands:
                if op.type == 2:  # IMM
                    val = op.imm & 0xFFFFFFFF
                    if val in KNOWN_ROR13:
                        annotation = f"  <<< API hash: {KNOWN_ROR13[val]}"
                        api_hash_hits.append((insn.address, val, KNOWN_ROR13[val]))

        # PEB access detection
        if insn.mnemonic in ("mov", "lea") and insn.op_str:
            if "fs:[0x30]" in insn.op_str or "gs:[0x60]" in insn.op_str:
                annotation = "  <<< PEB access (API resolution)"

        print(f"  0x{insn.address:08x}:  {insn.mnemonic:<8s} {insn.op_str}{annotation}")

    # Summary
    print(f"\n[*] {len(instructions)} instructions disassembled")

    if args.find_xor and xor_sites:
        print(f"\n[+] XOR sites ({len(xor_sites)}):")
        for addr in xor_sites:
            print(f"    0x{addr:08x}")

    if args.find_strings:
        sequences = extract_push_immediates(instructions)
        if sequences:
            print(f"\n[+] Push-constructed strings ({len(sequences)}):")
            for addr, values in sequences:
                s = decode_push_string(values)
                print(f'    0x{addr:08x}: "{s}"')

    if args.find_api_hash and api_hash_hits:
        print(f"\n[+] API hash matches ({len(api_hash_hits)}):")
        for addr, h, name in api_hash_hits:
            print(f"    0x{addr:08x}: 0x{h:08X} = {name}")


if __name__ == "__main__":
    main()
