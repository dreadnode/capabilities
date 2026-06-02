#!/usr/bin/env python3
"""XOR brute-force decoder — single-byte and multi-byte key recovery.

Usage:
    python xor_brute.py <file> [--key-len N] [--known-plaintext TEXT] [--top N]

Single-byte mode (default):
    Tries all 256 single-byte keys, scores each by printable-ASCII ratio.

Multi-byte mode (--key-len N):
    Uses frequency analysis per key-byte position assuming English/ASCII plaintext.

Known-plaintext mode (--known-plaintext TEXT):
    If you know part of the plaintext (e.g., "MZ", "HTTP", "<?xml"), recovers
    the key bytes at offset 0 and extends via frequency analysis.
"""

from __future__ import annotations

import argparse
import string
import sys
from pathlib import Path

PRINTABLE = set(string.printable.encode("ascii"))


def score_printable(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII."""
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE) / len(data)


def score_english(data: bytes) -> float:
    """Rough English-text score: printable ratio + letter frequency bonus."""
    if not data:
        return 0.0
    printable_ratio = score_printable(data)
    # Bonus for common English letters
    freq_chars = set(b"etaoinshrdlu ETAOINSHRDLU")
    freq_ratio = sum(1 for b in data if b in freq_chars) / len(data)
    return printable_ratio * 0.6 + freq_ratio * 0.4


def xor_single_byte(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_multi_byte(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(data[i] ^ key[i % klen] for i in range(len(data)))


def brute_single(data: bytes, top_n: int = 5) -> list[tuple[int, float, bytes]]:
    """Try all 256 single-byte XOR keys, return top N by score."""
    results = []
    for key in range(256):
        decoded = xor_single_byte(data, key)
        results.append((key, score_printable(decoded), decoded))
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:top_n]


def brute_multi(data: bytes, key_len: int) -> tuple[bytes, bytes]:
    """Recover multi-byte XOR key via per-position frequency analysis."""
    key = bytearray(key_len)
    for pos in range(key_len):
        # Extract every key_len-th byte starting at pos
        stripe = bytes(data[i] for i in range(pos, len(data), key_len))
        best_key = 0
        best_score = -1.0
        for k in range(256):
            decoded_stripe = bytes(b ^ k for b in stripe)
            s = score_english(decoded_stripe)
            if s > best_score:
                best_score = s
                best_key = k
        key[pos] = best_key
    return bytes(key), xor_multi_byte(data, key)


def recover_from_known(data: bytes, known: bytes, offset: int = 0) -> bytes:
    """Recover key bytes from known plaintext at a given offset."""
    key_bytes = bytes(data[offset + i] ^ known[i] for i in range(len(known)))
    return key_bytes


def main():
    parser = argparse.ArgumentParser(description="XOR brute-force decoder")
    parser.add_argument("file", help="Input file (ciphertext)")
    parser.add_argument(
        "--key-len", type=int, default=1, help="Key length (default: 1 = single-byte)"
    )
    parser.add_argument(
        "--known-plaintext", type=str, default=None, help="Known plaintext at offset 0"
    )
    parser.add_argument(
        "--top", type=int, default=5, help="Show top N results (single-byte mode)"
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Write best decryption to file"
    )
    args = parser.parse_args()

    data = Path(args.file).read_bytes()
    print(f"[*] Loaded {len(data)} bytes from {args.file}")

    if args.known_plaintext:
        known = args.known_plaintext.encode()
        partial_key = recover_from_known(data, known)
        print(
            f"[+] Key bytes from known plaintext: {partial_key.hex()} ({partial_key!r})"
        )
        if args.key_len > len(partial_key):
            print(
                f"[*] Extending to full key length {args.key_len} via frequency analysis..."
            )
            full_key, decoded = brute_multi(data, args.key_len)
            # Override positions we know for certain
            full_key = bytearray(full_key)
            for i, b in enumerate(partial_key):
                full_key[i] = b
            full_key = bytes(full_key)
            decoded = xor_multi_byte(data, full_key)
        else:
            full_key = partial_key
            decoded = xor_multi_byte(
                data, full_key * ((len(data) // len(full_key)) + 1)
            )
        print(f"[+] Full key: {full_key.hex()} ({full_key!r})")
        print(f"[+] Decoded preview: {decoded[:200]!r}")
        best = decoded
    elif args.key_len == 1:
        results = brute_single(data, args.top)
        for key, score, decoded in results:
            preview = decoded[:80]
            print(
                f"  key=0x{key:02X} ({chr(key) if 32 <= key < 127 else '.'}) "
                f"score={score:.3f}  preview={preview!r}"
            )
        best = results[0][2]
    else:
        key, decoded = brute_multi(data, args.key_len)
        print(f"[+] Recovered key: {key.hex()} ({key!r})")
        print(f"[+] Decoded preview: {decoded[:200]!r}")
        best = decoded

    if args.output:
        Path(args.output).write_bytes(best)
        print(f"[+] Written {len(best)} bytes to {args.output}")


if __name__ == "__main__":
    main()
