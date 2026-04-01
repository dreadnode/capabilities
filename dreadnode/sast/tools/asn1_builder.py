"""ASN.1/DER structure builder for PoC inputs.

Builds ASN.1 DER-encoded binary files from a JSON tree description.
For general file construction library guidance, see the
file-construction-libraries skill.
"""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import Any

from dreadnode.agents.tools import Toolset, tool_method

# Tag class bits (bits 7-6)
_TAG_CLASSES: dict[str, int] = {
    "UNIVERSAL": 0x00,
    "APPLICATION": 0x40,
    "CONTEXT_SPECIFIC": 0x80,
    "PRIVATE": 0xC0,
}

# Universal tag numbers
_UNIVERSAL_TAGS: dict[str, int] = {
    "BOOLEAN": 0x01,
    "INTEGER": 0x02,
    "BIT_STRING": 0x03,
    "OCTET_STRING": 0x04,
    "NULL": 0x05,
    "OID": 0x06,
    "OBJECT_IDENTIFIER": 0x06,
    "ENUMERATED": 0x0A,
    "UTF8_STRING": 0x0C,
    "SEQUENCE": 0x10,
    "SET": 0x11,
    "PRINTABLE_STRING": 0x13,
    "IA5_STRING": 0x16,
    "UTC_TIME": 0x17,
    "GENERALIZED_TIME": 0x18,
    "VISIBLE_STRING": 0x1A,
    "GENERAL_STRING": 0x1B,
    "UNIVERSAL_STRING": 0x1C,
    "BMP_STRING": 0x1E,
}

# Tags that are constructed (contain children) by default
_CONSTRUCTED_TAGS: set[str] = {"SEQUENCE", "SET"}


def _encode_tag(
    tag_str: str,
    number: int | None,
    constructed: bool | None,  # noqa: FBT001
) -> bytes:
    """Encode an ASN.1 tag byte(s)."""
    tag_upper = tag_str.upper()

    if tag_upper in _TAG_CLASSES:
        # Context-specific, application, or private tag
        if number is None:
            msg = f"Tag class '{tag_str}' requires a 'number' field"
            raise ValueError(msg)
        class_bits = _TAG_CLASSES[tag_upper]
        is_constructed = constructed if constructed is not None else False
    elif tag_upper in _UNIVERSAL_TAGS:
        number = _UNIVERSAL_TAGS[tag_upper]
        class_bits = 0x00
        is_constructed = (
            constructed if constructed is not None else (tag_upper in _CONSTRUCTED_TAGS)
        )
    else:
        msg = (
            f"Unknown tag '{tag_str}'. "
            f"Use a universal type ({', '.join(sorted(_UNIVERSAL_TAGS))}) "
            f"or a class (CONTEXT_SPECIFIC, APPLICATION, PRIVATE) with 'number'."
        )
        raise ValueError(msg)

    constructed_bit = 0x20 if is_constructed else 0x00

    if number < 0x1F:
        return bytes([class_bits | constructed_bit | number])

    # Long-form tag encoding (tag number >= 31)
    tag_bytes = [class_bits | constructed_bit | 0x1F]
    # Encode tag number in base-128
    num_bytes: list[int] = []
    n = number
    while n > 0:
        num_bytes.append(n & 0x7F)
        n >>= 7
    num_bytes.reverse()
    for i, b in enumerate(num_bytes):
        if i < len(num_bytes) - 1:
            tag_bytes.append(b | 0x80)
        else:
            tag_bytes.append(b)
    return bytes(tag_bytes)


def _encode_length(length: int) -> bytes:
    """Encode an ASN.1 length using DER definite-length encoding."""
    if length < 0x80:
        return bytes([length])
    # Long form: first byte = 0x80 | number of length bytes
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _encode_value(tag_str: str, node: dict[str, Any]) -> bytes:  # noqa: PLR0911, PLR0912
    """Encode the value portion of a TLV based on tag type."""
    tag_upper = tag_str.upper()

    # Raw bytes override (for corruption / custom data)
    if "raw_hex" in node:
        raw_hex = node["raw_hex"]
        try:
            return binascii.unhexlify(raw_hex)
        except (ValueError, binascii.Error) as e:
            msg = f"raw_hex '{raw_hex}' is not valid hex ({e}). Provide an even-length hex string without 0x prefix."
            raise ValueError(msg) from e
    if "raw_bytes" in node:
        raw = node["raw_bytes"]
        if isinstance(raw, list):
            return bytes(raw)
        return raw.encode() if isinstance(raw, str) else bytes(raw)

    # Children (constructed types)
    children = node.get("children")
    if children is not None:
        return b"".join(_encode_node(child) for child in children)

    value = node.get("value")

    if tag_upper == "BOOLEAN":
        return b"\xff" if value else b"\x00"

    if tag_upper in ("INTEGER", "ENUMERATED"):
        if value is None:
            value = 0
        if isinstance(value, str):
            value = int(value, 0)
        # DER integer encoding: minimal two's complement
        if value == 0:
            return b"\x00"
        negative = value < 0
        if negative:
            # Two's complement for negative
            bit_len = (value.bit_length() + 8) & ~7  # round up to next byte
            value = (1 << bit_len) + value
        int_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
        # Ensure positive values with high bit set get a leading 0x00
        if not negative and int_bytes[0] & 0x80:
            int_bytes = b"\x00" + int_bytes
        return int_bytes

    if tag_upper == "NULL":
        return b""

    if tag_upper in ("OID", "OBJECT_IDENTIFIER"):
        if isinstance(value, str):
            return _encode_oid(value)
        return bytes(value) if isinstance(value, list) else b""

    if tag_upper in ("OCTET_STRING", "BIT_STRING"):
        if isinstance(value, str):
            # Treat as hex string (no 0x prefix). If odd length or invalid
            # hex chars, this is likely a typo — raise instead of silently
            # encoding as UTF-8 text. Use raw_bytes for non-hex data.
            try:
                return binascii.unhexlify(value)
            except (ValueError, binascii.Error) as e:
                msg = (
                    f"{tag_upper} value '{value}' is not valid hex ({e}). "
                    f"Provide an even-length hex string without 0x prefix "
                    f"(e.g. 'deadbeef'), or use raw_bytes for arbitrary data."
                )
                raise ValueError(msg) from e
        if isinstance(value, list):
            return bytes(value)
        return b""

    # String types
    if tag_upper in (
        "UTF8_STRING",
        "PRINTABLE_STRING",
        "IA5_STRING",
        "VISIBLE_STRING",
        "GENERAL_STRING",
    ):
        return str(value).encode("utf-8") if value is not None else b""

    if tag_upper in ("UTC_TIME", "GENERALIZED_TIME"):
        return str(value).encode("ascii") if value is not None else b""

    if tag_upper == "BMP_STRING":
        return str(value).encode("utf-16-be") if value is not None else b""

    if tag_upper == "UNIVERSAL_STRING":
        return str(value).encode("utf-32-be") if value is not None else b""

    # Default: if it has a value, encode it
    if value is not None:
        if isinstance(value, str):
            try:
                return binascii.unhexlify(value)
            except (ValueError, binascii.Error):
                return value.encode("utf-8")
        if isinstance(value, int):
            if value == 0:
                return b"\x00"
            return value.to_bytes((value.bit_length() + 7) // 8, "big")
        if isinstance(value, list):
            return bytes(value)

    return b""


def _encode_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string to DER value bytes."""
    components = [int(c) for c in oid_str.split(".")]
    if len(components) < 2:
        msg = f"OID must have at least 2 components: {oid_str}"
        raise ValueError(msg)
    # Basic sanity check: components must be non-negative
    for idx, comp in enumerate(components):
        if comp < 0:
            msg = f"OID components must be non-negative, got {comp} at position {idx} in {oid_str}"
            raise ValueError(msg)
    first, second = components[0], components[1]
    # ITU-T X.690: first component must be 0, 1, or 2
    if first not in (0, 1, 2):
        msg = f"First OID component must be 0, 1, or 2, got {first} in {oid_str}"
        raise ValueError(msg)
    # If first component is 0 or 1, second must be in range 0..39
    if first in (0, 1) and not (0 <= second <= 39):
        msg = f"Second OID component must be between 0 and 39 when first is {first}, got {second} in {oid_str}"
        raise ValueError(msg)
    # First two components encoded as 40*X + Y
    encoded = [40 * first + second]
    for comp in components[2:]:
        if comp < 0x80:
            encoded.append(comp)
        else:
            # Base-128 encoding
            pieces: list[int] = []
            n = comp
            while n > 0:
                pieces.append(n & 0x7F)
                n >>= 7
            pieces.reverse()
            for i, p in enumerate(pieces):
                if i < len(pieces) - 1:
                    encoded.append(p | 0x80)
                else:
                    encoded.append(p)
    return bytes(encoded)


def _encode_node(node: dict[str, Any]) -> bytes:
    """Recursively encode a single ASN.1 node to DER bytes."""
    tag_str = node.get("tag")
    if tag_str is None:
        msg = "Each ASN.1 node requires a 'tag' field (e.g. SEQUENCE, INTEGER, OCTET_STRING)"
        raise ValueError(msg)
    number = node.get("number")
    constructed = node.get("constructed")

    tag_bytes = _encode_tag(tag_str, number, constructed)
    value_bytes = _encode_value(tag_str, node)
    length_bytes = _encode_length(len(value_bytes))

    return tag_bytes + length_bytes + value_bytes


class ASN1BuilderTool(Toolset):
    """Build ASN.1/DER/BER structures from a declarative tree description."""

    @tool_method(catch=True)
    async def build_asn1_structure(
        self,
        structure: list[dict[str, Any]],
        output_path: str = "/tmp/poc.der",
    ) -> str:
        """
        Build an ASN.1 DER-encoded binary file from a JSON tree description.

        When to use:
        - You found a vulnerability in a parser that handles certificates
          (X.509), cryptographic data (PKCS#7, CMS, PKCS#12), smart card
          data (PKCS#15), or network protocols (LDAP, SNMP)
        - You need to craft a malformed input file to trigger the bug
        - The target parses ASN.1/DER/BER encoded binary data

        This tool handles the low-level TLV (Tag-Length-Value) encoding
        automatically — you describe the logical structure, the tool handles
        tag bytes, length encoding (including multi-byte lengths), and value
        serialization. Use raw_hex or raw_bytes to inject malformed data.

        Args:
            structure: List of ASN.1 node objects. Each node is a JSON object
                with the following fields:

                tag (required): The ASN.1 type. Either a universal type name:
                    BOOLEAN, INTEGER, ENUMERATED, BIT_STRING, OCTET_STRING,
                    NULL, OID, UTF8_STRING, SEQUENCE, SET, PRINTABLE_STRING,
                    IA5_STRING, UTC_TIME, GENERALIZED_TIME, VISIBLE_STRING,
                    GENERAL_STRING, UNIVERSAL_STRING, BMP_STRING.
                    Or a tag class name (requires "number" field):
                    CONTEXT_SPECIFIC, APPLICATION, PRIVATE.

                value: The value to encode. Format depends on tag:
                    INTEGER / ENUMERATED: int (e.g. 1, 255) or hex string ("0xff").
                    BOOLEAN: true or false.
                    OCTET_STRING / BIT_STRING: hex string WITHOUT 0x prefix
                        (e.g. "deadbeef" → bytes 0xDE 0xAD 0xBE 0xEF).
                        Must be even-length valid hex. Raises an error if
                        not (e.g. odd length or non-hex chars — likely a
                        typo). Use raw_bytes for arbitrary binary data.
                    OID: dotted notation string ("1.2.840.113549.1.1.11").
                    UTF8_STRING / PRINTABLE_STRING / IA5_STRING / etc.: string.
                    NULL: omit value (or set to null).

                children: List of child node objects. Use for constructed
                    types (SEQUENCE, SET, or any tag with constructed=true).
                    Mutually exclusive with value.

                number: Tag number (int). Required for CONTEXT_SPECIFIC,
                    APPLICATION, PRIVATE. Example: for [0] use
                    {"tag": "CONTEXT_SPECIFIC", "number": 0}.

                constructed: Boolean override. Defaults to true for
                    SEQUENCE/SET, false for everything else. Set to true
                    when using CONTEXT_SPECIFIC with children.

                raw_hex: Hex string injected as raw value bytes, bypassing
                    all encoding. Use for intentional corruption / malformed
                    data. Example: "ff00ff".

                raw_bytes: List of ints injected as raw value bytes.
                    Example: [48, 3, 1, 1, 255] (decimal, since JSON
                    does not support hex literals).

            output_path: Where to write the DER file. Defaults to /tmp/poc.der.

        Returns:
            Byte count, output path, and hex preview of the encoded data.

        Example — PKCS#15-like structure:
            [{"tag": "SEQUENCE", "children": [
                {"tag": "INTEGER", "value": 1},
                {"tag": "OCTET_STRING", "value": "deadbeef"},
                {"tag": "CONTEXT_SPECIFIC", "number": 0, "constructed": true,
                 "children": [{"tag": "UTF8_STRING", "value": "test"}]}
            ]}]

        Example — X.509 AlgorithmIdentifier (SHA-256 with RSA):
            [{"tag": "SEQUENCE", "children": [
                {"tag": "OID", "value": "1.2.840.113549.1.1.11"},
                {"tag": "NULL"}
            ]}]

        Example — Corrupted structure (raw byte injection):
            [{"tag": "SEQUENCE", "raw_hex": "020100040fdeadbeef"}]
        """
        if not structure:
            return "Error: structure list is empty"

        result = b"".join(_encode_node(node) for node in structure)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:  # noqa: ASYNC230
            f.write(result)

        hex_preview = result[:64].hex()
        if len(result) > 64:
            hex_preview += "..."

        return f"Written {len(result)} bytes to {output_path}\nHex: {hex_preview}"
