#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
# ]
# ///
"""Protoscope MCP server.

Thin Python MCP wrapper around the Protobuf Protoscope CLI. This intentionally
does not vendor, install, or modify a local Protoscope install. It delegates to:

  1. PROTOSCOPE_COMMAND, if set
  2. protoscope on PATH
  3. go run github.com/protocolbuffers/protoscope/cmd/protoscope@latest, if Go exists

The Go fallback is only used when invoked; status checks do not install or
download anything.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from fastmcp import FastMCP

mcp = FastMCP("protoscope")

MODULE_PATH = "github.com/protocolbuffers/protoscope/cmd/protoscope@latest"
MAX_OUTPUT_CHARS = int(os.environ.get("PROTOSCOPE_MAX_OUTPUT_CHARS", "50000"))
DEFAULT_TIMEOUT = int(os.environ.get("PROTOSCOPE_TIMEOUT", "60"))


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_command() -> list[str] | None:
    configured = os.environ.get("PROTOSCOPE_COMMAND")
    if configured:
        parts = shlex.split(configured)
        if parts and shutil.which(parts[0]):
            return parts
        return None

    if shutil.which("protoscope"):
        return ["protoscope"]

    if shutil.which("go"):
        return ["go", "run", MODULE_PATH]

    return None


def _missing_dependency_message() -> str:
    return (
        "Error: protoscope is unavailable. Install it with:\n"
        "  go install github.com/protocolbuffers/protoscope/cmd/protoscope@latest\n"
        "Alternatively set PROTOSCOPE_COMMAND to an explicit executable, or make "
        "`go` available so the MCP can use `go run "
        "github.com/protocolbuffers/protoscope/cmd/protoscope@latest` as a fallback."
    )


def _is_go_run(command: list[str] | None) -> bool:
    return bool(command and command[:2] == ["go", "run"])


def _build_options(
    *,
    descriptor_set: str | None = None,
    message_type: str | None = None,
    explicit_wire_types: bool = False,
    explicit_length_prefixes: bool = False,
    print_field_names: bool = False,
    print_enum_names: bool = False,
    all_fields_are_messages: bool = False,
    no_groups: bool = False,
    no_quoted_strings: bool = False,
) -> list[str]:
    args: list[str] = []
    if descriptor_set:
        args.extend(["-descriptor-set", descriptor_set])
    if message_type:
        args.extend(["-message-type", message_type])
    if explicit_wire_types:
        args.append("-explicit-wire-types")
    if explicit_length_prefixes:
        args.append("-explicit-length-prefixes")
    if print_field_names:
        args.append("-print-field-names")
    if print_enum_names:
        args.append("-print-enum-names")
    if all_fields_are_messages:
        args.append("-all-fields-are-messages")
    if no_groups:
        args.append("-no-groups")
    if no_quoted_strings:
        args.append("-no-quoted-strings")
    return args


def _clean_hex(hex_data: str) -> bytes:
    clean = re.sub(r"(?i)0x", "", hex_data)
    clean = re.sub(r"[^0-9a-fA-F]", "", clean)
    if not clean:
        raise ValueError("hex_data did not contain any hex bytes")
    if len(clean) % 2:
        raise ValueError("hex_data has an odd number of hex digits")
    return bytes.fromhex(clean)


def _format_bytes(data: bytes, output_format: Literal["hex", "base64"]) -> str:
    if output_format == "hex":
        return data.hex()
    if output_format == "base64":
        return base64.b64encode(data).decode()
    raise ValueError("output_format must be 'hex' or 'base64'")


async def _run_protoscope(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, bytes, str]:
    command = _resolve_command()
    if not command:
        return 127, b"", _missing_dependency_message()

    proc = await asyncio.create_subprocess_exec(
        *(command + args),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, b"", f"Error: protoscope command timed out after {timeout}s"

    return (
        proc.returncode if proc.returncode is not None else 1,
        stdout,
        stderr.decode(errors="replace"),
    )


def _render_text_result(returncode: int, stdout: bytes, stderr: str) -> str:
    text = stdout.decode(errors="replace")
    if stderr:
        text = f"{text}\n{stderr}".strip()
    if returncode != 0:
        return _truncate(f"Error (exit {returncode}): {text}")
    return _truncate(text)


@mcp.tool
async def protoscope_status() -> dict:
    """Report how the MCP would invoke Protoscope on this host."""
    command = _resolve_command()
    return {
        "available": command is not None,
        "command": command,
        "uses_go_run_fallback": _is_go_run(command),
        "timeout_seconds": DEFAULT_TIMEOUT,
        "max_output_chars": MAX_OUTPUT_CHARS,
        "hint": None if command else _missing_dependency_message(),
    }


@mcp.tool
async def protoscope_run(
    args: Annotated[list[str], "Raw Protoscope CLI arguments, excluding the binary name"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Run any Protoscope command for advanced workflows."""
    if not args:
        return "Error: args must include Protoscope CLI arguments."
    returncode, stdout, stderr = await _run_protoscope(args, timeout=timeout)
    return _render_text_result(returncode, stdout, stderr)


@mcp.tool
async def protoscope_help(
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Show Protoscope CLI help."""
    returncode, stdout, stderr = await _run_protoscope(["--help"], timeout=timeout)
    return _render_text_result(returncode, stdout, stderr)


@mcp.tool
async def protoscope_inspect_file(
    input_path: Annotated[str, "Path to an encoded protobuf binary file"],
    descriptor_set: Annotated[str | None, "Optional encoded FileDescriptorSet path"] = None,
    message_type: Annotated[str | None, "Full message type name for descriptor-guided decoding"] = None,
    explicit_wire_types: Annotated[bool, "Include explicit wire type for every field"] = False,
    explicit_length_prefixes: Annotated[bool, "Emit literal length prefixes instead of braces"] = False,
    print_field_names: Annotated[bool, "Print field names when using message_type"] = False,
    print_enum_names: Annotated[bool, "Print enum names when using message_type"] = False,
    all_fields_are_messages: Annotated[bool, "Try to disassemble all fields as messages"] = False,
    no_groups: Annotated[bool, "Do not try to disassemble groups"] = False,
    no_quoted_strings: Annotated[bool, "Assume no fields are strings"] = False,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Inspect an encoded protobuf binary file as Protoscope text."""
    path = Path(input_path).expanduser()
    if not path.exists():
        return f"Error: input_path does not exist: {path}"

    args = _build_options(
        descriptor_set=descriptor_set,
        message_type=message_type,
        explicit_wire_types=explicit_wire_types,
        explicit_length_prefixes=explicit_length_prefixes,
        print_field_names=print_field_names,
        print_enum_names=print_enum_names,
        all_fields_are_messages=all_fields_are_messages,
        no_groups=no_groups,
        no_quoted_strings=no_quoted_strings,
    )
    args.append(str(path))
    returncode, stdout, stderr = await _run_protoscope(args, timeout=timeout)
    return _render_text_result(returncode, stdout, stderr)


@mcp.tool
async def protoscope_inspect_hex(
    hex_data: Annotated[str, "Encoded protobuf bytes as hex"],
    descriptor_set: Annotated[str | None, "Optional encoded FileDescriptorSet path"] = None,
    message_type: Annotated[str | None, "Full message type name for descriptor-guided decoding"] = None,
    explicit_wire_types: Annotated[bool, "Include explicit wire type for every field"] = False,
    explicit_length_prefixes: Annotated[bool, "Emit literal length prefixes instead of braces"] = False,
    print_field_names: Annotated[bool, "Print field names when using message_type"] = False,
    print_enum_names: Annotated[bool, "Print enum names when using message_type"] = False,
    all_fields_are_messages: Annotated[bool, "Try to disassemble all fields as messages"] = False,
    no_groups: Annotated[bool, "Do not try to disassemble groups"] = False,
    no_quoted_strings: Annotated[bool, "Assume no fields are strings"] = False,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Inspect encoded protobuf bytes supplied as hex."""
    try:
        data = _clean_hex(hex_data)
    except ValueError as exc:
        return f"Error: {exc}"

    with tempfile.NamedTemporaryFile(prefix="protoscope-", suffix=".pb") as tmp:
        tmp.write(data)
        tmp.flush()
        return await protoscope_inspect_file(
            tmp.name,
            descriptor_set=descriptor_set,
            message_type=message_type,
            explicit_wire_types=explicit_wire_types,
            explicit_length_prefixes=explicit_length_prefixes,
            print_field_names=print_field_names,
            print_enum_names=print_enum_names,
            all_fields_are_messages=all_fields_are_messages,
            no_groups=no_groups,
            no_quoted_strings=no_quoted_strings,
            timeout=timeout,
        )


@mcp.tool
async def protoscope_assemble_text(
    source: Annotated[str, "Protoscope source text to assemble"],
    output_format: Annotated[Literal["hex", "base64"], "Return encoding for binary output"] = "hex",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Assemble Protoscope source text and return encoded binary bytes."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="protoscope-",
        suffix=".txt",
    ) as tmp:
        tmp.write(source)
        tmp.flush()
        returncode, stdout, stderr = await _run_protoscope(
            ["-s", tmp.name],
            timeout=timeout,
        )
    if returncode != 0:
        return _render_text_result(returncode, stdout, stderr)
    try:
        return _format_bytes(stdout, output_format)
    except ValueError as exc:
        return f"Error: {exc}"


@mcp.tool
async def protoscope_assemble_file(
    source_path: Annotated[str, "Path to Protoscope source text"],
    output_format: Annotated[Literal["hex", "base64"], "Return encoding for binary output"] = "hex",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Assemble a Protoscope source file and return encoded binary bytes."""
    path = Path(source_path).expanduser()
    if not path.exists():
        return f"Error: source_path does not exist: {path}"
    returncode, stdout, stderr = await _run_protoscope(
        ["-s", str(path)],
        timeout=timeout,
    )
    if returncode != 0:
        return _render_text_result(returncode, stdout, stderr)
    try:
        return _format_bytes(stdout, output_format)
    except ValueError as exc:
        return f"Error: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
