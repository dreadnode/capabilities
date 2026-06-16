"""ExifTool wrapper for EXIF metadata reading, writing, and injection.

Wraps the ``exiftool`` CLI for reading and manipulating image/document
metadata. Primary security use cases: injecting XSS payloads into EXIF
fields (Comment, Artist, Copyright, ImageDescription), crafting images
with metadata that triggers SSRF when processed server-side, and
stripping metadata to test upload sanitization.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Annotated

from dreadnode.agents.tools import Toolset, tool_method

_MAX_OUTPUT = 50_000


def _find_exiftool() -> str:
    path = shutil.which("exiftool")
    if path is None:
        raise FileNotFoundError(
            "exiftool not found on PATH. Install via: apt-get install libimage-exiftool-perl"
        )
    return path


async def _run(args: list[str], timeout: int = 30) -> str:
    exiftool = _find_exiftool()
    proc = await asyncio.create_subprocess_exec(
        exiftool,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return "Error: exiftool timed out"

    output = stdout.decode(errors="replace")
    if proc.returncode != 0:
        err = stderr.decode(errors="replace").strip()
        if err:
            output = f"{output}\nstderr: {err}" if output else f"Error: {err}"
    return output[:_MAX_OUTPUT]


class ExifTool(Toolset):
    """Read, write, and strip EXIF/XMP/IPTC metadata on image and document files.

    Wraps the exiftool CLI for metadata manipulation during web security
    testing. Use for injecting payloads into metadata fields, reading
    metadata from downloaded files, and testing upload sanitization.
    """

    @tool_method(name="exif_read", catch=True)
    async def exif_read(
        self,
        path: Annotated[str, "Path to the file to read metadata from."],
        tags: Annotated[
            list[str] | None,
            "Specific tags to read (e.g. ['Comment', 'Artist']). Omit to read all.",
        ] = None,
    ) -> str:
        """Read EXIF/XMP/IPTC metadata from a file.

        Returns all metadata tags by default, or specific tags if provided.
        Useful for inspecting uploaded files, checking if metadata survives
        server-side processing, or examining downloaded images for information leakage.
        """
        file_path = Path(path)
        if not file_path.is_file():
            return f"Error: file not found: {path}"

        args = ["-j", "-G"]
        if tags:
            args.extend(f"-{tag}" for tag in tags)
        args.append(str(file_path))
        return await _run(args)

    @tool_method(name="exif_write", catch=True)
    async def exif_write(
        self,
        path: Annotated[str, "Path to the file to modify."],
        tags: Annotated[
            dict[str, str],
            "Tag-value pairs to write (e.g. {'Comment': '<script>alert(1)</script>', 'Artist': 'test'}).",
        ],
        no_backup: Annotated[
            bool,
            "Skip creating a backup (_original) file. Default true for cleaner workflow.",
        ] = True,
    ) -> str:
        """Write metadata tags to a file.

        Injects arbitrary values into EXIF/XMP/IPTC fields. Common security
        payloads: XSS in Comment/Artist/Copyright/ImageDescription, SSRF URLs
        in GPSImgDirection or XMP fields, command injection strings in metadata
        that gets logged or processed by backend tools.
        """
        file_path = Path(path)
        if not file_path.is_file():
            return f"Error: file not found: {path}"

        args: list[str] = []
        if no_backup:
            args.append("-overwrite_original")
        for tag, value in tags.items():
            args.append(f"-{tag}={value}")
        args.append(str(file_path))
        return await _run(args)

    @tool_method(name="exif_strip", catch=True)
    async def exif_strip(
        self,
        path: Annotated[str, "Path to the file to strip metadata from."],
        no_backup: Annotated[
            bool,
            "Skip creating a backup (_original) file. Default true.",
        ] = True,
    ) -> str:
        """Strip all metadata from a file.

        Removes every EXIF/XMP/IPTC tag. Use to create a clean baseline file
        before injecting specific payloads, or to test whether a server-side
        upload handler strips metadata by comparing before/after.
        """
        file_path = Path(path)
        if not file_path.is_file():
            return f"Error: file not found: {path}"

        args = ["-all="]
        if no_backup:
            args.append("-overwrite_original")
        args.append(str(file_path))
        return await _run(args)

    @tool_method(name="exif_copy", catch=True)
    async def exif_copy(
        self,
        source: Annotated[str, "Path to the source file to copy metadata from."],
        destination: Annotated[
            str, "Path to the destination file to copy metadata to."
        ],
        no_backup: Annotated[
            bool,
            "Skip creating a backup (_original) file. Default true.",
        ] = True,
    ) -> str:
        """Copy all metadata from one file to another.

        Transfers EXIF/XMP/IPTC tags between files. Use to transplant payloads
        from a crafted file into a target-compatible format, or to replicate
        metadata from a legitimate file into a malicious one.
        """
        src = Path(source)
        dst = Path(destination)
        if not src.is_file():
            return f"Error: source file not found: {source}"
        if not dst.is_file():
            return f"Error: destination file not found: {destination}"

        args = ["-TagsFromFile", str(src)]
        if no_backup:
            args.append("-overwrite_original")
        args.append(str(dst))
        return await _run(args)
