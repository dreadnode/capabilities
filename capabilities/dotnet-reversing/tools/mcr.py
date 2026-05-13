"""MCR (Microsoft Container Registry) tools for extracting .NET assemblies.

Provides tools to search, inspect, and extract .NET binaries from MCR container
images without Docker—using pure HTTP + tarfile extraction. The container is
never executed; only filesystem layers are downloaded and unpacked.

Ported from ray_dotnet/app/tasks/mcr.py with modifications for the capability
tool interface.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import tarfile
import tempfile
import typing as t
import zlib
from io import BytesIO
from pathlib import Path

import aiohttp
from dreadnode.agents.tools import tool
from loguru import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REGISTRY = "https://mcr.microsoft.com"
DEFAULT_OUTPUT_DIR = Path.home() / "workspace" / "mcr"

# Accept headers for manifest schema types
ACCEPT_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
ACCEPT_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT_MANIFEST_V1 = "application/vnd.oci.image.manifest.v1+json"
ACCEPT_ANY_MANIFEST = ", ".join(
    [
        ACCEPT_MANIFEST_LIST,
        ACCEPT_MANIFEST_V2,
        ACCEPT_MANIFEST_V1,
        "application/vnd.docker.distribution.manifest.v1+json",
    ]
)

# Timeouts
CATALOG_TIMEOUT = 30
TAGS_TIMEOUT = 20
MANIFEST_TIMEOUT = 30
LAYER_DOWNLOAD_TIMEOUT = 600

# Max layer size (2 GB) — refuse to download layers larger than this
MAX_LAYER_SIZE = 2 * 1024 * 1024 * 1024

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _timeout(seconds: int) -> aiohttp.ClientTimeout:
    """Create an aiohttp timeout with the given total seconds."""
    return aiohttp.ClientTimeout(total=seconds)


async def _http_get_json(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> dict[str, t.Any]:
    """HTTP GET returning parsed JSON. Raises on non-2xx status."""
    async with session.get(url, headers=headers, timeout=_timeout(timeout)) as resp:
        resp.raise_for_status()
        return await resp.json(content_type=None)


# ---------------------------------------------------------------------------
# Registry primitives
# ---------------------------------------------------------------------------


async def _get_catalog(session: aiohttp.ClientSession) -> list[str]:
    """Fetch the full MCR repository catalog."""
    data = await _http_get_json(session, f"{REGISTRY}/v2/_catalog", timeout=CATALOG_TIMEOUT)
    return data["repositories"]


async def _get_tags(session: aiohttp.ClientSession, repo: str) -> list[str]:
    """Fetch all available tags for a repo. Returns [] on error."""
    try:
        result = await _http_get_json(session, f"{REGISTRY}/v2/{repo}/tags/list", timeout=TAGS_TIMEOUT)
        return result.get("tags") or []
    except (aiohttp.ClientResponseError, KeyError):
        return []


async def _get_manifest(
    session: aiohttp.ClientSession,
    repo: str,
    ref: str,
    accept: str = ACCEPT_ANY_MANIFEST,
) -> dict[str, t.Any]:
    """Fetch a manifest by tag or digest."""
    try:
        return await _http_get_json(
            session,
            f"{REGISTRY}/v2/{repo}/manifests/{ref}",
            headers={"Accept": accept},
            timeout=MANIFEST_TIMEOUT,
        )
    except aiohttp.ClientResponseError:
        return {}


# ---------------------------------------------------------------------------
# Version sorting
# ---------------------------------------------------------------------------


def _version_sort_key(tag: str) -> tuple[bool, list[int], str]:
    """Sort key that puts numeric version tags highest-first.

    Parses dot-separated numeric segments so '8.0.25' sorts above '8.0.8'.
    Non-numeric segments are skipped so '8.0-preview.1' parses as [8, 0, 1].
    Tags with no numeric segments sort last.
    """
    parts = re.split(r"[.\-]", tag)
    nums: list[int] = []
    for p in parts:
        if p.isdigit():
            nums.append(int(p))
    # Tags without any numeric parts sort after those with; negate nums for descending
    return (not bool(nums), [-n for n in nums], tag)


# ---------------------------------------------------------------------------
# Layer resolution
# ---------------------------------------------------------------------------


async def _resolve_platform_manifest(
    session: aiohttp.ClientSession,
    repo: str,
    manifests: list[dict[str, t.Any]],
    platform: str,
) -> dict[str, t.Any]:
    """Pick the manifest matching the requested platform from a manifest list."""
    arch, os_name = "amd64", "linux"
    if "/" in platform:
        os_name, arch = platform.split("/", 1)

    for m in manifests:
        p = m.get("platform", {})
        if p.get("architecture") == arch and p.get("os") == os_name:
            # Fetch the platform-specific manifest (accept both Docker v2 and OCI v1)
            accept = f"{ACCEPT_MANIFEST_V2}, {ACCEPT_MANIFEST_V1}"
            return await _get_manifest(session, repo, m["digest"], accept)
    return {}


async def _resolve_layers(
    session: aiohttp.ClientSession,
    repo: str,
    tag: str,
    platform: str = "linux/amd64",
) -> list[dict[str, t.Any]]:
    """Resolve layers for a repo:tag, handling manifest list/v2/v1 schemas."""
    data = await _get_manifest(session, repo, tag)
    if not data:
        return []

    # Case 1: manifest list — pick platform, then get layers
    if "manifests" in data:
        platform_manifest = await _resolve_platform_manifest(session, repo, data["manifests"], platform)
        return platform_manifest.get("layers", [])

    # Case 2: single v2 manifest — layers inline
    if data.get("schemaVersion") == 2 and "layers" in data:
        return data["layers"]

    # Case 3: v1 schema — fsLayers with blobSum digests
    if data.get("schemaVersion") == 1 and "fsLayers" in data:
        seen: set[str] = set()
        layers: list[dict[str, t.Any]] = []
        for fs in data["fsLayers"]:
            digest = fs.get("blobSum")
            if digest and digest not in seen:
                seen.add(digest)
                layers.append({"digest": digest, "size": 0})
        return layers

    return []


# ---------------------------------------------------------------------------
# Layer peeking (HTTP range requests)
# ---------------------------------------------------------------------------


async def _peek_layer(
    session: aiohttp.ClientSession,
    repo: str,
    digest: str,
    chunk_size: int = 10 * 1024,
    max_attempts: int = 10,
) -> list[str]:
    """Partially download a layer to list its files without fetching the whole blob.

    Uses HTTP range requests with exponentially growing chunks. Returns file
    names found in the tar header, or [] if decompression fails.
    """
    url = f"{REGISTRY}/v2/{repo}/blobs/{digest}"
    bytes_read = 0
    buffer = BytesIO()

    for _ in range(max_attempts):
        range_end = bytes_read + chunk_size - 1
        chunk_size *= 2

        try:
            async with session.get(
                url,
                headers={"Range": f"bytes={bytes_read}-{range_end}"},
                timeout=_timeout(30),
            ) as response:
                if response.status not in (200, 206):
                    break
                data = await response.read()
                buffer.seek(0, 2)
                buffer.write(data)
                bytes_read += len(data)
                buffer.seek(0)
        except aiohttp.ClientError:
            break

        try:
            decompressed = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(buffer.read())
            names: list[str] = []
            with tarfile.open(mode="r|", fileobj=BytesIO(decompressed)) as tar:
                try:
                    for member in tar:
                        names.append(member.name)
                except Exception:
                    pass  # truncated stream — return what we got
            if names:
                return names
        except Exception:
            continue

    return []


def _is_app_path(path: str) -> bool:
    """Check if a path is under an app/ directory."""
    normalized = path.lstrip("./")
    return normalized == "app" or normalized.startswith("app/")


def _is_dotnet_binary(path: str) -> bool:
    """Check if a path is a .NET binary."""
    lower = path.lower()
    return lower.endswith(".dll") or lower.endswith(".exe")


async def _find_app_layers(
    session: aiohttp.ClientSession,
    repo: str,
    layers: list[dict[str, t.Any]],
) -> list[tuple[str, int, list[str]]]:
    """Peek into each layer in parallel to find those containing .NET app files."""

    # Filter out tiny layers before peeking
    candidates = [
        (layer["digest"], layer.get("size", 0))
        for layer in layers
        if not (layer.get("size", 0) and layer.get("size", 0) < 1000)
    ]

    if not candidates:
        return []

    # Peek all candidate layers concurrently
    peek_results = await asyncio.gather(*(_peek_layer(session, repo, digest) for digest, _ in candidates))

    app_layers: list[tuple[str, int, list[str]]] = []
    for (digest, size), files in zip(candidates, peek_results):
        if files and (any(_is_app_path(f) for f in files) or any(_is_dotnet_binary(f) for f in files)):
            app_layers.append((digest, size, files))

    return app_layers


# ---------------------------------------------------------------------------
# Layer download and extraction
# ---------------------------------------------------------------------------


async def _download_layer(
    session: aiohttp.ClientSession,
    repo: str,
    digest: str,
    out_dir: Path,
    dll_only: bool = True,
) -> list[str]:
    """Download and extract a full layer. Returns list of extracted files."""
    url = f"{REGISTRY}/v2/{repo}/blobs/{digest}"
    extracted: list[str] = []

    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
        # Stream download to temp file
        async with session.get(url, timeout=_timeout(LAYER_DOWNLOAD_TIMEOUT)) as resp:
            resp.raise_for_status()
            content_length = resp.content_length
            if content_length is not None and content_length > MAX_LAYER_SIZE:
                raise RuntimeError(f"Layer {digest} is {content_length} bytes, " f"exceeds {MAX_LAYER_SIZE} byte limit")
            downloaded = 0
            async for chunk in resp.content.iter_chunked(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > MAX_LAYER_SIZE:
                    raise RuntimeError(f"Layer {digest} download exceeded {MAX_LAYER_SIZE} byte limit")
                tmp.write(chunk)
        tmp.flush()
        tmp.seek(0)

        # Extract from temp file
        with tarfile.open(fileobj=tmp, mode="r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue

                # Sanitize path
                safe_name = member.name.lstrip("/")
                safe_name = safe_name.replace("..", "_")

                if dll_only and not _is_dotnet_binary(safe_name):
                    continue

                # Extract file
                dest = (out_dir / safe_name).resolve()
                if not dest.is_relative_to(out_dir.resolve()):
                    continue  # path traversal attempt

                dest.parent.mkdir(parents=True, exist_ok=True)

                try:
                    src = tar.extractfile(member)
                    if src is not None:
                        with src:
                            dest.write_bytes(src.read())
                        extracted.append(safe_name)
                except Exception as e:
                    logger.warning(f"Failed to extract {safe_name}: {e}")
                    continue

    return extracted


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _format_extraction_summary(out_dir: Path, repo: str, tag: str, files: list[str], cached: bool = False) -> str:
    """Format the extraction summary for the agent."""
    lines: list[str] = []

    if cached:
        lines.append(f"[CACHED] Already extracted: {repo}:{tag}")
    else:
        lines.append(f"Extracted: {repo}:{tag}")

    lines.append(f"Output: {out_dir}")
    lines.append(f"Files: {len(files)}")
    lines.append("")

    # Group files by parent directory
    by_dir: dict[str, list[str]] = {}
    for f in sorted(files):
        parent = str(Path(f).parent)
        by_dir.setdefault(parent, []).append(Path(f).name)

    for parent, names in sorted(by_dir.items()):
        lines.append(f"{parent}/ ({len(names)} files)")
        for name in names[:5]:  # show first 5 per dir
            lines.append(f"  {name}")
        if len(names) > 5:
            lines.append(f"  ... and {len(names) - 5} more")
        lines.append("")

    lines.append(f"Use dotnet_scan_binaries('{out_dir}') to analyze.")
    return "\n".join(lines)


def _slugify(s: str) -> str:
    """Convert a string to a safe directory name."""
    return s.replace("/", "_").replace(":", "_")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
async def mcr_search_repositories(
    query: t.Annotated[str, "Substring to match against repository names"],
) -> str:
    """Search the MCR catalog (~3,200 repos) for repositories matching a query.

    Returns a list of repository names that contain the query string.
    """
    try:
        async with aiohttp.ClientSession() as session:
            repos = await _get_catalog(session)
    except aiohttp.ClientResponseError as e:
        return f"ERROR: Failed to fetch MCR catalog: HTTP {e.status}"
    except Exception as e:
        return f"ERROR: Failed to fetch MCR catalog: {e}"

    query_lower = query.lower()
    matches = sorted([r for r in repos if query_lower in r.lower()])

    if not matches:
        return f"No repositories matching '{query}'"

    lines = [f"Found {len(matches)} repositories matching '{query}':", ""]
    lines.extend(matches)
    return "\n".join(lines)


@tool
async def mcr_list_tags(
    repository: t.Annotated[str, "MCR repository path, e.g. 'dotnet/aspnet'"],
    filter_pattern: t.Annotated[str, "Optional substring filter for tag names"] = "",
    include_windows: t.Annotated[bool, "Include Windows tags (excluded by default)"] = False,
) -> str:
    """List available tags for an MCR repository, sorted by version (newest first).

    By default excludes Windows-specific tags. Use filter_pattern to narrow results.
    """
    async with aiohttp.ClientSession() as session:
        tags = await _get_tags(session, repository)

    if not tags:
        return f"ERROR: Repository '{repository}' not found or has no tags"

    # Filter out Windows tags unless requested
    if not include_windows:
        tags = [tag for tag in tags if "-windows" not in tag.lower()]

    # Apply substring filter
    if filter_pattern:
        pattern_lower = filter_pattern.lower()
        tags = [tag for tag in tags if pattern_lower in tag.lower()]

    if not tags:
        msg = f"No tags found for '{repository}'"
        if filter_pattern:
            msg += f" matching '{filter_pattern}'"
        return msg

    # Sort by version (newest first)
    tags = sorted(tags, key=_version_sort_key)

    lines = [f"Found {len(tags)} tags for '{repository}'"]
    if filter_pattern:
        lines[0] += f" (filtered by '{filter_pattern}')"
    lines.append("")
    lines.extend(tags)
    return "\n".join(lines)


@tool
async def mcr_pull_and_extract(
    image: t.Annotated[
        str,
        "MCR image ref, e.g. 'dotnet/aspnet:8.0' or 'dotnet/aspnet' (defaults to latest tag)",
    ],
    platform: t.Annotated[str, "Target platform: 'linux/amd64' (default) or 'linux/arm64'"] = "linux/amd64",
    dll_only: t.Annotated[bool, "Only extract .dll and .exe files (default True)"] = True,
) -> str:
    """Extract .NET assemblies from an MCR image without running any container code.

    Downloads only the layers containing .NET binaries using HTTP range requests
    to peek layer contents first. No Docker required.
    """
    # Parse image ref
    if ":" in image:
        repo, tag = image.rsplit(":", 1)
    else:
        repo, tag = image, "latest"

    # Remove mcr.microsoft.com prefix if present
    repo = repo.removeprefix("mcr.microsoft.com/")

    # Compute output directory
    out_dir = DEFAULT_OUTPUT_DIR / _slugify(f"{repo}_{tag}")

    # Check cache — only trust directories with a .complete sentinel
    sentinel = out_dir / ".complete"
    if sentinel.exists():
        existing_dlls = list(out_dir.rglob("*.dll")) + list(out_dir.rglob("*.exe"))
        if existing_dlls:
            files = [str(f.relative_to(out_dir)) for f in existing_dlls]
            return _format_extraction_summary(out_dir, repo, tag, files, cached=True)

    # Remove incomplete previous extraction
    if out_dir.exists():
        shutil.rmtree(out_dir)

    async with aiohttp.ClientSession() as session:
        # Resolve layers
        layers = await _resolve_layers(session, repo, tag, platform)
        if not layers:
            return f"ERROR: Could not resolve layers for '{repo}:{tag}' (platform: {platform}). Check that the repository and tag exist."

        # Find layers with app content
        app_layers = await _find_app_layers(session, repo, layers)
        if not app_layers:
            return f"No .NET assemblies found in '{repo}:{tag}'. This image may not contain .NET binaries, or they may be in an unexpected location."

        # Create output directory
        out_dir.mkdir(parents=True, exist_ok=True)

        # Download and extract app layers
        all_files: list[str] = []
        for digest, _size, _peeked_files in app_layers:
            try:
                extracted = await _download_layer(session, repo, digest, out_dir, dll_only)
                all_files.extend(extracted)
            except Exception as e:
                logger.warning(f"Failed to extract layer {digest}: {e}")
                continue

    if not all_files:
        return f"ERROR: Failed to extract any files from '{repo}:{tag}'. The layers may be in an unsupported format."

    # Mark extraction as complete
    sentinel.touch()

    return _format_extraction_summary(out_dir, repo, tag, all_files)
