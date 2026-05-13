"""Enrichment tools for secure-software package analysis.

These complement the Spectra Assure API client with:

- **Ecosystem fetch** — resolve a purl to its registry URL (npm, pypi,
  rubygems, cargo, maven, nuget, go) and download the artifact without
  needing a Spectra Assure Portal import.
- **Archive inspection** — extract tarballs / zips / wheels / npm
  tarballs into a working directory and list file inventory with
  per-file hashes and sizes.
- **Static triage** — strings, entropy, magic-byte inspection, optional
  YARA scan.
- **Vulnerability enrichment** — query OSV.dev (unauthenticated) for
  known CVEs affecting a purl or specific version.
- **Supply-chain health** — fetch OpenSSF Scorecard results for the
  repository backing a package.

Designed to chain cleanly with the Spectra Assure report data: use
``spectra_get_version_report`` for RL's analysis, then cross-reference
with OSV/Scorecard/file-level hashes here.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import shutil
import tarfile
import typing as t
import zipfile
from pathlib import Path

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr


def _default_dir() -> Path:
    env = os.environ.get("SECURE_SOFTWARE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / "workspace" / "secure-software"


def _resolve(path: str) -> Path:
    p = Path(path).expanduser()
    if p.is_absolute():
        return p
    return _default_dir() / p


class PackageEnrichment(Toolset):
    """Download, extract, and enrich packages with vuln/health data."""

    timeout: int = 60
    max_output_chars: int = 40_000

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "reversinglabs-secure-software/1.0"},
            )
        return self._client

    def _clip(self, text: str) -> str:
        if len(text) > self.max_output_chars:
            total = len(text)
            return text[: self.max_output_chars] + f"\n\n... [TRUNCATED: {total} chars total]"
        return text

    # ------------------------------------------------------------------
    # Ecosystem download
    # ------------------------------------------------------------------

    @tool_method(name="ecosystem_download", catch=True)
    async def ecosystem_download(
        self,
        purl: t.Annotated[
            str,
            "Package URL, e.g. 'pkg:npm/left-pad@1.3.0', 'pkg:pypi/requests@2.31.0', "
            "'pkg:gem/rails@7.1.0', 'pkg:cargo/serde@1.0.0', "
            "'pkg:maven/org.apache.commons/commons-lang3@3.14.0', "
            "'pkg:nuget/Newtonsoft.Json@13.0.3'. Version is required.",
        ],
        save_as: t.Annotated[
            str,
            "Optional local filename. Relative paths resolve under "
            "SECURE_SOFTWARE_DIR. If empty, a name is derived from the purl.",
        ] = "",
    ) -> str:
        """Resolve a purl to its registry URL and download the artifact.

        Complements ``spectra_import_purl`` for cases where you just want
        the archive without going through the Portal. Returns the
        absolute path to the downloaded file.
        """
        try:
            ecosystem, namespace, name, version = _parse_purl(purl)
        except ValueError as exc:
            return f"Error: {exc}"
        if not version:
            return "Error: purl must include a version (e.g. '@1.2.3')."

        client = self._ensure_client()
        try:
            url, default_name = await _resolve_registry_url(client, ecosystem, namespace, name, version)
        except ValueError as exc:
            return f"Error: {exc}"

        dest = _resolve(save_as or default_name)
        dest.parent.mkdir(parents=True, exist_ok=True)

        total = 0
        async with client.stream("GET", url) as stream:
            if stream.status_code >= 400:
                body = (await stream.aread()).decode(errors="replace")
                return f"HTTP {stream.status_code} from {url}\n\n{body[:1500]}"
            with dest.open("wb") as fh:
                async for chunk in stream.aiter_bytes():
                    fh.write(chunk)
                    total += len(chunk)
        sha256 = _sha256(dest)
        return f"Downloaded {total} bytes to {dest}\nsha256: {sha256}\nsource: {url}"

    # ------------------------------------------------------------------
    # Archive inspection
    # ------------------------------------------------------------------

    @tool_method(name="extract_archive", catch=True)
    async def extract_archive(
        self,
        archive: t.Annotated[str, "Path to the downloaded archive"],
        into: t.Annotated[
            str,
            "Destination directory. Relative paths resolve under " "SECURE_SOFTWARE_DIR. Created if missing.",
        ] = "",
    ) -> str:
        """Extract a tar/zip/wheel/npm tarball safely into a directory.

        Refuses entries with absolute paths or '..' components to avoid
        zip-slip. Returns the number of files extracted and the root.
        """
        src = _resolve(archive)
        if not src.exists():
            return f"Error: archive not found: {src}"
        if not into:
            into = f"extracted/{src.stem}"
        dest = _resolve(into)
        dest.mkdir(parents=True, exist_ok=True)

        count = 0
        if zipfile.is_zipfile(src):
            with zipfile.ZipFile(src) as zf:
                for member in zf.infolist():
                    if _unsafe_path(member.filename):
                        continue
                    zf.extract(member, dest)
                    count += 1
        elif tarfile.is_tarfile(src):
            with tarfile.open(src) as tf:
                for member in tf.getmembers():
                    if _unsafe_path(member.name):
                        continue
                    try:
                        tf.extract(member, dest, filter="data")
                    except TypeError:
                        tf.extract(member, dest)
                    count += 1
        else:
            return f"Error: {src} is not a recognised archive (zip or tar)."
        return f"Extracted {count} entries to {dest}"

    @tool_method(name="file_inventory", catch=True)
    async def file_inventory(
        self,
        path: t.Annotated[str, "Directory to walk"],
        limit: t.Annotated[int, "Maximum files to include"] = 500,
    ) -> str:
        """List every file under a directory with size and SHA-256.

        Use after ``extract_archive`` to get a manifest you can cross-
        reference with Spectra Assure per-file hash data or feed to
        other reversing capabilities.
        """
        root = _resolve(path)
        if not root.exists():
            return f"Error: path not found: {root}"
        if root.is_file():
            return _format_entry(root, root.parent)
        lines: list[str] = [f"# Inventory of {root}"]
        count = 0
        for entry in sorted(root.rglob("*")):
            if entry.is_file():
                lines.append(_format_entry(entry, root))
                count += 1
                if count >= limit:
                    lines.append(f"... [truncated at {limit} files]")
                    break
        lines.append(f"# Total files listed: {count}")
        return self._clip("\n".join(lines))

    @tool_method(name="file_strings", catch=True)
    async def file_strings(
        self,
        path: t.Annotated[str, "File to extract printable strings from"],
        min_length: t.Annotated[int, "Minimum run length"] = 6,
        max_strings: t.Annotated[int, "Max strings to return"] = 400,
    ) -> str:
        """Extract printable ASCII/UTF-16 strings from a binary.

        Pure-Python implementation — no dependency on `/usr/bin/strings`.
        Useful for quick triage of suspicious packages.
        """
        target = _resolve(path)
        if not target.exists() or not target.is_file():
            return f"Error: not a file: {target}"
        data = target.read_bytes()
        out: list[str] = []
        current = bytearray()
        for b in data:
            if 32 <= b < 127:
                current.append(b)
            else:
                if len(current) >= min_length:
                    out.append(current.decode("ascii", errors="replace"))
                    if len(out) >= max_strings:
                        break
                current = bytearray()
        if len(current) >= min_length and len(out) < max_strings:
            out.append(current.decode("ascii", errors="replace"))
        return self._clip("\n".join(out) or "(no printable runs found)")

    @tool_method(name="file_entropy", catch=True)
    async def file_entropy(
        self,
        path: t.Annotated[str, "File to measure"],
    ) -> str:
        """Compute Shannon entropy and magic bytes of a file.

        Entropy > ~7.5 suggests packed/encrypted content.
        """
        target = _resolve(path)
        if not target.exists() or not target.is_file():
            return f"Error: not a file: {target}"
        data = target.read_bytes()
        if not data:
            return "File is empty."
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        entropy = 0.0
        for c in counts:
            if c:
                p = c / total
                entropy -= p * math.log2(p)
        magic = data[:16].hex()
        return (
            f"path: {target}\nsize: {total} bytes\n"
            f"sha256: {hashlib.sha256(data).hexdigest()}\n"
            f"entropy: {entropy:.4f} bits/byte\nmagic(hex): {magic}"
        )

    @tool_method(name="yara_scan", catch=True)
    async def yara_scan(
        self,
        target: t.Annotated[str, "File or directory to scan"],
        rules: t.Annotated[
            str,
            "Path to a YARA rules file, or inline YARA source. "
            "If the string contains 'rule ' it is treated as inline.",
        ],
        recursive: t.Annotated[bool, "Recurse into directories"] = True,
    ) -> str:
        """Scan files with YARA rules.

        Requires the ``yara-python`` package (``pip install yara-python``).
        Returns one line per match: ``<file> -> <rule>``.
        """
        try:
            import yara  # type: ignore[import-untyped]
        except ImportError:
            return "Error: yara-python is not installed. " "Install with `pip install yara-python` to enable this tool."
        if "rule " in rules:
            compiled = yara.compile(source=rules)
        else:
            rules_path = _resolve(rules)
            if not rules_path.exists():
                return f"Error: rules file not found: {rules_path}"
            compiled = yara.compile(filepath=str(rules_path))

        target_path = _resolve(target)
        if not target_path.exists():
            return f"Error: target not found: {target_path}"
        paths: list[Path]
        if target_path.is_file():
            paths = [target_path]
        elif recursive:
            paths = [p for p in target_path.rglob("*") if p.is_file()]
        else:
            paths = [p for p in target_path.iterdir() if p.is_file()]

        hits: list[str] = []
        for p in paths:
            try:
                matches = compiled.match(str(p))
            except Exception as exc:  # noqa: BLE001
                hits.append(f"{p} -> ERROR: {exc}")
                continue
            for m in matches:
                hits.append(f"{p} -> {m.rule}")
        return self._clip("\n".join(hits) or f"No YARA matches across {len(paths)} file(s).")

    # ------------------------------------------------------------------
    # External vulnerability / health enrichment
    # ------------------------------------------------------------------

    @tool_method(name="osv_query_purl", catch=True)
    async def osv_query_purl(
        self,
        purl: t.Annotated[
            str,
            "Package URL, with or without @version. Version narrows the query; "
            "without it, OSV returns every vuln ever recorded for the package.",
        ],
    ) -> str:
        """Look up known vulnerabilities for a package on OSV.dev.

        Unauthenticated public API. Returns OSV records with ID, summary,
        severity, and affected ranges.
        """
        try:
            ecosystem, namespace, name, version = _parse_purl(purl)
        except ValueError as exc:
            return f"Error: {exc}"
        package_name = f"{namespace}/{name}" if namespace else name
        osv_ecosystem = _osv_ecosystem(ecosystem)
        body: dict[str, t.Any] = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
        if version:
            body["version"] = version
        client = self._ensure_client()
        resp = await client.post("https://api.osv.dev/v1/query", json=body)
        if resp.status_code >= 400:
            return f"HTTP {resp.status_code} from OSV\n\n{resp.text[:1500]}"
        payload = resp.json()
        vulns = payload.get("vulns") or []
        if not vulns:
            return f"OSV: no known vulnerabilities for {purl} in ecosystem {osv_ecosystem}."
        lines = [f"OSV: {len(vulns)} vulnerability record(s) for {purl}"]
        for v in vulns[:50]:
            sev = ", ".join(s.get("type", "?") + ":" + s.get("score", "?") for s in v.get("severity", [])) or "n/a"
            lines.append(f"- {v.get('id')}  severity={sev}  summary={v.get('summary', '')[:180]}")
        return self._clip("\n".join(lines))

    @tool_method(name="scorecard_fetch", catch=True)
    async def scorecard_fetch(
        self,
        repo: t.Annotated[
            str,
            "Source repo in 'host/owner/name' form, e.g. " "'github.com/psf/requests'.",
        ],
    ) -> str:
        """Fetch the latest OpenSSF Scorecard result for a repository.

        Unauthenticated. Returns overall score plus per-check details
        (Vulnerabilities, Maintained, Code-Review, etc.).
        """
        repo = repo.strip().removeprefix("https://").removeprefix("http://")
        url = f"https://api.securityscorecards.dev/projects/{repo}"
        client = self._ensure_client()
        resp = await client.get(url)
        if resp.status_code == 404:
            return f"Scorecard: no result for {repo} (may not be tracked)."
        if resp.status_code >= 400:
            return f"HTTP {resp.status_code} from Scorecard\n\n{resp.text[:1500]}"
        payload = resp.json()
        overall = payload.get("score")
        date = payload.get("date")
        lines = [f"Scorecard for {repo} (as of {date}): overall={overall}/10"]
        for check in payload.get("checks", []):
            lines.append(
                f"  {check.get('name'):<24} {check.get('score'):>3}/10  " f"{(check.get('reason') or '')[:120]}"
            )
        return self._clip("\n".join(lines))

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    @tool_method(name="clean_workdir", catch=True)
    async def clean_workdir(
        self,
        subdir: t.Annotated[
            str,
            "Path under SECURE_SOFTWARE_DIR to remove. Empty means the whole workdir.",
        ] = "",
    ) -> str:
        """Remove a subdirectory under SECURE_SOFTWARE_DIR. Use with care."""
        root = _default_dir()
        target = _resolve(subdir) if subdir else root
        try:
            target.relative_to(root)
        except ValueError:
            return f"Error: refusing to delete outside {root}"
        if not target.exists():
            return f"Nothing to remove at {target}"
        await asyncio.to_thread(shutil.rmtree, target)
        return f"Removed {target}"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _parse_purl(purl: str) -> tuple[str, str, str, str]:
    """Return (ecosystem, namespace, name, version)."""
    p = purl.strip()
    if not p.startswith("pkg:"):
        raise ValueError(f"Not a purl: {purl!r}")
    rest = p[len("pkg:") :]
    if rest.startswith("community/"):
        rest = rest[len("community/") :]
    eco_sep = rest.find("/")
    if eco_sep < 0:
        raise ValueError(f"purl missing '/': {purl!r}")
    ecosystem = rest[:eco_sep].lower()
    tail = rest[eco_sep + 1 :]
    version = ""
    if "@" in tail:
        tail, version = tail.rsplit("@", 1)
    if "/" in tail:
        namespace, name = tail.rsplit("/", 1)
    else:
        namespace, name = "", tail
    if "?" in name:
        name = name.split("?", 1)[0]
    if "?" in version:
        version = version.split("?", 1)[0]
    return ecosystem, namespace, name, version


async def _resolve_registry_url(
    client: httpx.AsyncClient,
    ecosystem: str,
    namespace: str,
    name: str,
    version: str,
) -> tuple[str, str]:
    """Return (download_url, default_filename) for an ecosystem + version.

    Some ecosystems (PyPI) require an API lookup to find the canonical
    artifact URL; those are resolved here.
    """
    eco = ecosystem.lower()
    if eco == "npm":
        unscoped = name
        filename = f"{unscoped}-{version}.tgz"
        registry_name = f"{namespace}/{name}" if namespace else name
        return (
            f"https://registry.npmjs.org/{registry_name}/-/{filename}",
            filename,
        )
    if eco == "pypi":
        meta_url = f"https://pypi.org/pypi/{name}/{version}/json"
        resp = await client.get(meta_url)
        if resp.status_code >= 400:
            raise ValueError(f"pypi metadata lookup failed: HTTP {resp.status_code} for {meta_url}")
        payload = resp.json()
        files = payload.get("urls") or []
        sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
        chosen = sdist or (files[0] if files else None)
        if not chosen:
            raise ValueError(f"pypi {name}@{version} has no downloadable files")
        return chosen["url"], chosen.get("filename", f"{name}-{version}")
    if eco in ("gem", "rubygems"):
        filename = f"{name}-{version}.gem"
        return f"https://rubygems.org/downloads/{filename}", filename
    if eco in ("cargo", "crates"):
        filename = f"{name}-{version}.crate"
        return f"https://crates.io/api/v1/crates/{name}/{version}/download", filename
    if eco == "nuget":
        filename = f"{name}.{version}.nupkg".lower()
        return (
            f"https://www.nuget.org/api/v2/package/{name}/{version}",
            filename,
        )
    if eco == "maven":
        if not namespace:
            raise ValueError("maven purl requires a group namespace")
        group_path = namespace.replace(".", "/")
        filename = f"{name}-{version}.jar"
        return (
            f"https://repo1.maven.org/maven2/{group_path}/{name}/{version}/{filename}",
            filename,
        )
    if eco in ("golang", "go"):
        module = f"{namespace}/{name}" if namespace else name
        filename = f"{name}-{version}.zip"
        return (
            f"https://proxy.golang.org/{module.lower()}/@v/{version}.zip",
            filename,
        )
    raise ValueError(f"unsupported ecosystem for direct download: {ecosystem}")


def _osv_ecosystem(purl_eco: str) -> str:
    """Map purl ecosystem names to OSV ecosystem names."""
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "gem": "RubyGems",
        "rubygems": "RubyGems",
        "cargo": "crates.io",
        "crates": "crates.io",
        "nuget": "NuGet",
        "maven": "Maven",
        "golang": "Go",
        "go": "Go",
        "composer": "Packagist",
        "hex": "Hex",
        "pub": "Pub",
    }
    return mapping.get(purl_eco.lower(), purl_eco)


def _unsafe_path(name: str) -> bool:
    p = Path(name)
    if p.is_absolute():
        return True
    parts = p.parts
    return ".." in parts


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_entry(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    size = path.stat().st_size
    return f"{_sha256(path)}  {size:>10}  {rel}"
