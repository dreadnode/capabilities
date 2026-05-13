"""ReversingLabs Spectra Assure (secure.software) API client.

Covers two surfaces:

- **Community** — search the public catalogue by purl / partial purl / hash
  and fetch analysis reports for any community package version.
- **Portal** — import a community package into your project, check scan
  status, export reports (CycloneDX, SPDX, SARIF, rl-json, rl-cve, ...)
  and pull a short-lived download URL for the artifact.

Auth: Personal Access Token via ``Authorization: Bearer <token>``.
Configuration is read from environment variables on first use:

- ``SPECTRA_ASSURE_TOKEN``  (required)
- ``SPECTRA_ASSURE_HOST``   default ``my.secure.software``
- ``SPECTRA_ASSURE_PATH``   default ``demo``  (the portal slug after the host)
- ``SPECTRA_ASSURE_ORG``    default empty    (needed for Portal endpoints)
- ``SPECTRA_ASSURE_GROUP``  default empty    (needed for Portal endpoints)
- ``SECURE_SOFTWARE_DIR``   default ``~/workspace/secure-software``

Docs: https://docs.secure.software/api-reference/
"""

from __future__ import annotations

import json
import os
import typing as t
from pathlib import Path
from urllib.parse import quote

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

REPORT_FORMATS = (
    "cyclonedx",
    "rl-checks",
    "rl-cve",
    "rl-diff",
    "rl-json",
    "rl-summary-pdf",
    "rl-uri",
    "sarif",
    "spdx",
)


def _default_download_dir() -> Path:
    env = os.environ.get("SECURE_SOFTWARE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / "workspace" / "secure-software"


class SpectraAssure(Toolset):
    """ReversingLabs Spectra Assure (secure.software) API client.

    Exposes Community search/report endpoints and Portal project
    operations (import, status, download, report export).
    """

    timeout: int = 60
    max_output_chars: int = 50_000

    _client: httpx.AsyncClient | None = PrivateAttr(default=None)
    _token: str | None = PrivateAttr(default=None)
    _host: str | None = PrivateAttr(default=None)
    _path: str | None = PrivateAttr(default=None)
    _org: str | None = PrivateAttr(default=None)
    _group: str | None = PrivateAttr(default=None)

    def _configure(self) -> None:
        if self._token is None:
            self._token = os.environ.get("SPECTRA_ASSURE_TOKEN", "").strip()
        if self._host is None:
            self._host = os.environ.get("SPECTRA_ASSURE_HOST", "my.secure.software").strip()
        if self._path is None:
            self._path = os.environ.get("SPECTRA_ASSURE_PATH", "demo").strip().strip("/")
        if self._org is None:
            self._org = os.environ.get("SPECTRA_ASSURE_ORG", "").strip()
        if self._group is None:
            self._group = os.environ.get("SPECTRA_ASSURE_GROUP", "").strip()

    def _base_url(self) -> str:
        self._configure()
        return f"https://{self._host}/{self._path}/api/public/v1"

    def _headers(self) -> dict[str, str]:
        self._configure()
        if not self._token:
            raise RuntimeError(
                "SPECTRA_ASSURE_TOKEN is not set. Create a Personal Access Token "
                "in the Spectra Assure Portal (Account settings) and export it."
            )
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            )
        return self._client

    def _require_portal_scope(self) -> tuple[str, str]:
        self._configure()
        if not self._org or not self._group:
            raise RuntimeError(
                "Portal endpoints need SPECTRA_ASSURE_ORG and SPECTRA_ASSURE_GROUP. "
                "Community endpoints (search, community report) work without them."
            )
        return self._org, self._group

    def _clip(self, text: str) -> str:
        if len(text) > self.max_output_chars:
            total = len(text)
            return text[: self.max_output_chars] + f"\n\n... [TRUNCATED: {total} chars total]"
        return text

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, t.Any] | None = None,
        json_body: t.Any | None = None,
        accept: str = "application/json",
    ) -> httpx.Response:
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        headers = self._headers()
        headers["Accept"] = accept
        return await client.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            headers=headers,
        )

    def _format(self, resp: httpx.Response, *, raw: bool = False) -> str:
        status = resp.status_code
        ct = resp.headers.get("content-type", "")
        if raw or "application/json" not in ct:
            return f"HTTP {status} {ct}\n\n{self._clip(resp.text)}"
        try:
            parsed = resp.json()
            body = json.dumps(parsed, indent=2)
        except Exception:
            body = resp.text
        return f"HTTP {status}\n\n{self._clip(body)}"

    # ------------------------------------------------------------------
    # Community endpoints
    # ------------------------------------------------------------------

    @tool_method(name="spectra_search_packages", catch=True)
    async def search_packages(
        self,
        queries: t.Annotated[
            list[str],
            "Search terms (max 50). Each is a full purl "
            "'pkg:community/<namespace>/<name>@<version>', a partial purl "
            "(version optional, wildcards allowed in name), or a SHA1/SHA256 hash. "
            "Ecosystems supported: npm, pypi, gem, nuget, maven, go, cargo, etc.",
        ],
        page: t.Annotated[int, "Page number (1-indexed)"] = 1,
        page_size: t.Annotated[int, "Results per page (max 100)"] = 25,
    ) -> str:
        """Search the Spectra Assure Community catalogue.

        Accepts up to 50 queries per call. Hash searches return both the
        matched package and any packages that *contain* that hash.
        """
        if not queries:
            return "Error: 'queries' must contain at least one term."
        if len(queries) > 50:
            return "Error: Spectra Assure caps search at 50 queries per request."
        resp = await self._request(
            "POST",
            "/community/packages/search",
            params={"page": page, "page_size": page_size},
            json_body={"queries": queries},
        )
        return self._format(resp)

    @tool_method(name="spectra_get_package", catch=True)
    async def get_package(
        self,
        purl: t.Annotated[
            str,
            "Package URL, e.g. 'pkg:community/npm/lodash' or 'pkg:npm/lodash'. "
            "Both forms accepted — the client normalises to 'pkg:community/...'",
        ],
    ) -> str:
        """Fetch community package metadata and the latest published version summary."""
        normalised = _normalise_community_purl(purl)
        resp = await self._request(
            "GET",
            f"/community/packages/{quote(normalised, safe='')}",
        )
        return self._format(resp)

    @tool_method(name="spectra_get_version_report", catch=True)
    async def get_version_report(
        self,
        purl: t.Annotated[
            str,
            "Package URL without the version, " "e.g. 'pkg:community/npm/lodash' or 'pkg:pypi/requests'.",
        ],
        version: t.Annotated[str, "Version string (e.g. '4.17.21')"],
    ) -> str:
        """Fetch the Community analysis report for a specific package version.

        The report includes malware detections, vulnerability counts,
        license findings, quality metrics, and file-level analysis.
        """
        normalised = _normalise_community_purl(purl)
        resp = await self._request(
            "GET",
            f"/community/packages/{quote(normalised, safe='')}/versions/{quote(version, safe='')}",
        )
        return self._format(resp)

    # ------------------------------------------------------------------
    # Portal endpoints (require SPECTRA_ASSURE_ORG / _GROUP)
    # ------------------------------------------------------------------

    @tool_method(name="spectra_import_purl", catch=True)
    async def import_purl(
        self,
        project: t.Annotated[str, "Portal project slug"],
        package: t.Annotated[str, "Portal package slug (created if missing)"],
        version: t.Annotated[str, "Version to import"],
        source_purl: t.Annotated[
            str,
            "Community purl to pull from, e.g. 'pkg:pypi/requests@2.31.0'.",
        ],
    ) -> str:
        """Import a community package version into your Portal project for scanning.

        This is the supported way to pull an arbitrary community artifact
        into Spectra Assure — after import, poll ``spectra_get_status``
        and then ``spectra_download_artifact`` to retrieve the file.
        """
        org, group = self._require_portal_scope()
        rl_path = f"pkg:rl/{project}/{package}@{version}"
        resp = await self._request(
            "POST",
            f"/purl-import/{org}/{group}/{quote(rl_path, safe=':/@')}",
            json_body={"purl": source_purl},
        )
        return self._format(resp)

    @tool_method(name="spectra_get_status", catch=True)
    async def get_status(
        self,
        project: t.Annotated[str, "Portal project slug"],
        package: t.Annotated[str, "Portal package slug"],
        version: t.Annotated[str, "Version string"],
        download: t.Annotated[
            bool,
            "If true, response carries a short-lived (60s) download URL " "for the version artifact.",
        ] = False,
    ) -> str:
        """Check analysis status of a Portal package version.

        Set ``download=True`` to receive a signed URL that can be used
        with ``spectra_download_artifact`` before it expires.
        """
        org, group = self._require_portal_scope()
        rl_path = f"pkg:rl/{project}/{package}@{version}"
        resp = await self._request(
            "GET",
            f"/status/{org}/{group}/{quote(rl_path, safe=':/@')}",
            params={"download": "true"} if download else None,
        )
        return self._format(resp)

    @tool_method(name="spectra_export_report", catch=True)
    async def export_report(
        self,
        project: t.Annotated[str, "Portal project slug"],
        package: t.Annotated[str, "Portal package slug"],
        version: t.Annotated[str, "Version string"],
        report_type: t.Annotated[
            str,
            "Report format: one of cyclonedx, rl-checks, rl-cve, rl-diff, "
            "rl-json, rl-summary-pdf, rl-uri, sarif, spdx.",
        ] = "rl-json",
        save_as: t.Annotated[
            str,
            "Optional local filename to save the report to. Relative paths " "resolve under SECURE_SOFTWARE_DIR.",
        ] = "",
    ) -> str:
        """Export an analysis report for a Portal package version.

        By default the full body is returned inline (and truncated if
        huge). Pass ``save_as`` to stream it to disk instead and receive
        the absolute path back.
        """
        if report_type not in REPORT_FORMATS:
            return f"Error: unknown report_type '{report_type}'. " f"Valid: {', '.join(REPORT_FORMATS)}"
        org, group = self._require_portal_scope()
        rl_path = f"pkg:rl/{project}/{package}@{version}"
        accept = "application/pdf" if report_type == "rl-summary-pdf" else "application/json"
        resp = await self._request(
            "GET",
            f"/report/{org}/{group}/{report_type}/{quote(rl_path, safe=':/@')}",
            accept=accept,
        )
        if resp.status_code >= 400:
            return self._format(resp)
        if save_as:
            dest = _resolve_download_path(save_as)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(resp.content)
            return f"Saved {report_type} report ({len(resp.content)} bytes) to {dest}"
        if report_type == "rl-summary-pdf":
            return f"PDF report fetched ({len(resp.content)} bytes). " "Re-run with save_as=<file.pdf> to persist it."
        return self._format(resp, raw=report_type in {"sarif", "cyclonedx", "spdx"})

    @tool_method(name="spectra_download_artifact", catch=True)
    async def download_artifact(
        self,
        project: t.Annotated[str, "Portal project slug"],
        package: t.Annotated[str, "Portal package slug"],
        version: t.Annotated[str, "Version string"],
        save_as: t.Annotated[
            str,
            "Local filename. Relative paths resolve under SECURE_SOFTWARE_DIR. "
            "If empty, defaults to '<project>-<package>-<version>.bin'.",
        ] = "",
    ) -> str:
        """Download the analysed artifact for a Portal package version.

        Fetches a 60-second signed URL from ``/status?download=true``
        then streams the file to disk. Returns the absolute destination.
        """
        org, group = self._require_portal_scope()
        rl_path = f"pkg:rl/{project}/{package}@{version}"
        status_resp = await self._request(
            "GET",
            f"/status/{org}/{group}/{quote(rl_path, safe=':/@')}",
            params={"download": "true"},
        )
        if status_resp.status_code >= 400:
            return self._format(status_resp)
        try:
            payload = status_resp.json()
        except Exception:
            return f"Error: status response was not JSON:\n{status_resp.text[:500]}"
        download_url = _find_download_url(payload)
        if not download_url:
            return (
                "Error: no download URL in status response. The artifact may still "
                "be processing, or this version does not expose one. Raw body:\n"
                + json.dumps(payload, indent=2)[: self.max_output_chars]
            )
        dest_name = save_as or f"{project}-{package}-{version}.bin"
        dest = _resolve_download_path(dest_name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        client = self._ensure_client()
        total = 0
        async with client.stream("GET", download_url) as stream:
            if stream.status_code >= 400:
                body = (await stream.aread()).decode(errors="replace")
                return f"HTTP {stream.status_code} fetching signed URL\n\n{body[:2000]}"
            with dest.open("wb") as fh:
                async for chunk in stream.aiter_bytes():
                    fh.write(chunk)
                    total += len(chunk)
        return f"Downloaded {total} bytes to {dest}"


def _normalise_community_purl(purl: str) -> str:
    """Accept 'pkg:npm/foo' or 'pkg:community/npm/foo' — return the latter."""
    p = purl.strip()
    if not p.startswith("pkg:"):
        raise ValueError(f"Not a purl: {purl!r}")
    rest = p[len("pkg:") :]
    if rest.startswith("community/"):
        return p
    return f"pkg:community/{rest}"


def _resolve_download_path(name: str) -> Path:
    p = Path(name).expanduser()
    if p.is_absolute():
        return p
    return _default_download_dir() / p


def _find_download_url(payload: t.Any) -> str | None:
    """Walk the status payload looking for a download URL field."""
    if isinstance(payload, dict):
        for key in ("download_url", "downloadUrl", "download", "artifact_url", "url"):
            val = payload.get(key)
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                return val
        for value in payload.values():
            found = _find_download_url(value)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = _find_download_url(item)
            if found:
                return found
    return None
