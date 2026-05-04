"""Toolset: ingest data, manage collection clients, search the graph.

Three concerns share this module because they're all about the
data-loading side of the platform:

- **Search** — generic graph search (``/api/v2/graphs/search``) for
  resolving names to object ids without writing Cypher.
- **File-upload jobs** — the way SharpHound / AzureHound results are
  pushed into BHE. An agent can create a job, upload one or more
  collection files to it, then close the job to trigger ingest.
- **Clients** — managed collectors (Enterprise feature). The tools
  let an agent enumerate them, view their job history, and trigger
  scheduled collection runs.
"""

from __future__ import annotations

import json
import typing as t
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method

from runtime.client import BHEAPIError, get_client


class DataTools(Toolset):
    """Search the graph and manage data ingestion."""

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    @tool_method(name="search_graph", catch=True)
    async def search_graph(
        self,
        query: t.Annotated[
            str,
            "Free-text query — matched against names and object ids "
            "across every node kind.",
        ],
        kind: t.Annotated[
            str,
            "Optional kind filter (User, Computer, Group, Domain, "
            "OU, GPO, AZUser, AZGroup, ...). Empty for all.",
        ] = "",
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 50,
    ) -> str:
        """Resolve human-readable names to graph nodes.

        The first move when you have ``"jdoe@example.com"`` and need
        an object_id to feed into the entity / cypher tools.
        """
        if not query.strip():
            return "error: query is empty"
        params: dict[str, t.Any] = {"q": query, "skip": skip, "limit": limit}
        if kind:
            params["type"] = kind
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/graphs/search", params=params
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # File upload jobs
    # ------------------------------------------------------------------

    @tool_method(name="list_file_upload_jobs", catch=True)
    async def list_file_upload_jobs(
        self,
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 50,
    ) -> str:
        """List existing file-upload jobs.

        Useful during ingest debugging: each job carries its current
        status (Pending / Running / Complete / Failed) and the list
        of files associated with it.
        """
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/file-upload-jobs",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="create_file_upload_job", catch=True)
    async def create_file_upload_job(self) -> str:
        """Open a new file-upload job.

        Subsequent ``upload_collection_file`` calls reference the job
        id from this response. Close the job with
        ``end_file_upload_job`` once every file is uploaded — that
        triggers the ingestion pipeline.
        """
        client = get_client()
        try:
            data = await client.post_json("/api/v2/file-upload-jobs", json={})
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="upload_collection_file", catch=True)
    async def upload_collection_file(
        self,
        job_id: t.Annotated[str, "Id from create_file_upload_job"],
        path: t.Annotated[
            str,
            "Local filesystem path to the collection file. Typically a "
            "SharpHound .zip or AzureHound .json.",
        ],
    ) -> str:
        """Push one collection file into a pending upload job.

        BHE accepts SharpHound zips and AzureHound JSON. Listing
        accepted types via ``accepted_upload_types`` is the safe
        first step.
        """
        if not job_id:
            return "error: job_id is required"
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            return f"error: not a file: {file_path}"
        body = file_path.read_bytes()
        # The endpoint sniffs content-type from the body; pass the
        # body verbatim so the magic-byte detection works.
        client = get_client()
        headers = {"Content-Type": _guess_content_type(file_path)}
        try:
            response = await client.post(
                f"/api/v2/file-upload-jobs/{job_id}/files",
                data=body,
                headers=headers,
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        if response.status_code >= 400:
            return f"error: HTTP {response.status_code}: {response.text[:300]}"
        return json.dumps(
            {
                "job_id": job_id,
                "filename": file_path.name,
                "size": len(body),
                "status": "uploaded",
            },
            indent=2,
            default=str,
        )

    @tool_method(name="end_file_upload_job", catch=True)
    async def end_file_upload_job(
        self,
        job_id: t.Annotated[str, "Id of the job to close"],
    ) -> str:
        """Close a file-upload job and trigger ingestion.

        BHE marks the job complete and queues the uploaded files
        for processing. Use ``list_file_upload_jobs`` to watch the
        status afterwards.
        """
        if not job_id:
            return "error: job_id is required"
        client = get_client()
        try:
            await client.delete_json(f"/api/v2/file-upload-jobs/{job_id}")
        except BHEAPIError as exc:
            return f"error: {exc}"
        return f"closed file upload job {job_id}"

    @tool_method(name="accepted_upload_types", catch=True)
    async def accepted_upload_types(self) -> str:
        """List the file types BHE will accept for uploads."""
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/file-upload-jobs/accepted-types"
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # Managed clients (Enterprise)
    # ------------------------------------------------------------------

    @tool_method(name="list_clients", catch=True)
    async def list_clients(
        self,
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 50,
    ) -> str:
        """List managed collection clients on the BHE deployment."""
        client = get_client()
        try:
            data = await client.get_json(
                "/api/v2/clients", params={"skip": skip, "limit": limit}
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="list_client_jobs", catch=True)
    async def list_client_jobs(
        self,
        client_id: t.Annotated[str, "Client id"],
        skip: t.Annotated[int, "Pagination offset"] = 0,
        limit: t.Annotated[int, "Cap on rows returned"] = 50,
    ) -> str:
        """Completed collection jobs for a specific client."""
        if not client_id:
            return "error: client_id is required"
        client = get_client()
        try:
            data = await client.get_json(
                f"/api/v2/clients/{client_id}/jobs",
                params={"skip": skip, "limit": limit},
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)

    @tool_method(name="schedule_collection_job", catch=True)
    async def schedule_collection_job(
        self,
        client_id: t.Annotated[str, "Client id"],
        ad_structure_collection: t.Annotated[
            bool, "Collect AD nodes / edges"
        ] = True,
        local_group_collection: t.Annotated[
            bool, "Collect local-group + session data"
        ] = False,
        session_collection: t.Annotated[bool, "Collect session data"] = False,
    ) -> str:
        """Queue a collection job for a managed client.

        The flags toggle which collection method runs. Defaults
        match the conservative "structure only" setting that
        doesn't poke endpoints — flip the others on for richer
        data when you've coordinated with the AD admin.
        """
        if not client_id:
            return "error: client_id is required"
        body = {
            "session_collection": session_collection,
            "local_group_collection": local_group_collection,
            "ad_structure_collection": ad_structure_collection,
        }
        client = get_client()
        try:
            data = await client.post_json(
                f"/api/v2/clients/{client_id}/jobs", json=body
            )
        except BHEAPIError as exc:
            return f"error: {exc}"
        return json.dumps(data, indent=2, default=str)


def _guess_content_type(path: Path) -> str:
    """Best-effort content-type sniffing for upload bodies."""
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return "application/zip"
    if suffix == ".json":
        return "application/json"
    return "application/octet-stream"
