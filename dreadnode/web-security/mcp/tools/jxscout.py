"""jxscout tools — wraps jxscout-pro-v2 CLI and project SQLite databases.

Provides JS analysis data: match queries, file listings, wordlist generation,
findings, bookmarks, repeater, and asset relationships. Uses the CLI for
write operations and complex queries, SQLite for fast reads.

Requires:
  - jxscout-pro-v2 binary on the host
  - sqlite3 (stdlib, for fast database reads)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP

JXSCOUT_HOME = Path.home() / ".jxscout-pro"
JXSCOUT_BINARY = os.environ.get("JXSCOUT_BINARY", "jxscout-pro-v2")
MAX_OUTPUT_CHARS = 50_000


def _find_binary() -> str | None:
    if shutil.which(JXSCOUT_BINARY):
        return JXSCOUT_BINARY
    for candidate in [
        Path.home() / "go" / "bin" / "jxscout-pro-v2",
        Path.home() / "bin" / "jxscout-pro-v2",
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def _project_db(project: str) -> Path:
    return JXSCOUT_HOME / "projects" / project / "project.db"


def _query_db(project: str, sql: str, params: tuple = ()) -> list[tuple]:
    db_path = _project_db(project)
    if not db_path.exists():
        raise FileNotFoundError(f"Project '{project}' not found at {db_path}")
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


async def _run_cli(args: list[str], timeout: int = 30) -> str:
    binary = _find_binary()
    if not binary:
        return "Error: jxscout-pro-v2 binary not found. Set JXSCOUT_BINARY env var."
    proc = await asyncio.create_subprocess_exec(
        binary, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return f"Error: command timed out after {timeout}s"
    output = stdout.decode(errors="replace")
    if proc.returncode != 0:
        err = stderr.decode(errors="replace")
        return f"Error (exit {proc.returncode}): {err}"
    return output[:MAX_OUTPUT_CHARS]


def register(mcp: FastMCP) -> None:
    """Register all jxscout tools on the given FastMCP server."""

    # ------------------------------------------------------------------
    # Database query tools (fast, no binary needed)
    # ------------------------------------------------------------------

    @mcp.tool
    async def jxscout_list_projects() -> str:
        """List all jxscout projects."""
        projects_dir = JXSCOUT_HOME / "projects"
        if not projects_dir.exists():
            return "No jxscout projects found."
        projects = sorted(
            d.name for d in projects_dir.iterdir()
            if d.is_dir() and (d / "project.db").exists()
        )
        if not projects:
            return "No jxscout projects found."
        return "\n".join(projects)

    @mcp.tool
    async def jxscout_match_summary(
        project: Annotated[str, "Project name (e.g. 'postman')"],
    ) -> str:
        """Get match counts by kind for a project — start here for recon."""
        try:
            rows = _query_db(
                project,
                "SELECT match_kind, COUNT(*) as cnt FROM matches GROUP BY match_kind ORDER BY cnt DESC;",
            )
        except FileNotFoundError as e:
            return str(e)
        if not rows:
            return "No matches found."
        return "\n".join(f"{kind}\t{count}" for kind, count in rows)

    @mcp.tool
    async def jxscout_security_matches(
        project: Annotated[str, "Project name"],
        limit: Annotated[int, "Maximum results"] = 100,
    ) -> str:
        """Get all security-relevant matches (XSS sinks, secrets, postMessage, etc.) with file paths."""
        security_kinds = (
            "html_manipulation", "dangerously_set_inner_html", "window_onmessage",
            "post_message", "location_assignment", "jwt", "github_pat",
            "stripe_secret_key", "private_key", "sensitive_property_name",
            "hostname", "graphql",
        )
        placeholders = ",".join("?" * len(security_kinds))
        try:
            rows = _query_db(
                project,
                f"""SELECT m.match_kind, m.match_value,
                    CASE ar.file_type
                      WHEN 'js' THEN (SELECT fs_path FROM js_files WHERE id = ar.file_id)
                      WHEN 'html' THEN (SELECT fs_path FROM html_files WHERE id = ar.file_id)
                      WHEN 'reversed_source' THEN (SELECT reversed_fs_path FROM source_map_reversed_files WHERE id = ar.file_id)
                    END as file_path
                  FROM matches m
                  JOIN analysis_run ar ON m.analysis_run_id = ar.id
                  WHERE m.match_kind IN ({placeholders})
                  LIMIT ?;""",
                (*security_kinds, limit),
            )
        except FileNotFoundError as e:
            return str(e)
        if not rows:
            return "No security-relevant matches found."
        return "\n".join(f"{kind}\t{value}\t{path or '(unknown)'}" for kind, value, path in rows)[:MAX_OUTPUT_CHARS]

    @mcp.tool
    async def jxscout_list_files(
        project: Annotated[str, "Project name"],
        file_type: Annotated[str, "File type: 'js', 'html', or 'reversed_source'"] = "js",
        limit: Annotated[int, "Maximum results"] = 50,
    ) -> str:
        """List files tracked by jxscout for a project."""
        table_map = {
            "js": ("js_files", "id, url, fs_path"),
            "html": ("html_files", "id, url, fs_path"),
            "reversed_source": ("source_map_reversed_files", "id, reversed_fs_path, source_map_file_id"),
        }
        if file_type not in table_map:
            return f"Error: file_type must be one of: {', '.join(table_map.keys())}"
        table, cols = table_map[file_type]
        try:
            rows = _query_db(project, f"SELECT {cols} FROM {table} LIMIT ?;", (limit,))
        except FileNotFoundError as e:
            return str(e)
        if not rows:
            return f"No {file_type} files found."
        return "\n".join("\t".join(str(c) for c in row) for row in rows)

    # ------------------------------------------------------------------
    # CLI wrapper tools (jxscout-pro-v2 -c)
    # ------------------------------------------------------------------

    @mcp.tool
    async def jxscout_list_match_kinds(
        project: Annotated[str, "Project name"],
    ) -> str:
        """List all match kinds available in a project."""
        return await _run_cli(["-c", "list-match-kinds", "--project-name", project, "--json"])

    @mcp.tool
    async def jxscout_get_matches(
        project: Annotated[str, "Project name"],
        match_kind: Annotated[str, "Match kind (e.g. 'api_path', 'hostname', 'jwt', 'html_manipulation')"],
        limit: Annotated[int, "Maximum results"] = 50,
        show_only_unseen: Annotated[bool, "Only show unreviewed matches"] = False,
        value_include: Annotated[str | None, "Filter: match value must contain this string"] = None,
    ) -> str:
        """Get matches by kind with file paths and positions (JSON output)."""
        args = ["-c", "get-matches", "--project-name", project, "--match-kind", match_kind, "--json", "--limit", str(limit)]
        if show_only_unseen:
            args.append("--show-only-unseen")
        if value_include:
            args.extend(["--value-include", value_include])
        return await _run_cli(args)

    @mcp.tool
    async def jxscout_mark_matches_seen(
        project: Annotated[str, "Project name"],
        match_ids: Annotated[str | None, "Comma-separated match IDs to mark seen"] = None,
        match_kind: Annotated[str | None, "Mark all matches of this kind as seen"] = None,
    ) -> str:
        """Mark matches as seen/reviewed."""
        args = ["-c", "mark-matches-seen", "--project-name", project]
        if match_ids:
            args.extend(["--match-ids", match_ids])
        elif match_kind:
            args.extend(["--match-kind", match_kind])
        else:
            return "Error: provide either match_ids or match_kind"
        return await _run_cli(args)

    @mcp.tool
    async def jxscout_mark_matches_unseen(
        project: Annotated[str, "Project name"],
        match_ids: Annotated[str, "Comma-separated match IDs to mark unseen"],
    ) -> str:
        """Mark matches as unseen for re-review."""
        return await _run_cli(["-c", "mark-matches-unseen", "--project-name", project, "--match-ids", match_ids])

    @mcp.tool
    async def jxscout_wordlist(
        project: Annotated[str, "Project name"],
        limit: Annotated[int, "Maximum words"] = 200,
        sort_by_count: Annotated[bool, "Sort by occurrence count"] = True,
    ) -> str:
        """Generate a fuzzing wordlist from JS analysis."""
        args = ["-c", "wordlist", "--project-name", project, "--limit", str(limit)]
        if sort_by_count:
            args.append("--sort-by-count")
        return await _run_cli(args)

    @mcp.tool
    async def jxscout_create_finding(
        project: Annotated[str, "Project name"],
        kind: Annotated[str, "Finding kind (e.g. 'xss', 'secret', 'idor')"],
        severity: Annotated[str, "Severity: low, medium, high, critical"],
        description: Annotated[str, "Finding description"],
        dedup_key: Annotated[str | None, "Deduplication key"] = None,
    ) -> str:
        """Create a finding in jxscout."""
        args = ["-c", "create-finding", "--project-name", project, "--kind", kind, "--severity", severity, "--description", description]
        if dedup_key:
            args.extend(["--dedup-key", dedup_key])
        return await _run_cli(args)

    @mcp.tool
    async def jxscout_get_findings(
        project: Annotated[str, "Project name"],
    ) -> str:
        """List all findings in a project."""
        return await _run_cli(["-c", "get-findings", "--project-name", project])

    @mcp.tool
    async def jxscout_get_finding(
        project: Annotated[str, "Project name"],
        finding_id: Annotated[int, "Finding ID"],
    ) -> str:
        """Get a specific finding by ID."""
        return await _run_cli(["-c", "get-finding", "--project-name", project, "--finding-id", str(finding_id)])

    @mcp.tool
    async def jxscout_analyze_file(
        project: Annotated[str, "Project name"],
        file_path: Annotated[str, "Path to JS or HTML file"],
        file_type: Annotated[str, "File type: js, html, reversed_source"] = "js",
    ) -> str:
        """Run ad-hoc analysis on a file."""
        return await _run_cli(["-c", "analyze", "--project-name", project, "--file-type", file_type, file_path], timeout=60)

    @mcp.tool
    async def jxscout_get_loaded_js_files(
        project: Annotated[str, "Project name"],
        page_url: Annotated[str, "Page URL to check which JS files it loads"],
    ) -> str:
        """Get JS files loaded by a specific page URL."""
        return await _run_cli(["-c", "get-loaded-js-files", "--project-name", project, page_url, "--json"])

    @mcp.tool
    async def jxscout_get_js_file_loader_page(
        project: Annotated[str, "Project name"],
        file_path: Annotated[str, "Path to JS file"],
    ) -> str:
        """Get which pages load a specific JS file."""
        return await _run_cli(["-c", "get-js-file-loader-page", "--project-name", project, file_path, "--json"])

    @mcp.tool
    async def jxscout_get_loaded_iframes(
        project: Annotated[str, "Project name"],
        page_url: Annotated[str, "Page URL to check for embedded iframes"],
    ) -> str:
        """Get iframes embedded by a specific page."""
        return await _run_cli(["-c", "get-loaded-iframes", "--project-name", project, page_url, "--json"])

    @mcp.tool
    async def jxscout_get_related_assets(
        project: Annotated[str, "Project name"],
        file_path: Annotated[str, "Path to file"],
    ) -> str:
        """Get full relationship graph for a file."""
        return await _run_cli(["-c", "get-related-assets", "--project-name", project, file_path, "--json"])

    @mcp.tool
    async def jxscout_bookmark_create_group(
        project: Annotated[str, "Project name"],
        name: Annotated[str, "Bookmark group name"],
    ) -> str:
        """Create a bookmark group."""
        return await _run_cli(["-c", "bookmark", "create-group", "--project-name", project, "--name", name])

    @mcp.tool
    async def jxscout_bookmark_create(
        project: Annotated[str, "Project name"],
        group: Annotated[str, "Bookmark group name"],
        file_path: Annotated[str, "Path to file"],
        start_line: Annotated[int, "Start line number"],
        end_line: Annotated[int, "End line number"],
        note: Annotated[str | None, "Note explaining why this code is interesting"] = None,
        start_column: Annotated[int, "Start column"] = 0,
        end_column: Annotated[int, "End column"] = 0,
    ) -> str:
        """Create a bookmark on a code location."""
        args = [
            "-c", "bookmark", "create", "--project-name", project,
            "--group", group, "--file-path", file_path,
            "--start-line", str(start_line), "--start-column", str(start_column),
            "--end-line", str(end_line), "--end-column", str(end_column),
        ]
        if note:
            args.extend(["--note", note])
        return await _run_cli(args)

    @mcp.tool
    async def jxscout_repeater(
        project: Annotated[str, "Project name"],
        request_file: Annotated[str, "Path to .req file to send"],
    ) -> str:
        """Send a raw HTTP request via jxscout repeater."""
        return await _run_cli(["-c", "repeater", "--project-name", project, request_file], timeout=30)

    @mcp.tool
    async def jxscout_retrigger_events(
        project: Annotated[str, "Project name"],
        subscriber: Annotated[str, "Subscriber to retrigger (e.g. 'analyzer')"],
    ) -> str:
        """Retrigger events for a subscriber (e.g. after adding custom analyzers)."""
        return await _run_cli(["-c", "retrigger-events", "--project-name", project, "--subscriber", subscriber], timeout=120)

    @mcp.tool
    async def jxscout_print_settings(
        project: Annotated[str, "Project name"],
    ) -> str:
        """Print the full resolved project settings."""
        return await _run_cli(["-c", "print-full-project-settings", "--project-name", project])
