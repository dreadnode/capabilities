#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "fastmcp>=2.0",
#   "mvt>=2.5",
# ]
# ///
"""MVT (Mobile Verification Toolkit) MCP server — iOS forensics over
iTunes/Finder backups and full-filesystem extractions.

Thin Python MCP wrapper around the `mvt-ios` CLI. This does not vendor
or modify a local MVT install. It resolves the command in this order:

  1. MVT_COMMAND, if set (full command string, e.g. "mvt-ios")
  2. mvt-ios on PATH
  3. python -m mvt.ios (via sys.executable) — works because this
     script's PEP 723 deps install mvt into the uv-managed venv

Module output is requested as JSON — MVT writes one JSON file per
module into the `--output` directory. Tool results return a parsed
`{module: records}` dict, with a `_detected` sibling entry whenever a
STIX IoC file is supplied.

MVT distinguishes two source kinds:
  - iTunes/Finder backup directory  (check-backup)
  - Full-filesystem extraction      (check-fs)

Most modules run on backups; a handful (shutdown_log, analytics,
certain WebKit logs) require an FFS. Pass the correct `source_kind`
for every call. Run `mvt_info` first to confirm the source is
readable and record device context.
"""

from __future__ import annotations

import asyncio
import json
import os
import plistlib
import shlex
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

from fastmcp import FastMCP

mcp = FastMCP("mvt")

MAX_OUTPUT_CHARS = int(os.environ.get("MVT_MAX_OUTPUT_CHARS", "200000"))
DEFAULT_TIMEOUT = int(os.environ.get("MVT_TIMEOUT", "900"))

SourceKind = Literal["backup", "fs"]


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n...[truncated]..."


def _resolve_command() -> list[str] | None:
    configured = os.environ.get("MVT_COMMAND")
    if configured:
        parts = shlex.split(configured)
        if parts and shutil.which(parts[0]):
            return parts
        return None

    if shutil.which("mvt-ios"):
        return ["mvt-ios"]

    # Fallback: invoke the mvt.ios module using the current interpreter.
    # The PEP 723 deps above guarantee mvt is importable under `uv run`.
    return [sys.executable, "-m", "mvt.ios"]


def _missing_dependency_message() -> str:
    return (
        "Error: mvt-ios is unavailable. Install it with:\n"
        "  pipx install mvt  (or)  uv tool install mvt\n"
        "Alternatively set MVT_COMMAND to an explicit command."
    )


def _subcommand(source_kind: SourceKind) -> str:
    return "check-backup" if source_kind == "backup" else "check-fs"


async def _run_mvt(
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
        stdin=asyncio.subprocess.DEVNULL,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, b"", f"Error: mvt-ios command timed out after {timeout}s"

    return (
        proc.returncode if proc.returncode is not None else 1,
        stdout,
        stderr.decode(errors="replace"),
    )


def _collect_module_json(output_dir: Path) -> dict[str, Any]:
    """Load every *.json file MVT wrote into the output dir."""
    results: dict[str, Any] = {}
    for path in sorted(output_dir.glob("*.json")):
        try:
            results[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            results[path.stem] = {"_raw": path.read_text(encoding="utf-8", errors="replace")}
    return results


async def _run_check(
    source: str,
    source_kind: SourceKind,
    *,
    module: str | None = None,
    iocs: str | None = None,
    fast: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    source_path = Path(source).expanduser()
    if not source_path.exists():
        return f"Error: source does not exist: {source_path}"
    if iocs is not None:
        iocs_path = Path(iocs).expanduser()
        if not iocs_path.exists():
            return f"Error: iocs file does not exist: {iocs_path}"

    with tempfile.TemporaryDirectory(prefix="mvt-out-") as tmp:
        args = [_subcommand(source_kind), "-o", tmp]
        if module:
            args.extend(["-m", module])
        if iocs is not None:
            args.extend(["-i", str(Path(iocs).expanduser())])
        if fast:
            args.append("-f")
        args.append(str(source_path))

        returncode, stdout, stderr = await _run_mvt(args, timeout=timeout)
        results = _collect_module_json(Path(tmp))
        logs = (stdout.decode(errors="replace") + stderr).strip()

    if returncode != 0 and not results:
        return _truncate(f"Error (exit {returncode}): {logs}")

    payload: dict[str, Any] = {"results": results}
    if returncode != 0:
        payload["partial"] = True
        payload["log_tail"] = logs[-4000:]
    return _truncate(json.dumps(payload, indent=2, default=str))


# ── MVT core tools ───────────────────────────────────────────────────


@mcp.tool
async def mvt_status() -> dict[str, Any]:
    """Report how the MCP would invoke mvt-ios on this host."""
    command = _resolve_command()
    return {
        "available": command is not None,
        "command": command,
        "timeout_seconds": DEFAULT_TIMEOUT,
        "max_output_chars": MAX_OUTPUT_CHARS,
        "hint": None if command else _missing_dependency_message(),
    }


@mcp.tool
async def mvt_info(
    source: Annotated[str, "Path to the iOS backup dir or FFS extraction"],
    source_kind: Annotated[
        SourceKind, "'backup' for iTunes/Finder backup, 'fs' for full-filesystem extraction"
    ] = "backup",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Device and acquisition metadata — call this first.

    Runs MVT's cheap identification module (`backup_info` for backups,
    `version_history` for FFS). Returns device name, iOS build, product
    type, serial, encryption state, and acquisition timestamp. Record
    this context and attach it to every finding downstream.
    """
    module = "backup_info" if source_kind == "backup" else "version_history"
    return await _run_check(source, source_kind, module=module, timeout=timeout)


@mcp.tool
async def mvt_list_modules(
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    timeout: Annotated[int, "Command timeout in seconds"] = 60,
) -> str:
    """List every MVT module available for the given source kind."""
    # mvt-ios requires a positional source path even with --list-modules;
    # an empty temp dir satisfies the CLI parser without ever being read.
    with tempfile.TemporaryDirectory(prefix="mvt-listmod-") as placeholder:
        args = [_subcommand(source_kind), "--list-modules", placeholder]
        returncode, stdout, stderr = await _run_mvt(args, timeout=timeout)
    text = stdout.decode(errors="replace")
    if returncode != 0:
        return _truncate(f"Error (exit {returncode}): {text}\n{stderr}")
    return _truncate(text or stderr)


@mcp.tool
async def mvt_decrypt_backup(
    source: Annotated[str, "Path to the encrypted iTunes backup directory"],
    destination: Annotated[str, "Destination directory for the decrypted copy"],
    password: Annotated[str, "Backup password"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Decrypt an encrypted iTunes/Finder backup into a working copy.

    Subsequent tool calls should use `destination` as their `source`.
    Wrong password surfaces as a non-zero exit with an MVT error log —
    no retry is attempted (so a typo doesn't burn a lockout budget on
    whatever rate-limited store holds the key material).

    The password is forwarded to mvt-ios as a CLI argument (its only
    accepted surface), which means it is briefly visible to local
    process listings while the subprocess runs.
    """
    src = Path(source).expanduser()
    dst = Path(destination).expanduser()
    if not src.exists():
        return f"Error: source does not exist: {src}"
    dst.mkdir(parents=True, exist_ok=True)
    args = ["decrypt-backup", "-d", str(dst), "-p", password, str(src)]
    returncode, stdout, stderr = await _run_mvt(args, timeout=timeout)
    log = (stdout.decode(errors="replace") + stderr).strip()
    if returncode != 0:
        return _truncate(f"Error (exit {returncode}): {log}")
    return _truncate(f"Decrypted backup written to {dst}\n\n{log}")


@mcp.tool
async def mvt_check_iocs(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    iocs: Annotated[str, "Path to a STIX2 IoC file (e.g. Amnesty / Citizen Lab release)"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    fast: Annotated[bool, "Skip slow modules for a quicker sweep"] = False,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Run every module and correlate against a STIX IoC file.

    This is the primary spyware-hunting primitive. Amnesty's published
    STIX feeds cover Pegasus, Predator, QuaDream, RCS, and other
    mercenary spyware. Detections appear as `<module>_detected` keyed
    entries alongside the raw module output.
    """
    return await _run_check(source, source_kind, iocs=iocs, fast=fast, timeout=timeout)


@mcp.tool
async def mvt_run_module(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    module: Annotated[str, "MVT module name (see mvt_list_modules)"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file to correlate against"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Run a single MVT module — escape hatch for the long tail.

    Use curated wrappers first. Reach for this for modules like
    `webkit_session_resource_log`, `id_status_cache`, `net_usage`,
    `shortcuts`, `chrome_history`, `contacts`, `cookies`, etc.
    """
    return await _run_check(source, source_kind, module=module, iocs=iocs, timeout=timeout)


# ── Curated module wrappers ──────────────────────────────────────────


@mcp.tool
async def mvt_installed_apps(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Installed applications (applications module) — bundle IDs, versions.

    IoC correlation flags bundle IDs associated with commercial spyware
    (e.g. known Predator / Hermit loader identifiers).
    """
    return await _run_check(source, source_kind, module="applications", iocs=iocs, timeout=timeout)


@mcp.tool
async def mvt_sms_messages(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """SMS / iMessage messages and embedded URLs (sms module).

    With --iocs, flags messages whose URLs match known spyware
    delivery infrastructure (Pegasus one-click / zero-click vectors).
    """
    return await _run_check(source, source_kind, module="sms", iocs=iocs, timeout=timeout)


@mcp.tool
async def mvt_calls(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' recommended — CallHistory.storedata lives in HomeDomain"] = "backup",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Call history from CallHistory.storedata (calls module)."""
    return await _run_check(source, source_kind, module="calls", timeout=timeout)


@mcp.tool
async def mvt_safari_history(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Safari browsing history (safari_history module).

    Pair with `mvt_run_module safari_browser_state` and
    `webkit_session_resource_log` (FFS) for full WebKit visibility.
    """
    return await _run_check(source, source_kind, module="safari_history", iocs=iocs, timeout=timeout)


@mcp.tool
async def mvt_configuration_profiles(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Installed configuration profiles (configuration_profiles module).

    Rogue MDM / provisioning profiles are a primary iOS persistence
    vector for commercial spyware and targeted social-engineering.
    Anything unsigned, recently installed, or lacking a well-known
    enterprise issuer deserves scrutiny.
    """
    return await _run_check(source, source_kind, module="configuration_profiles", iocs=iocs, timeout=timeout)


@mcp.tool
async def mvt_tcc(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """TCC — Transparency, Consent, and Control grants (tcc module).

    Which apps were granted Location, Microphone, Camera, Contacts,
    Photos, AddressBook, Reminders. Unexpected grants to non-Apple
    apps — or to bundle IDs you don't recognize — are high-signal.
    """
    return await _run_check(source, source_kind, module="tcc", timeout=timeout)


@mcp.tool
async def mvt_datausage(
    source: Annotated[str, "Path to the backup dir or FFS extraction"],
    source_kind: Annotated[SourceKind, "'backup' or 'fs'"] = "backup",
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Per-process cellular data usage (datausage module).

    DataUsage.sqlite records bytes in/out per process. Unknown
    processes — especially those with short-lived rows and no matching
    entry in `applications` — are a classic Pegasus / Predator tell.
    """
    return await _run_check(source, source_kind, module="datausage", iocs=iocs, timeout=timeout)


@mcp.tool
async def mvt_shutdown_log(
    source: Annotated[str, "Path to the FFS extraction (FFS-only module)"],
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Parse /private/var/db/diagnostics shutdown.log (shutdown_log module).

    FFS-only. The shutdown log records processes that delayed shutdown,
    a well-known Pegasus side channel (CitizenLab / Kaspersky research
    surfaced multiple campaigns via anomalous shutdown-log entries).
    """
    return await _run_check(source, "fs", module="shutdown_log", timeout=timeout)


@mcp.tool
async def mvt_manifest(
    source: Annotated[str, "Path to an iTunes/Finder backup directory"],
    iocs: Annotated[str | None, "Optional STIX IoC file"] = None,
    timeout: Annotated[int, "Command timeout in seconds"] = DEFAULT_TIMEOUT,
) -> str:
    """Scan Manifest.db for suspicious domain/path entries (manifest module).

    Backup-only. MVT cross-references every file entry against its
    IoC domain/path rules; the module produces both the full file
    inventory and flagged hits.
    """
    return await _run_check(source, "backup", module="manifest", iocs=iocs, timeout=timeout)


# ── Backup-native content tools (no MVT) ─────────────────────────────


@mcp.tool
async def ios_backup_list(
    backup_dir: Annotated[str, "Path to an iTunes/Finder backup directory"],
    domain_filter: Annotated[
        str | None, "Exact domain match, e.g. 'HomeDomain' or 'AppDomain-com.apple.MobileSMS'"
    ] = None,
    path_substring: Annotated[str | None, "Case-insensitive substring to match against relativePath"] = None,
    limit: Annotated[int, "Maximum rows to return"] = 500,
) -> str:
    """List logical files in an iTunes backup via Manifest.db.

    Resolves the opaque `<hash>` on-disk layout back to the logical
    `{domain, relativePath}` keys. Use this to find the file you want
    before calling `ios_backup_extract`.
    """
    backup = Path(backup_dir).expanduser()
    manifest = backup / "Manifest.db"
    if not manifest.exists():
        return f"Error: Manifest.db not found at {manifest}"

    conditions: list[str] = []
    params: list[Any] = []
    if domain_filter:
        conditions.append("domain = ?")
        params.append(domain_filter)
    if path_substring:
        conditions.append("lower(relativePath) LIKE ?")
        params.append(f"%{path_substring.lower()}%")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"SELECT fileID, domain, relativePath, flags FROM Files {where} " f"ORDER BY domain, relativePath LIMIT ?"
    params.append(limit)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as exc:
        return f"Error: {exc}"
    finally:
        if conn is not None:
            conn.close()

    return _truncate(json.dumps([dict(r) for r in rows], indent=2, default=str))


@mcp.tool
async def ios_backup_extract(
    backup_dir: Annotated[str, "Path to an iTunes/Finder backup directory"],
    domain: Annotated[str, "Backup domain, e.g. 'HomeDomain'"],
    relative_path: Annotated[str, "File's relativePath in Manifest.db"],
    output_dir: Annotated[str, "Directory to copy the extracted file into"],
) -> str:
    """Extract a logical file from an iTunes backup by {domain, relativePath}.

    The resulting copy retains the original binary bytes — it's still
    a binary plist / SQLite / keychain blob / etc. Feed it into
    `ios_sqlite_query` or `ios_read_plist` as appropriate.
    """
    backup = Path(backup_dir).expanduser()
    manifest = backup / "Manifest.db"
    if not manifest.exists():
        return f"Error: Manifest.db not found at {manifest}"
    out = Path(output_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
        row = conn.execute(
            "SELECT fileID FROM Files WHERE domain = ? AND relativePath = ?",
            (domain, relative_path),
        ).fetchone()
    except sqlite3.Error as exc:
        return f"Error: {exc}"
    finally:
        if conn is not None:
            conn.close()

    if not row:
        return f"Error: no entry for ({domain}, {relative_path})"
    file_id = row[0]
    src = backup / file_id[:2] / file_id
    if not src.exists():
        return f"Error: backup file missing on disk: {src}"
    dst = out / f"{file_id}-{Path(relative_path).name}"
    shutil.copy2(src, dst)
    return json.dumps(
        {"file_id": file_id, "domain": domain, "relative_path": relative_path, "extracted": str(dst)},
        indent=2,
    )


def _no_attach_authorizer(action: int, *_: Any) -> int:
    # SQLITE_ATTACH = 24, SQLITE_DETACH = 25. mode=ro only constrains
    # the primary database; without this, a query could ATTACH a
    # different file and read it.
    if action in (24, 25):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


@mcp.tool
async def ios_sqlite_query(
    database: Annotated[str, "Path to a SQLite database file"],
    query: Annotated[str, "SQL query (opened read-only; writes/attaches are rejected by SQLite)"],
    limit: Annotated[int, "Maximum rows to return (applied after the query)"] = 500,
) -> str:
    """Run a read-only SQL query against a SQLite database.

    Use for extracted iOS artifacts: `sms.db`, `CallHistory.storedata`,
    `knowledgeC.db`, `Photos.sqlite`, `DataUsage.sqlite`, etc. The
    connection is opened with `mode=ro` and an authorizer that denies
    `ATTACH`/`DETACH`, so writes, attaches, and vacuum are rejected
    at the SQLite layer.
    """
    db_path = Path(database).expanduser()
    if not db_path.exists():
        return f"Error: database does not exist: {db_path}"
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.set_authorizer(_no_attach_authorizer)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchmany(limit)
    except sqlite3.Error as exc:
        return f"Error: {exc}"
    finally:
        if conn is not None:
            conn.close()
    return _truncate(json.dumps([dict(r) for r in rows], indent=2, default=str))


@mcp.tool
async def ios_read_plist(
    path: Annotated[str, "Path to a plist file (binary or XML)"],
    max_bytes: Annotated[int, "Refuse files larger than this (safety cap)"] = 5_000_000,
) -> str:
    """Read an Apple plist (binary or XML) and return it as JSON.

    Handles `Info.plist`, `Status.plist`, `Manifest.plist`,
    `com.apple.wifi.plist`, per-app preference plists, and any other
    standard plist the backup / FFS surfaces.
    """
    plist_path = Path(path).expanduser()
    if not plist_path.exists():
        return f"Error: plist does not exist: {plist_path}"
    size = plist_path.stat().st_size
    if size > max_bytes:
        return f"Error: plist is {size} bytes, exceeds cap {max_bytes}"
    try:
        with plist_path.open("rb") as fh:
            data = plistlib.load(fh)
    except (plistlib.InvalidFileException, ValueError) as exc:
        return f"Error: failed to parse plist: {exc}"
    return _truncate(json.dumps(data, indent=2, default=str))


if __name__ == "__main__":
    mcp.run(transport="stdio")
