---
name: mythic-c2-readonly
description: Use when reviewing Mythic C2 operation data in read-only mode — viewing callbacks, task history, credentials, files, artifacts, and other collected data.
---

# Mythic Read-Only Viewer

Query Mythic C2 operation data without executing commands or modifying state.

## Configuration

Set env vars before use: `MYTHIC_SERVER_IP`, `MYTHIC_SERVER_PORT`, `MYTHIC_PASSWORD` (or `MYTHIC_API_TOKEN`).

## Usage

```bash
uv run {baseDir}/scripts/mythic_read.py <command> [options]
```

## Orientation Workflow

```bash
uv run {baseDir}/scripts/mythic_read.py status
uv run {baseDir}/scripts/mythic_read.py callbacks --active
uv run {baseDir}/scripts/mythic_read.py tasks --callback 1
uv run {baseDir}/scripts/mythic_read.py credentials
uv run {baseDir}/scripts/mythic_read.py files
```

## Commands

| Command | Description |
|---------|-------------|
| `status` | Connection info and current operation |
| `callbacks [--active]` | List callbacks (agents) |
| `callback <id>` | Full details for one callback (JSON) |
| `tasks [--callback N] [--limit N] [--offset N]` | List executed commands |
| `task-output <id> [--max-lines N] [--offset N]` | Decoded task output with line paging |
| `credentials [--limit N] [--offset N]` | Discovered credentials |
| `files [--uploaded] [--limit N]` | Downloaded/uploaded files |
| `file-contents <uuid>` | Save file to /tmp/mythic-readonly/ + preview |
| `artifacts [--limit N] [--offset N]` | IOCs/artifacts |
| `keylogs [--callback N] [--limit N]` | Keylog captures |
| `screenshots [--limit N]` | Screenshot metadata |
| `processes [--host NAME] [--limit N]` | Process listings |
| `file-browser [--host NAME] [--path PREFIX] [--limit N]` | File system data |
| `tokens [--callback N] [--limit N]` | Windows token data |
| `search <term> [--types tasks,credentials,...] [--limit N]` | Cross-type search |

## Global Flags

- `--detail` / `-d` — full raw JSON output (SIDs, DACLs, metadata, everything)
- `--json` — machine-parseable JSON output

## Working with Large Outputs

Task output supports line-based paging:
```bash
uv run {baseDir}/scripts/mythic_read.py task-output 5 --max-lines 50
uv run {baseDir}/scripts/mythic_read.py task-output 5 --max-lines 50 --offset 50
```

File contents are saved to disk — use the Read tool for targeted access:
```bash
uv run {baseDir}/scripts/mythic_read.py file-contents <uuid>
# Then use: Read("/tmp/mythic-readonly/<uuid>", offset=100, limit=50)
```

## Summary vs Detail

Default output is compact text tables. Use `--detail` or `--json` when you need full data for security analysis (token internals, raw artifacts, full process metadata).

## Read-Only

This tool CANNOT execute commands, modify callbacks, create tasks, or change any Mythic state.
