---
name: mythic-c2-readonly
description: Use when reviewing Mythic C2 operation data in read-only mode — viewing callbacks, task history, credentials, files, artifacts, and other collected data.
---

# Mythic Read-Only MCP Server

Query Mythic C2 operation data without executing commands or modifying state. Credentials are configured in the server environment — they never appear in conversations.

## Configuration

Set env vars in the MCP server environment: `MYTHIC_SERVER_IP`, `MYTHIC_SERVER_PORT`, `MYTHIC_PASSWORD` (or `MYTHIC_API_TOKEN`).

## Orientation Workflow

1. `get_status` — verify connection and current operation
2. `list_callbacks --active_only` — see live agents
3. `list_tasks --callback_id N` — command history for a callback
4. `list_credentials` — discovered credentials
5. `list_files` — downloaded/uploaded files
6. `search "<term>"` — cross-type search

## Tools

| Tool | Purpose |
|------|---------|
| `get_status` | Connection info and current operation |
| `list_callbacks` | List callbacks (agents); filter with `active_only` |
| `get_callback` | Full details for a single callback |
| `list_tasks` | Executed commands (filter by callback, paginated) |
| `get_task_output` | Decoded task output with line paging |
| `list_credentials` | Discovered credentials |
| `list_files` | Downloaded/uploaded files |
| `get_file_contents` | Download file to /tmp/mythic-readonly/ + preview |
| `list_artifacts` | IOCs/artifacts |
| `list_keylogs` | Keylog captures |
| `list_screenshots` | Screenshot metadata |
| `list_processes` | Captured process listings |
| `list_file_browser` | File system data from agents |
| `list_tokens` | Windows token captures |
| `search` | Cross-type search (tasks, credentials, files, artifacts, keylogs) |

## Working with Large Outputs

`get_task_output` supports line-based paging via `max_lines` and `offset`. For big command output, request chunks rather than the whole thing.

`get_file_contents` saves the file to disk and returns a preview plus the path — use your Read tool on the saved path with offset/limit for targeted access to large files.

## Read-Only

This server CANNOT execute commands, modify callbacks, create tasks, or change any Mythic state.

## CLI Fallback

The original CLI script is still available at `scripts/mythic_read.py` for standalone use:
```bash
uv run {baseDir}/scripts/mythic_read.py <command> [options]
```
