---
name: ghostwriter-readonly
description: Use when reviewing GhostWriter data in read-only mode — clients, projects, findings, objectives, targets, scope, deconflictions, evidence, observations, reports, infrastructure, activity logs, and notes.
---

# GhostWriter Read-Only Viewer

Query GhostWriter reporting and operational data without modifying state.

## Configuration

Set env vars before use: `GHOSTWRITER_URL`, `GHOSTWRITER_API_TOKEN` (or `GHOSTWRITER_USERNAME` + `GHOSTWRITER_PASSWORD`).

## Usage

```bash
uv run {baseDir}/scripts/ghostwriter_read.py <command> [options]
```

## Orientation Workflow

```bash
uv run {baseDir}/scripts/ghostwriter_read.py status
uv run {baseDir}/scripts/ghostwriter_read.py clients
uv run {baseDir}/scripts/ghostwriter_read.py projects
uv run {baseDir}/scripts/ghostwriter_read.py objectives --project 1
uv run {baseDir}/scripts/ghostwriter_read.py targets --project 1
uv run {baseDir}/scripts/ghostwriter_read.py findings --project 1
uv run {baseDir}/scripts/ghostwriter_read.py activity-logs --project 1
```

## Commands

| Command | Description |
|---------|-------------|
| `status` | Connection info and authentication check |
| `clients [--limit N]` | List client organizations |
| `client <id>` | Full details for one client (JSON) |
| `projects [--client N] [--limit N]` | List projects/engagements |
| `project <id>` | Full project details with associated findings |
| `findings [--project N] [--severity S] [--limit N] [--offset N]` | List reported findings |
| `finding <id>` | Full finding details (JSON) |
| `finding-templates [--severity S] [--limit N]` | Finding template library |
| `objectives [--project N] [--limit N]` | Project objectives and sub-tasks |
| `targets [--project N] [--limit N]` | Target hosts/systems |
| `scope [--project N] [--limit N]` | Scope definitions (IP ranges, etc.) |
| `deconflictions [--project N] [--limit N]` | Deconfliction entries |
| `evidence [--project N] [--finding N] [--limit N]` | Evidence files |
| `whitecards [--project N] [--limit N]` | White cards / exceptions |
| `observations [--project N] [--limit N] [--offset N]` | Observations/notes |
| `reports [--project N] [--limit N]` | List reports |
| `infrastructure [--project N]` | Summary of servers and domains |
| `servers [--project N] [--limit N]` | List team servers |
| `domains [--project N] [--limit N]` | List registered domains |
| `activity-logs [--project N] [--limit N] [--offset N]` | Operation activity logs |
| `notes <type> [--parent-id N] [--limit N]` | Notes (type: client, project, domain, server) |
| `search <term> [--types ...] [--limit N]` | Cross-type search |

## Global Flags

- `--detail` / `-d` — full raw JSON output (all fields, metadata, everything)
- `--json` — machine-parseable JSON output

## Summary vs Detail

Default output is compact text tables. Use `--detail` or `--json` when you need full data for reporting analysis (full finding descriptions, remediation text, raw evidence metadata).

## Read-Only

This tool CANNOT create, modify, or delete any GhostWriter data. The only mutation used is the Login mutation to obtain a JWT token for authentication.
