---
name: ghostwriter-readonly
description: Use when reviewing GhostWriter data in read-only mode — clients, projects, findings, objectives, targets, scope, deconflictions, evidence, observations, reports, infrastructure, activity logs, and notes.
---

# GhostWriter Read-Only MCP Server

Query GhostWriter reporting and operational data without modifying state. Credentials are configured in the server environment — they never appear in conversations.

## Configuration

Set env vars in the MCP server environment: `GHOSTWRITER_URL`, `GHOSTWRITER_API_TOKEN` (or `GHOSTWRITER_USERNAME` + `GHOSTWRITER_PASSWORD`).

## Orientation Workflow

1. `get_status` — verify connection, see aggregate counts
2. `list_clients` — see client organizations
3. `list_projects` — see engagements (filter by client_id)
4. `list_objectives --project_id N` — project objectives
5. `list_targets --project_id N` — target hosts
6. `list_findings --project_id N` — reported findings
7. `list_activity_logs --project_id N` — oplog entries

## Tools

| Tool | Purpose |
|------|---------|
| `get_status` | Connection info and aggregate counts |
| `list_clients` | List client organizations |
| `get_client` | Full client details with projects |
| `list_projects` | List projects/engagements |
| `get_project` | Full project details with findings and reports |
| `list_findings` | List reported findings (filter by project, severity) |
| `get_finding` | Full finding details (CVSS, remediation, evidence) |
| `list_finding_templates` | Finding template library |
| `list_objectives` | Project objectives and sub-tasks |
| `list_targets` | Target hosts/systems |
| `list_scope` | Scope definitions (IP ranges, etc.) |
| `list_deconflictions` | Deconfliction entries |
| `list_evidence` | Evidence files (filter by project, finding) |
| `list_whitecards` | White cards / exceptions |
| `list_observations` | Observations from reports |
| `list_reports` | List reports |
| `get_infrastructure` | Combined server + domain summary |
| `list_servers` | Team servers with checkouts |
| `list_domains` | Registered domains with checkouts |
| `list_activity_logs` | Operation activity logs |
| `list_notes` | Notes (type: client, project, domain, server) |
| `search` | Cross-type search across multiple data types |

## Common Filters

Most list tools accept `project_id` to scope results to a single engagement and `limit` for pagination. `list_findings` and `list_activity_logs` also accept `offset`.

## Read-Only

This server CANNOT create, modify, or delete any GhostWriter data. The only mutation used is the Login mutation to obtain a JWT token when API token auth is not configured.

## CLI Fallback

The original CLI script is still available at `scripts/ghostwriter_read.py` for standalone use:
```bash
uv run {baseDir}/scripts/ghostwriter_read.py <command> [options]
```
