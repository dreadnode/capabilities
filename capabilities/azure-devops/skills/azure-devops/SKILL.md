---
name: azure-devops
description: Use when the user wants to connect to Azure DevOps — query Boards work items with WIQL, read PRs, inspect pipeline runs, create or update work items and wiki pages, or set up ADO auth. The connector — not security tradecraft.
---

# Azure DevOps

Connector for Azure DevOps (Boards, Repos, Pipelines, Wiki, Test Plans) via
Microsoft's official MCP server. The agent sees the enabled tool surface (~76
tools on the shipped domains) once it loads — this skill covers auth, the domain
/ toolset model, WIQL, and the idioms. Security triage methodology — dedup,
severity, SLA, owner inference — is deliberately out of scope; pair this with
whichever triage capability your workflow uses.

## Auth

The manifest pins `--authentication azcli`, so the MCP **delegates to your existing
Azure CLI session** — no token to paste, no per-call browser prompt.

1. Install Azure CLI: <https://learn.microsoft.com/cli/azure/install-azure-cli>.
2. `az login` with an account that can reach the target ADO org.
3. Set `ADO_ORG` (the org **name**, e.g. `contoso`, not the URL) in the **secrets
   screen** (`/secrets` or `F7`) or your launching shell. Optionally `ADO_PROJECT` /
   `ADO_TEAM` — when a tool needs a project or team and the call didn't name one,
   the server elicits a picker; these answer it up front. Needs the pinned
   `@azure-devops/mcp` ≥ 2.8.0; they are inert on older builds.
4. The `checks:` fail fast if `az` is missing or `az account show` is empty — by
   design, since `azcli` has nothing to delegate to without a live session.

First tool call may show a one-time org-consent browser prompt — that's Microsoft's
MSAL flow, not ours.

To switch modes, edit `--authentication` in `capability.yaml`:

| Mode | What | When |
|---|---|---|
| `azcli` (default) | Reuses the `az login` token | Box already signed into Azure CLI |
| `interactive` | Browser sign-in to Entra | No CLI session; human present |
| `pat` | base64 PAT from `PERSONAL_ACCESS_TOKEN` | Headless / non-Entra orgs |
| `envvar` | Raw bearer from `ADO_MCP_AUTH_TOKEN` | Token minted elsewhere |

Read vs write is enforced by **project roles** — a read-only principal can't mutate;
no in-band toggle. (The remote preview at `https://mcp.dev.azure.com/{org}` is
Entra-OAuth-only and doesn't support Claude Code yet — the local server is the right
default.)

## Toolset domains — keep the surface small

The upstream defaults to `all` (90 tools); the capability narrows that to 76 via
`-d`. Add domains as **separate list items** in `capability.yaml`, then reload
(`/capabilities` → reload) — a single comma-joined string is read as one unknown
domain and silently reverts to all 90.

| Domain | Shipped | Adds |
|---|---|---|
| `core` | ✅ | Project / team / org discovery (keep on) |
| `work` | ✅ | Iterations, teams, capacity |
| `work-items` | ✅ | Boards CRUD, WIQL |
| `repositories` | ✅ | Repos and PRs |
| `wiki` | ✅ | Wiki pages |
| `pipelines` | ✅ | Build / release runs, logs, artifacts |
| `test-plans` | — | Test plans and suites (+9 tools) |
| `search` | — | Cross-org search |
| `advanced-security` | — | GHAS alerts via `advsec_get_alerts` / `advsec_get_alert_details` (+2) — the only way to read them here, and they need GHAS licensed on the org |

## WIQL & idioms

WIQL is the SQL-shaped DSL for Boards; `@project` and `@me` are useful built-ins:

```sql
SELECT [System.Id], [System.Title], [System.State] FROM workitems
WHERE [System.TeamProject] = @project AND [System.WorkItemType] = 'Bug'
  AND [System.State] <> 'Closed' ORDER BY [Microsoft.VSTS.Common.Priority]
```

<https://learn.microsoft.com/azure/devops/boards/queries/wiql-syntax>

- Filtered work-item reads are a **two-step chain**: `wit_query_by_wiql` (or
  `wit_my_work_items`) returns IDs → `wit_get_work_items_batch_by_ids` hydrates them.
- Work-item IDs are **org-wide** integers (`wit_get_work_item, id=…`).
- `System.AreaPath` uses backslashes — escape them in JSON (`"Contoso\\Auth\\Identity"`).
  Don't invent area paths / iterations; list them first.
- GHAS alerts (advanced-security domain) come from `advsec_get_alerts`.
