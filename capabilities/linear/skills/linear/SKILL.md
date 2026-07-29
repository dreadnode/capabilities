---
name: linear
description: Use when the user wants to connect to Linear, search or read Linear issues / projects / cycles, create or update issues, or set up Linear auth. The connector — not the triage workflow.
---

# Linear

Connector for Linear via its official remote MCP server. The agent sees the tool
surface once it loads — this skill covers auth, scope, the filter model, and the
idioms. Security triage methodology — dedup, severity, SLA, owner inference — is
deliberately out of scope; pair this with whichever triage capability your
workflow uses.

## Auth

Native HTTP MCP with spec-compliant OAuth (RFC 8414 + 9728 + DCR + PKCE S256); the
runtime drives the flow — no `mcp-remote` bridge.

### A. Interactive OAuth (default; individual users)

On first connect, `linear` shows in the Services screen as `needs authentication`.
Click **Authenticate** → browser → approve; tokens persist to
`~/.dreadnode/mcp-auth.json` (mode 0600, keyed by server URL) and refresh silently.
To switch workspaces or after revoking access, Services → `linear` →
**Re-authenticate** (clears just this server's tokens). For SSH/headless, set
`DREADNODE_HEADLESS=1`; the auth URL is logged — complete it on a machine with a
browser and forward the callback port it prints (`ssh -R <port>:localhost:<port>`).

### B. API key (service / agent accounts)

For unattended use, **just set one secret** — no manifest edit. The server entry
carries an optional `Authorization` header bound to `LINEAR_API_KEY`: set it and the
static token wins, leave it unset and OAuth (A) stays default.

1. Linear → **Settings → Account → Security & Access** → generate a key. Per-key
   permissions (Read / Write / Admin) and team scoping are supported — pick **Read**
   + one team for enforced, least-privilege read-only.
2. Add `LINEAR_API_KEY` in the **secrets screen** (`/secrets` or `F7`) or web app,
   reload, confirm with `dn secret list`. Don't paste keys into chat.

> **Agent identity.** When the consumer is an agent / service, prefer an OAuth app
> install with `actor=app` over a personal key — actions attribute to the app, not
> the installing user, and it doesn't burn a billable seat.
> <https://linear.app/developers/oauth-actor-authorization>.

Scope is enforced by the **key or OAuth grant** — the tool surface is identical
either way, so a write-scoped key can mutate. Want read-only? Issue a read-only key.

## Filters & idioms

No JQL-style string — structured search with `team`, `state`, `assignee`, `project`,
`priority`, `labels`, plus a free-text `query`. Compose by argument, not a query
string. Reference: <https://linear.app/developers/graphql#filtering>.

- `ABC-123` (team prefix + number) is the canonical identifier — prefer it over
  free-text when the user has it. Internal numeric IDs are a different thing and
  rarely what the user means.
- `query` is broad — narrow with `team` / `state` / `project` rather than stuffing
  keywords in.
- Use the team's **actual** workflow state names (list them with the team-info tool);
  don't guess. Same for labels / projects before creating.
- Cycles are time-boxed — "the current cycle" shifts between calls.
