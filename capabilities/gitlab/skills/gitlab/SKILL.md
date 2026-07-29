---
name: gitlab
description: Use when the user wants to connect to GitLab — search or read issues / MRs / projects, create or update issues and MRs, inspect pipelines, or set up GitLab auth. The connector — not security tradecraft.
---

# GitLab

Connector for GitLab (gitlab.com or self-managed) via the community
`@zereight/mcp-gitlab` server. The agent sees the tool surface (89 tools read-only,
161 with writes) once it loads — this skill covers auth, the real read-only switch,
and the idioms. Security triage methodology — dedup, severity, SLA, owner
inference — is deliberately out of scope; pair this with whichever triage
capability your workflow uses.

## Auth

Two server options, and the tradeoff is surface vs. provenance — not tier.
**Default: the community PAT server**, which is GA and exposes by far the broader
surface. GitLab's own OAuth MCP (path B) is first-party and token-free but still
beta and much narrower. It moved from Premium to **Free in GitLab 19.2**, so it's
a real option on any tier when you'd rather not mint a PAT or take a dependency on
a community package.

### A. Community server + PAT (default)

1. Generate a PAT:
   - gitlab.com: <https://gitlab.com/-/user_settings/personal_access_tokens>
   - self-managed: `<your-gitlab>/-/user_settings/personal_access_tokens`
2. Scopes: **read-only** `read_api` (+ `read_repository` for code, `read_registry`
   for the registry); **read + write** `api` (broad).
3. Add `GITLAB_PAT` in the **secrets screen** (`/secrets` or `F7`) or the web app.
   Confirm with `dn secret list`. Don't paste tokens into chat.
4. Self-managed: also set `GITLAB_API_URL` (e.g.
   `https://gitlab.example.com/api/v4` — the trailing `/api/v4` is required).

### B. Official GitLab OAuth MCP (first-party; Free tier since 19.2)

First-party MCP built into the instance, spec-compliant OAuth (RFC 9728 discovery
+ DCR/PKCE), no PAT — but much narrower, and beta since GitLab 18.6. Free tier and
up as of 19.2; on older instances it's Premium/Ultimate. Prerequisites live under
the instance's GitLab Duo settings. Replace the whole `gitlab:` block in
`capability.yaml`:

```yaml
mcp:
  servers:
    gitlab:
      url: https://gitlab.com/api/v4/mcp   # self-managed: https://<host>/api/v4/mcp
      auth:
        type: oauth
        client_name: dreadnode
      init_timeout: 60
```

First connect opens a browser; tokens persist and refresh. `DREADNODE_HEADLESS=1`
for SSH/headless. Read-only here is the OAuth grant / role, not the env var below.

## Read vs write — actually enforced

Unlike most tracker connectors, the community server supports **real** read-only:
`GITLAB_READ_ONLY_MODE=true` (the capability's default) means write tools aren't
even registered. To enable writes, set `GITLAB_READ_ONLY_MODE=false` (secrets screen
or launching shell) and reload. The PAT's scopes still bound what's possible — pair
the flip with an `api`-scoped token.

## Search & idioms

No JQL-style DSL — structured filters (`state`, `labels`, `milestone`, `assignee`,
`author`) plus a free-text `search` field. Compose by argument.

- `project_id` accepts the **path** (`group/project`) or the numeric ID. Path is
  human-friendly; ID is stable across renames.
- **IID vs ID**: `iid` is project-scoped (`#42` in the UI), `id` is instance-global.
  The tools generally take `iid` — pass `project_id` alongside it.
- Don't invent label / milestone names — list them first.
- Code search uses GitLab Advanced Search (Elasticsearch), Premium / self-managed only.
- Self-managed pipelines vary by tier (CI minutes, runners, security features).
- The server is **community-maintained**; the manifest pins
  `@zereight/mcp-gitlab@2.1.43` for a reproducible tool surface. Bump it in
  `capability.yaml` to adopt newer tools — and read the diff first, since the pin
  is the trust boundary on a third-party package.
- **Pipelines, wikis, and milestones are off by default upstream.** The manifest
  turns them on via `USE_PIPELINE` / `USE_GITLAB_WIKI` / `USE_MILESTONE` (62 tools
  without them, 89 with, read-only). Set the corresponding `GITLAB_USE_*` var to
  `false` to trim the surface back.
- There are **no snippet tools** in this server, at any version — if the user wants
  snippets, that's the REST API directly, not this connector.
