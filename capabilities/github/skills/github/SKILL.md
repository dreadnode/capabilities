---
name: github
description: Use when the user wants to connect to GitHub, search or read issues / PRs / code, create or update issues and PRs, inspect Actions runs, or review Dependabot / code-scanning alerts. The connector — not security tradecraft.
---

# GitHub

Connector for GitHub via its official remote MCP server. The agent sees the
enabled tool surface (~58 tools) once the server loads — this skill covers what
the tool specs don't: auth, read-only scoping, the issue-search DSL, and the
non-obvious idioms. Security triage methodology — dedup, severity, SLA, owner
inference — is deliberately out of scope; pair this with whichever triage
capability your workflow uses.

## Auth

Token sent as a Bearer header — **no OAuth**. This is a GitHub-side limit: its
remote MCP server doesn't support Dynamic Client Registration and its OAuth web
flow needs a `client_secret` that can't ship in an installed tool, so OAuth is
reserved for GitHub's allowlisted first-party hosts (VS Code, Cursor, …). For this
connector, a token is the path.

**Already using the `gh` CLI? Reuse its session — no new token.**

```bash
gh auth token        # copy the output into /secrets → GITHUB_PAT
```

Quickest path for most developers. `gh` OAuth tokens can rotate/expire, so for a
long-lived / unattended setup mint a fine-grained PAT instead:

1. <https://github.com/settings/personal-access-tokens/new>, scoped to the repos or
   org you need, minimum permissions:
   - **Read-only**: `Contents`, `Issues`, `Pull requests`, `Metadata` (Read), plus
     `Code scanning alerts` + `Dependabot alerts` (Read) for security data.
   - **Read + write**: add `Issues`, `Pull requests`, `Contents` (Write) only where needed.
2. Add `GITHUB_PAT` in the **secrets screen** (`/secrets` or `F7`) or the web app.
   Confirm with `dn secret list`. Don't paste tokens into chat.

Two independent read-only controls, and you want both:

- **PAT scopes** — a token without `Write` permissions can't mutate. This is the
  one that holds even if the server config changes.
- **Server-side** — set `GITHUB_READ_ONLY_MODE=true` (secrets screen or launching
  shell) and reload. The manifest binds it to the remote server's `X-MCP-Readonly`
  header, and the server then refuses to register mutating tools at all (58 → 38).
  Unset by default, so writes stay governed by the PAT alone.

The server-side flag is the useful backstop when the token is broader than the
task — the agent can't call what was never registered.

**GitHub Enterprise.** Enterprise Cloud with data residency changes the URL to
`https://copilot-api.<subdomain>.ghe.com/mcp` — swap `url:` in `capability.yaml`.
Enterprise Server (self-hosted) doesn't support the remote server; use the local
Docker image (`ghcr.io/github/github-mcp-server`) with a stdio `command:` entry.
Ask before doing this — the manifest changes aren't drive-by.

## Issue search DSL

`search_issues` takes GitHub's structured query (keyword tokens + `repo:`, `is:`,
`state:`, `label:`, `author:`, `assignee:`, `in:title`, `sort:` …) and covers
**both issues and PRs** — qualify with `is:issue` / `is:pr`. Prefer it over
`list_issues` for anything more specific than state.

```
repo:owner/name is:issue is:open label:bug author:alice
```

Reference: <https://docs.github.com/en/search-github/searching-on-github/searching-issues-and-pull-requests>.

## Idioms

- **No implicit scope** — every tool call needs `owner` and `repo`.
- `issue_read` / `issue_write` are **dispatcher tools**: pick the `method` (`get`,
  `get_comments`, `get_sub_issues`, `get_labels` for read; `create`, `update` for
  write). Sub-issues are first-class via `sub_issue_write`.
- List label / type names (`list_issue_types`, `get_label`) rather than guessing them.
- **Dependabot + code-scanning alerts are the security surfaces.** They need the
  token's `security_events` scope (or fine-grained `Code scanning alerts: Read` +
  `Dependabot alerts: Read`): `list_dependabot_alerts`, `get_dependabot_alert`,
  `list_code_scanning_alerts`, `get_code_scanning_alert`. These are **not** in the
  server's default toolset — the manifest requests them via `X-MCP-Toolsets`. If
  they're missing from the surface, that header is why, not the token.
- **Toolsets are a context lever.** The manifest ships `default`, `actions`, and the three
  security toolsets (58 tools); `all` is 95. Trim or extend the `X-MCP-Toolsets`
  header in `capability.yaml` to trade surface for context budget —
  <https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md>.
