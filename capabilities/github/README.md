# github

Wires GitHub into chat and agents by bundling GitHub's **official remote MCP server** (`https://api.githubcopilot.com/mcp/`) — issues, PRs, code search, Actions, Dependabot, code scanning. Ships no bespoke tool code; the value is the auth wiring, the toolset selection, and a skill. **Write-capable by default** — bounded by the PAT's permissions, with an optional server-side read-only lock (below).

## Setup

Authentication is a Personal Access Token sent as a Bearer header. Set `GITHUB_PAT` via the secrets screen (`/secrets`, F7) — or, if you're already on the `gh` CLI, `gh auth token` prints a reusable token (those rotate; mint a fine-grained PAT for unattended use). Grant the token read on the surfaces you need (Issues, Pull requests, Contents, Actions, Dependabot alerts) and write only where the agent must mutate.

| Var | Default | Notes |
|-----|---------|-------|
| `GITHUB_PAT` | _(required)_ | Bearer token. Its scopes are the outer bound on everything the agent can do. |
| `GITHUB_READ_ONLY_MODE` | _(unset)_ | Set `true` and reload to send `X-MCP-Readonly` — the server then won't register mutating tools at all (58 → 38). A backstop for when the token is broader than the task. |

**Read-only worth knowing:** the PAT's scopes are the real boundary, but the server-side flag above is a genuine second lock — the agent cannot call a tool that was never registered. Unset by default, so out of the box this is write-capable up to whatever the PAT allows. Among the tracker connectors only this one and `gitlab` can enforce read-only server-side; `linear`, `atlassian`, and `azure-devops` are credential-scoped only.

**There is deliberately no OAuth/device flow** — GitHub's remote MCP doesn't support Dynamic Client Registration and its OAuth flow needs a `client_secret` an installed capability can't ship, so GitHub reserves OAuth for its own allowlisted hosts. A token is the only path here (unlike the `linear` / `atlassian` connectors).

## Before you trust it

- **The security tools are opt-in and we opt in for you.** GitHub's default toolset ships none of them; the manifest requests `actions`, `code_security`, `dependabot`, and `secret_protection` explicitly via `X-MCP-Toolsets`. That lands the surface at 58 tools rather than the bare default's 47 or `all`'s 95. Trim that header if you want a smaller context footprint.
- **Code-scanning / SARIF tools need GitHub Advanced Security** licensed on the target org — without it those paths return empty regardless of PAT scope. Dependabot alerts don't carry this dependency.
- **Enterprise changes the URL** (data-residency Cloud is `https://copilot-api.<subdomain>.ghe.com/mcp`) or drops the remote server entirely (Enterprise Server → local Docker image). Both mean editing `capability.yaml` — see the skill.

Query idioms (the issue-search DSL) and the Enterprise swap live in `skills/github/`.
