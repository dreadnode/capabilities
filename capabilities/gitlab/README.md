# gitlab

Connects chat and agents to GitLab (issues, merge requests, projects, pipelines, milestones, wikis) on gitlab.com or self-managed, by bundling the community **`@zereight/mcp-gitlab`** server (`npx`, pinned `2.1.43`). Not first-party — the pin is your trust boundary; bump it deliberately. Works on every tier including Free.

## Setup

| Var | Default | Notes |
|-----|---------|-------|
| `GITLAB_PAT` | _(required)_ | Personal access token — `read_api` scope for read-only, `api` for writes. Set via the secrets screen (`/secrets`, F7), not chat. |
| `GITLAB_API_URL` | `https://gitlab.com/api/v4` | Point at a self-managed instance: `https://<host>/api/v4` (the `/api/v4` is required). |
| `GITLAB_READ_ONLY_MODE` | `true` | Read-only by default — at `true` the server doesn't register write tools at all. Set `false` and reload to enable writes (also needs an `api`-scoped token). |
| `GITLAB_USE_PIPELINE` | `true` | Pipeline / job / artifact tools. Off in the upstream default; on here. |
| `GITLAB_USE_WIKI` | `true` | Project and group wiki tools. Same story. |
| `GITLAB_USE_MILESTONE` | `true` | Milestone tools, including burndown events. Same story. |

Setting any of the three `GITLAB_USE_*` vars to `false` trims that group back out — the read-only surface is 62 tools with all three off, 89 with them on, and 161 once writes are enabled.

## Before you trust it

- **Read-only here is real, not advisory.** At the default the server never registers a mutating tool, so an over-scoped token still can't write through this connector. That's stronger than the credential-only scoping in the `github` / `linear` / `atlassian` / `azure-devops` connectors — it's a property of this server, not something we built.
- **It's community-maintained.** That's the tradeoff for tier coverage and surface breadth. GitLab ships a first-party OAuth MCP that's token-free and moved from Premium to **Free in GitLab 19.2** — narrower and still beta, but first-party. If provenance matters more than surface, `skills/gitlab/SKILL.md` has the drop-in manifest block.
- **No snippet tools exist** in this server at any version, despite snippets being a GitLab feature. Use the REST API directly if you need them.

Token setup, the OAuth swap, and filter idioms live in `skills/gitlab/`.
