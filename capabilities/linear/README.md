# linear

Points the runtime at **Linear's own hosted MCP server** (`https://mcp.linear.app/mcp`) — Linear maintains the tool surface; this capability ships only the wiring and a skill. **Write-capable**: it can create and update issues, comment, and transition workflow state. There is no read-only flag — scope is the credential's grant.

## Setup

Two auth paths, same tool surface:

- **OAuth (default)** — Services screen → `linear` → **Authenticate**; approve in the browser once, the refresh token persists to `~/.dreadnode/mcp-auth.json`. For headless/SSH set `DREADNODE_HEADLESS=1` (the auth URL is logged; forward the callback port it prints).
- **API key** — set `LINEAR_API_KEY` via the secrets screen (`/secrets`, F7); the header activates automatically and takes precedence over OAuth. For unattended/agent use, prefer an OAuth app install with `actor=app` over a personal key — actions attribute to the app and don't burn a billable seat.

For enforced read-only, mint a Read-permission key — Linear supports per-key Read / Write / Admin permissions and team scoping, so this is a real boundary even though it lives in the credential rather than the server. (The `gitlab` and `github` connectors can additionally refuse to register write tools server-side; Linear, Atlassian, and Azure DevOps cannot.)

Auth detail and filter idioms live in `skills/linear/`.
