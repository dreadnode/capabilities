# atlassian

Wires Jira, Confluence, and Compass into chat and agents through Atlassian's hosted Rovo MCP server (`https://mcp.atlassian.com/v1/mcp`, first-party). It can **write** — create and update issues and pages — not just read, and there is no read-only mode: an agent acts with the full permissions of whoever authenticated.

## Setup

**OAuth (default).** On first connect the `atlassian` server shows as *needs authentication* in Services — click **Authenticate**, grant the Rovo scopes once in the browser, and the refresh token persists to `~/.dreadnode/mcp-auth.json`. The **first install on a new Atlassian site needs a site admin** to approve the app before anyone else can authenticate. For headless/CI, set `DREADNODE_HEADLESS=1` to log the auth URL instead of opening a browser.

If a connect ever fails and you go looking: Atlassian publishes no RFC 9728 protected-resource document, so discovery resolves through the authorization-server metadata on `mcp.atlassian.com`, which delegates to `cf.mcp.atlassian.com`. A 404 on `.well-known/oauth-protected-resource` is expected here — it isn't the fault.

**API token (unattended, optional).** Only works if a site admin enabled "authentication via API token" in Rovo MCP settings (off by default). Set the `ATLASSIAN_BASIC` secret to the base64 of `email:token`:

```bash
printf '%s:%s' you@example.com ATATT… | base64 | tr -d '\n'
```

Service-account API *keys* use Bearer instead: change `Basic` to `Bearer` in the manifest header and bind `${ATLASSIAN_API_KEY}`.

## Before you trust it

- **No read-only mode.** Scope is the authenticated identity's roles — under OAuth an agent can do anything you can. Use a scoped service account for unattended runs. (The `gitlab` and `github` connectors can enforce read-only server-side; this one and `azure-devops` cannot — the credential is the only boundary.)
- **Rate limits are low** — Atlassian publishes 500 calls/hour on Free and 1,000/hour on Standard, with Premium/Enterprise adding per-user allowance up to 10,000/hour. Bulk loops will hit them.
- **Not for FedRAMP or HIPAA workloads** — Atlassian states the MCP server doesn't currently support either.

Agent-facing usage — the per-product query languages (JQL/CQL) and idioms — lives in `skills/atlassian/`, not here.
