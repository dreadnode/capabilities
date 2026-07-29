---
name: atlassian
description: Use when the user wants to connect to Jira, Confluence, or Compass — search issues with JQL, read or create issues and pages, link content across products, or set up Atlassian auth. The connector — not security tradecraft.
---

# Atlassian (Jira / Confluence / Compass)

Connector for Atlassian Cloud via the official Rovo remote MCP — one server, three
products. The agent sees the tool surface once it loads — this skill covers auth,
the per-product query languages, and the idioms. Security triage methodology —
dedup, severity, SLA, owner inference — is deliberately out of scope; pair this
with whichever triage capability your workflow uses.

## Auth

Native HTTP MCP with OAuth 2.1 + DCR; the runtime drives the flow, no
`mcp-remote` bridge. Atlassian doesn't publish an RFC 9728 protected-resource
document, so discovery resolves through the authorization-server metadata on
`mcp.atlassian.com`, which points at `cf.mcp.atlassian.com` for
authorize/token/register. Nothing to configure — but if you're debugging a failed
connect, that's the chain to walk, and it's why the `.well-known/
oauth-protected-resource` probes you'd try first come back 404.

### A. OAuth 2.1 (default)

On first connect, `atlassian` shows in Services as `needs authentication`. Click
**Authenticate** → browser → sign in and grant the Rovo scopes; tokens persist to
`~/.dreadnode/mcp-auth.json` (mode 0600) and refresh silently. Access respects your
existing Jira / Confluence / Compass roles. Switch sites / revoke via Services →
`atlassian` → **Re-authenticate**. SSH/headless: `DREADNODE_HEADLESS=1` logs the URL.

**First install on a new site needs a site admin** to complete consent once; until
then other users see "Your site admin must authorize this app." That's
Atlassian-side, not us.

### B. API token (only if your admin allowed it)

For unattended use, **just set one secret** — no manifest edit. The server entry
carries an optional `Authorization` header bound to `ATLASSIAN_BASIC`: set it and
Basic auth wins, leave it unset and OAuth (A) stays default.

1. Admin enables "authentication via API token" in **Rovo MCP server settings**
   (off by default).
2. Generate a token: <https://id.atlassian.com/manage-profile/security/api-tokens>.
3. Personal tokens use **Basic** (`email:token`, base64). Interpolation can't
   base64 for you — compute it and store the result as `ATLASSIAN_BASIC`:
   ```bash
   printf '%s:%s' you@example.com ATATT… | base64 | tr -d '\n'; echo
   ```
   Then reload. (Service-account API **keys** use Bearer — change `Basic` to `Bearer`
   in the manifest header and bind `${ATLASSIAN_API_KEY}`.)

If the admin hasn't enabled token auth this path 401s with a clear error — unset the
secret and reload to fall back to OAuth. Token-auth agents bypass OAuth domain
allowlists and are governed by IP allowlist + token scopes instead. Don't paste
tokens into chat.

Read vs write is enforced by the user's **project / space roles** (or the token's
scopes on path B) — there's no protocol-level read-only mode.

## Query languages — know which product

- **Jira: JQL.** `project = "ENG" AND status = "Open" AND assignee = currentUser()
  ORDER BY priority DESC`.
  <https://support.atlassian.com/jira-service-management-cloud/docs/use-advanced-search-with-jira-query-language-jql/>
- **Confluence: CQL.** `space = "ENG" AND type = page AND title ~ "release"`.
  <https://developer.atlassian.com/cloud/confluence/cql-fields/>
- **Compass:** structured typed filters (component type, owner team, dependencies),
  not a DSL.

Prefer JQL / CQL with the search tool over post-filtering large lists. `ENG-123` is
the canonical Jira key — use it directly when the user has it. Always scope queries
(`project = …`) — instance-wide ones are slow and rate-limited.

## Idioms

- **Rate limits bite.** Free 500/hr; Standard / Premium / Enterprise 1000/hr base
  (+20/user up to 10k/hr on higher tiers). Bulk loops blow through these — batch and
  back off. The Rovo MCP supports bulk create from a spec / meeting notes: parse into
  `{summary, description, …}` records, then create per record.
- The Rovo MCP is a **secure proxy, not a cache** — every call hits Atlassian Cloud;
  "I just read it" doesn't mean it's unchanged. It can also link entities across
  products (tickets ↔ a release-plan page ↔ a Compass component).
- `currentUser()` in JQL is the **OAuth user**, not the agent — with a service
  account, "assigned to me" means the service account.
- Don't invent custom field IDs — list the project's fields when the schema isn't obvious.
- No FedRAMP / HIPAA workloads through this MCP.
