---
name: bhe-bootstrap
description: Establish a working session against a BloodHound Enterprise deployment — verify credentials, identify the environment, list domains, and confirm the API is responding. Run this at the start of every session before any other BHE skill, or whenever a tool fails because no credentials are configured.
---

# BHE bootstrap

Every other BHE skill assumes a working session: the client knows the URL, has credentials that authenticate, and has identified at least one domain to operate against. `bhe-bootstrap` is the one skill that's safe to run with no prior state.

## Workflow

### 1. Establish credentials

Call `connect`. Three modes are supported:

- **HMAC** (preferred for long-running sessions). Pass `token_id` + `token_key`, or rely on `BHE_TOKEN_ID` / `BHE_TOKEN_KEY` env. Long-lived; signed per-request; survives restarts.
- **JWT** via login. Pass `username` + `password`; the runtime exchanges them for a session token. Useful when the operator only has a UI account.
- **Pre-existing JWT**. `BHE_JWT` env, or pass after a separate exchange.

If `connect` returns `auth_mode: "unconfigured"`, stop — every subsequent tool will fail. Surface the specific cause and let the caller fix it.

### 2. Confirm identity

`whoami` returns the current principal — email, name, role(s). Read it back so the caller can see which account the agent is acting as. Roles matter: read-only roles can't accept findings or create selectors, and write attempts will fail with HTTP 403.

### 3. Identify the graph state

Call `list_asset_group_tags` to see the configured tiers. A healthy BHE deployment shows at least Tier Zero plus a couple of custom tags. An empty list suggests the deployment is freshly provisioned and hasn't ingested data yet.

Call `posture_snapshot` to confirm at least one domain is recognised. If `data_count == 0`, the deployment has no graph data — point the caller at `data-ingestion` to upload SharpHound / AzureHound output before proceeding.

### 4. Output

A short JSON payload the caller can use to plan downstream skills:

```
{
  "auth_mode": "hmac" | "jwt" | "unconfigured",
  "base_url": "...",
  "user": { "email": "...", "roles": [...] },
  "domains": ["S-1-5-21-...", ...],
  "tier_zero_count": N,
  "exposure_index": F,
  "ready": true | false,
  "next": "attack-path-triage / data-ingestion / cypher-investigation / ..."
}
```

If `ready` is false, name the specific blocker (no domains, unauthenticated, role too restrictive) — don't paper over it.

## Cost budget

- One round-trip per step. Bootstrap is supposed to be cheap.
- If `whoami` or `list_asset_group_tags` returns 401, don't retry — surface the error and stop.
