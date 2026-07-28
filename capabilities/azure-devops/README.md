# azure-devops

Talks to Azure DevOps — Boards, Repos, Pipelines, Wiki — from chat and agents by bundling Microsoft's official `@azure-devops/mcp` server (pinned `2.8.1`, run on demand via `npx`). It's **write-capable** (create and update work items and wiki pages); scope is governed by your Azure DevOps project roles, not an in-band toggle — this connector has no server-side read-only switch, so use a read-scoped principal for unattended runs.

## Setup

Auth delegates to the Azure CLI — the server reuses your `az login` token, nothing to paste:

1. `az login` with an account that can reach the target org.
2. Set `ADO_ORG` to the org **name** (e.g. `contoso`, not the URL) via the secrets screen (`/secrets`, F7).
3. Optionally set `ADO_PROJECT` / `ADO_TEAM` to answer the project / team picker the server would otherwise elicit per call. (These need `@azure-devops/mcp` ≥ 2.8.0 — the reason the pin is 2.8.1 and not lower.)

There is no server-side read-only switch here — unlike `gitlab` and `github`, the ADO server registers its write tools unconditionally, so a read-scoped principal is the only way to pin this read-only.

A preflight `checks:` block fails fast if `az` is missing, no session is live, or Node < 20. To switch off `az login`, edit `--authentication` in `capability.yaml` (`interactive`, `pat`, or `envvar` are upstream-supported).

## Tool surface

The `-d` list ships `core work work-items repositories wiki pipelines` — **76 tools**, against 90 if you let the upstream default to `all`. To enable more, append `test-plans` (+9), `advanced-security` (+2, GHAS alerts), or `search` as **separate list items** in `capability.yaml` and reload.

One trap worth knowing: `-d` is parsed as an array, so the domains must stay one-per-line. Collapsing them into a single `core,work,...` string is read as one unknown domain and the server silently serves all 90 tools instead of erroring.

WIQL idioms and the GHAS-alert path are in `skills/azure-devops/`.
