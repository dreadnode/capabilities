---
name: ad-entity-walk
description: Investigate a single AD or Azure principal — who controls it, what it controls, where it has admin rights, and what's reachable via its credentials. Use when the caller asks "tell me about this user", "what does X have access to", "who can compromise Y", or when triaging a finding tied to a specific principal.
---

# AD entity walk

When a single principal is in the spotlight — a user from an attack-path finding, a service account that just landed in Tier Zero, a compromised computer from an incident — the question is always some variation of "what's its blast radius?". This skill pulls together the relationship info BHE has on that principal so the agent can answer.

## Preconditions

- `bhe-bootstrap` has run.
- A principal identifier — either an object_id (preferred) or a name to resolve.

## Workflow

### 1. Resolve to an object_id

If the caller supplied a name ("jdoe@example.com", "DC01.example.com"), call `search_graph(query=<name>, kind=<optional>)` to translate to an object_id. The first result is usually correct; if multiple results land, surface them and let the caller disambiguate before proceeding.

If the caller supplied an object_id, skip this step.

### 2. Pull basic info

Call `get_entity(object_id)`. The response carries:

- Kind (User, Computer, Group, Domain, AZUser, ...).
- Name and distinguished name.
- Domain.
- Counts of every relationship type (Sessions, AdminTo, MemberOf, ...).

Use the kind to choose the right downstream tools. `User` and `Computer` have rich per-kind endpoints (admin-rights, sessions, delegation); other kinds (Group, GPO, Domain) are mostly served by the generic `entity_controllers` / `entity_controllables` pair.

### 3. Walk inbound — who can compromise this?

Call `entity_controllers(object_id)`. The result is the set of principals with rights to take over this entity (Owner, GenericAll, GenericWrite, WriteOwner, ResetPassword, etc.).

For each controller:

- Note the kind. Group controllers are particularly important because their members all inherit the right.
- Spot Tier Zero entries. If a Tier Zero member controls the principal, the principal is effectively Tier Zero too — flag that.
- Spot stale memberships. A controller named `*_LEGACY` or in an OU labelled `_disabled` is drift worth surfacing.

If the principal is a `User`, also call `user_admins(user_id)` for the focused list of who has admin *on the user account itself* (this overlaps with `entity_controllers` but the per-kind endpoint sometimes surfaces more detail).

### 4. Walk outbound — what does this principal control?

Call `entity_controllables(object_id)`. The result is the set of nodes this principal can take over.

For users + computers, also call the per-kind right walks:

- `user_admin_rights(user_id, kind="admin-rights")` — local admin on remote machines.
- `user_admin_rights(user_id, kind="rdp-rights")` — RDP targets.
- `user_admin_rights(user_id, kind="powershell-remote-rights")` — WinRM targets.
- `user_admin_rights(user_id, kind="dcom-rights")` — DCOM execution.
- `user_admin_rights(user_id, kind="sql-admin-rights")` — SQL admin.
- `user_admin_rights(user_id, kind="constrained-delegation-rights")` — delegation targets.

Replace `user_admin_rights` with `computer_admin_rights` when the principal is a Computer.

### 5. Walk active sessions

For users: `user_sessions(user_id)` shows current logon footprint. Sessions are a hot target — every machine the user is logged into is a credential-theft opportunity for an attacker who compromises that machine.

For computers: `computer_sessions(computer_id)` shows who's logged into the machine. Combined with the inbound controllers walk, this answers "if this machine is compromised, whose credentials are at risk?".

### 6. Walk membership

For users: `user_membership(user_id)` shows direct + transitive group membership. Useful for spotting unexpected admin-group inclusions.

### 7. Tier and certification context

Call `search_asset_group_tags(query=<object_id>)` to see whether the principal is in any tag (Tier Zero, Crown Jewels, Owned, ...). If it's in Tier Zero, the blast radius interpretation flips — the principal's access becomes *the* attack target rather than a means of attack.

### 8. Output

```
{
  "principal": {
    "object_id": "...",
    "kind": "User",
    "name": "...",
    "domain": "...",
    "tags": ["Tier Zero", "Owned"],
    "is_certified": true
  },
  "inbound": {
    "controllers": [...],
    "admins": [...],
    "tier_zero_controllers": [...]
  },
  "outbound": {
    "admin_targets": N,
    "rdp_targets": N,
    "ps_remote_targets": N,
    "dcom_targets": N,
    "sql_admin_targets": N,
    "delegation_targets": N,
    "groups": [...]
  },
  "sessions": [...],
  "blast_radius_summary": "..."
}
```

The `blast_radius_summary` is the agent's contribution — one short paragraph synthesising the structured data into "if this account is compromised, the attacker reaches X, Y, and via Z gets to Tier Zero through finding W".

## Cost budget

- 5–8 tool calls per principal in the typical case.
- One `search_graph` for name resolution.
- Skip per-kind walks for kinds that don't have them (the per-kind endpoints 404 on Groups / OUs / Domains).

## What NOT to do

- Don't recurse into every controller. The walk fans out exponentially; stick to the immediate inbound / outbound layer for one principal. Use Cypher's `shortestPath` if you need transitive reachability.
- Don't propose remediation as part of the walk. The walk is descriptive; remediation is a separate operation. Hand off to `attack-path-triage` for that.
- Don't rely on `enabled = false` to dismiss a principal. Disabled accounts can still be re-enabled and used; their inclusion in the graph is still informative.
