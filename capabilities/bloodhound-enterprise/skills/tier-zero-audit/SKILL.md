---
name: tier-zero-audit
description: Audit the Tier Zero asset group — list members, validate that every inclusion is intentional, identify drift since the last audit, and certify or revoke certifications as needed. Use when the caller asks "audit Tier Zero", "review the tier list", "who's in Tier Zero and why", or after Tier Zero membership changes are reported in the audit log.
---

# Tier Zero audit

Tier Zero is BHE's most consequential asset group — it defines which principals the analysis engine treats as "high value" when computing attack paths. Drift in Tier Zero (a forgotten service account, a stale OU, a misclassified group) compounds: every transitive attack path against the new member becomes a finding. Auditing Tier Zero on a regular cadence is the highest-leverage hygiene activity in BHE.

## Preconditions

`bhe-bootstrap` has run and a Tier Zero tag exists.

## Workflow

### 1. Locate the Tier Zero tag

`list_asset_group_tags` returns every tag. Find the one named "Tier Zero" (or whatever the deployment called it — but the canonical type is `Tier`). Record its id; every subsequent call references it.

If no Tier Zero tag exists, the deployment is malformed — surface that to the caller. Don't try to create one yourself; tag schemas vary across BHE versions.

### 2. Enumerate members + counts

Call `count_tag_members(tag_id)` for the cheap rollup (User: 12, Computer: 4, Group: 7). Compare to the operator's expected baseline — sudden growth indicates new inclusions worth investigating.

Call `list_tag_members(tag_id, limit=500)` for the full list. Each row carries the object_id, kind, name, the selectors that included it, and `is_certified` — the operator's "I have validated this" flag.

### 3. Validate inclusions

Group members by selector (the `selectors` field on each member). For each selector:

- Is it `is_default: true` (BHE's built-ins)? Default selectors capture canonical Tier Zero principals — Domain Admins, Enterprise Admins, Domain Controllers. They should always pass review.
- Is it custom? Look up the selector via `list_tag_selectors(tag_id)` to read its Cypher. Verify the query is what you expect — selectors are sometimes broadened in panic during incident response and never trimmed back.

For each member surfaced by a custom selector, decide whether the inclusion makes sense:

- A service account in Tier Zero because it has admin on all DCs → correct, certify it.
- A user in Tier Zero because they're a member of a group that no longer exists → drift, recommend revocation.
- A computer in Tier Zero because it once was a DC but isn't anymore → drift, recommend revocation.

### 4. Compare against expected attack-path coverage

Call `domain_attack_paths(domain_sid)` for each domain. Tier Zero changes propagate into findings — if a new member just landed in Tier Zero, the analysis engine should now show new findings against principals that can reach them. If you see Tier Zero drift but no corresponding new findings, the analysis pass hasn't run since the change. Note this; don't trigger `start_attack_path_analysis` automatically.

### 5. Recommend certifications + revocations

For each member, output one of:

- `certify`: deliberate inclusion; mark as certified via `certify_member(object_id, certified=true)`.
- `revoke`: drift; recommend revocation. Don't auto-revoke — Tier Zero changes are governance decisions that need a human. Surface the rationale and the suggested action.
- `keep`: already certified, looks correct, no change.

### 6. Inspect history

Call `tag_history(tag_id, limit=100)`. The audit log shows the recent additions, removals, and certification changes — useful both for the audit narrative ("Tier Zero gained 3 service accounts last week, signed off by alice@") and for catching shadow changes ("a new selector was added by an account we don't recognise").

### 7. Output

```
{
  "tag_id": ...,
  "tag_name": "Tier Zero",
  "counts": { "User": ..., "Computer": ..., "Group": ..., ... },
  "members": [
    {
      "name": "...",
      "object_id": "...",
      "kind": "...",
      "selectors": ["..."],
      "is_certified": true,
      "verdict": "certify" | "revoke" | "keep",
      "rationale": "..."
    },
    ...
  ],
  "drift_count": N,
  "recent_changes": [audit_log_subset],
  "next": "operator: review verdicts; agent will execute approved certifications"
}
```

If the caller approves, execute the `certify_member` calls. Don't execute revocations from this skill — recommend them, let the operator do it through the UI or a follow-up explicit command.

## Cost budget

- One `list_asset_group_tags`.
- One `count_tag_members` + one `list_tag_members` per tag.
- One `list_tag_selectors` per tag.
- One `tag_history` per tag, capped at 100 rows.

## What NOT to do

- Don't add or remove Tier Zero selectors during an audit. Selector changes are bigger than per-member certifications and need a separate workflow.
- Don't certify in bulk without reviewing rationale. The point of certification is "I've thought about this"; bulk-certify defeats it.
- Don't recurse through `entity_controllers` for every Tier Zero member during an audit — that explodes into thousands of nodes. Save the recursion for `attack-path-triage`.
