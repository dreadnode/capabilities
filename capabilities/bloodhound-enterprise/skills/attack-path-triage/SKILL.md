---
name: attack-path-triage
description: Walk a BloodHound Enterprise deployment's active attack-path findings, prioritise them by severity and exposure, and produce a ranked action list. Use when the caller asks "what should we fix first", "what attack paths are active", "review BHE findings", or after an ingest cycle that surfaced new findings.
---

# Attack-path triage

BHE generates attack-path findings every analysis cycle — one per (principal, finding-type) pair where the principal can reach a Tier Zero asset via the named technique. Volumes vary from tens to thousands depending on environment hygiene. This skill turns that pile into a ranked action list with concrete remediation recommendations.

## Preconditions

`bhe-bootstrap` has run and reported at least one domain.

## Workflow

### 1. Inventory the finding catalogue

Call `list_attack_path_types`. The result enumerates every finding category the deployment knows about — Kerberoastable, GenericAll-on-DomainController, ESC1 / ESC2 / ESC8 (ADCS), DCSync, ShadowCredentials, etc. Read it once; you'll need the names for filtering and reference.

### 2. Pull the per-domain rollup

For each domain SID surfaced by bootstrap, call `domain_attack_paths(domain_sid)`. The rollup shows which finding categories are active in that domain plus their counts. Use it to decide where to spend triage cycles — domains with zero active findings are clean, domains with hundreds need focused attention.

### 3. Drill into high-impact categories

For each domain × category that warrants investigation, call `domain_attack_path_details(domain_sid, finding=<type>)`. This returns the per-finding rows: who the affected principal is, the exact edge involved, severity, and risk-acceptance state.

Prioritise by:

1. **Severity** (critical > high > medium > low).
2. **Principal blast radius**: a finding on a service account used by 1000 endpoints is larger than the same finding on a single user.
3. **Recency**: findings that appeared in the last analysis cycle are more interesting than long-standing ones (which have likely been triaged before — check `is_accepted_risk`).

### 4. Skip already-accepted risks

Findings with `is_accepted_risk: true` have been deliberately exempted by an operator. Don't re-triage them; surface them in a separate "previously accepted" bucket so the caller can audit the acceptances if they want, but don't propose remediation.

### 5. Walk the path

For each finding you'd recommend remediating, drill into the actual graph: call `get_entity(object_id=<finding's principal>)` and `entity_controllers(object_id=<principal>)` to see who else can reach the principal, then `entity_controllables(object_id=<principal>)` to see what the principal in turn controls. This turns "Kerberoastable user X exists" into "Kerberoastable user X has admin on 50 endpoints; cracking it gives the attacker enterprise admin via path Y".

For ADCS findings (ESC*), use `cert_template_info` and `cert_template_cas` to identify the publishing CA and template — the remediation almost always lives in template ACLs or CA configuration.

### 6. Output a ranked action list

```
{
  "domains_inspected": N,
  "active_findings": M,
  "accepted_risk": K,
  "ranked": [
    {
      "rank": 1,
      "finding": "ESC1",
      "domain_sid": "...",
      "principal": "...",
      "severity": "critical",
      "blast_radius": "12 admin targets, including DC01",
      "remediation": "remove enrollment rights for Authenticated Users from cert template Foo",
      "evidence": ["cert_template_info: ...", "entity_controllers: ..."]
    },
    ...
  ],
  "previously_accepted": [...],
  "next": "patch-and-recheck per recommendation"
}
```

Cap the ranked list at the top 25 unless the caller explicitly asked for more — beyond that the marginal value drops and the response gets unreadable.

## Cost budget

- One `list_attack_path_types` call per session.
- One `domain_attack_paths` per domain.
- `domain_attack_path_details` per (domain, category) — bound to ≤10 categories per domain.
- ≤25 entity walks (`get_entity` + `entity_controllers` + `entity_controllables`).

## What NOT to do

- Don't accept risk yourself. Risk acceptance is an operator decision; surface it as a recommendation in the action list and let the caller execute.
- Don't trigger `start_attack_path_analysis` during triage — it's a multi-minute server-side rebuild and will slow down every other tool call. Reserve for explicit "force a rebuild" requests.
- Don't propose Cypher patches to fix findings. Remediation is operational (modify ACLs, remove cert template enrollment rights, remove SPNs) — not graph mutations.
