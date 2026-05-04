---
name: attack-pattern-explore
description: Drive a self-directed survey of a BloodHound Enterprise deployment using the curated attack-pattern catalog. Walks the canonical AD / Azure / PKI patterns (Kerberoasting, unconstrained delegation, ADCS ESC1-15, ACL abuses, SID history, etc.) and surfaces concrete findings with evidence. Use when the caller asks "go find interesting things", "self-audit this deployment", "what's exploitable here", or when the analyst is dropped into an unfamiliar tenant and needs orientation.
---

# Attack-pattern explore

This is the agent's autonomous-discovery skill. The catalog at `runtime/cypher_library.py` ships ~40 known-useful queries covering canonical AD attack patterns. Walking the catalog top-to-bottom in 30 minutes covers ground a fresh analyst would take days to reproduce manually.

The skill exists because Cypher freedom alone isn't sufficient: an agent without prior AD knowledge will mostly stick to prebuilt tools and miss the patterns that don't have dedicated endpoints. The catalog is curriculum + ammo.

## Preconditions

`bhe-bootstrap` has run; the agent has confirmed credentials, at least one domain, and non-zero graph data.

## Workflow

### 1. Inventory the catalog

Call `list_attack_patterns()` (no filter). The response carries the catalog size and a per-category count — confirms the catalog actually loaded and gives a sense of scope. Record the categories so you can sequence the walk.

### 2. Pull the deployment's active findings

Call `list_attack_path_types`. Cross-reference with the catalog: any catalog pattern whose `attack_path_type` matches an active finding type is high-priority — the deployment has live findings of that shape, so the catalog query likely produces actionable results.

`list_attack_paths(limit=200)` gives you a representative sample of currently-active findings. Note the principals, domains, and severities; the patterns will produce richer context for these.

### 3. Plan the walk

Categorise the catalog into priority tiers based on what the deployment looks like:

- **Tier 1 (run first)** — patterns whose `attack_path_type` matches active findings. These are the most directly useful.
- **Tier 2 (run next)** — fundamentals that should always run: `da-all-members`, `tier-zero-shortest-paths-to`, `tier-zero-from-domain-users`, `dcsync-rights`, `kerb-roastable-tier-zero`, `adcs-esc1`, `acl-genericall-on-tier-zero`. These are the "no matter what's in this tenant, these are interesting" baseline.
- **Tier 3 (opportunistic)** — Azure patterns if Azure data is present (check via `posture_snapshot` for AAD domain SIDs); GPO patterns if there are non-trivial GPO counts; trust patterns if multiple domains exist.
- **Skip** — categories where the deployment shows no evidence (Azure patterns on AD-only deployments; SID-history if no migrations were ever done).

### 4. Run the walk

For each pattern in priority order:

1. `describe_attack_pattern(pattern_id)` — print the description if you're going to surface results to the caller, so the why-this-matters is in the agent's working memory.
2. `run_attack_pattern(pattern_id)`. The result is a graph digest: counts + truncated node/edge lists.
3. Decide whether the result is interesting:
   - **0 results**: the pattern doesn't apply here. Skip the write-up but record the negative finding (clean negatives are real artefacts of a hardened deployment).
   - **1–10 results**: drill in via `get_entity` / `entity_controllers` for each node returned, OR via `domain_attack_path_details` if the pattern correlates to a finding type.
   - **>10 results**: the result is interesting in aggregate, not per-node. Summarise counts and the top few representative nodes; the operator can drill in if they want detail.

Cap the walk at ~25 patterns per session. Beyond that you're past the point of diminishing returns and the caller's attention budget is exhausted.

### 5. Synthesize

Bucket the findings by impact level:

- **Critical**: tier-zero compromise paths from ordinary user populations (Domain Users, Authenticated Users), unrestricted ESC1, GenericAll on Tier Zero from non-tier-zero principals, foreign-domain controllers of Tier Zero.
- **High**: Kerberoastable Tier Zero, AS-REP roastable, unconstrained delegation, LAPS readers with broad scope, gMSA password readers, Sub-OU GPOs linked to Tier Zero containers.
- **Medium**: stale Tier Zero accounts, old passwords on Tier Zero, GPO writers outside Tier Zero, broad RDP fan-out from Domain Users.
- **Informational**: counts for context — total Domain Admins, total Tier Zero, total enrolled cert templates.

For each non-empty pattern, write one paragraph: what the pattern detects, what the result shows, why it's at the assigned impact level, and what the caller would do about it.

### 6. Output

```
{
  "deployment": {
    "domains": ["..."],
    "tier_zero_count": N,
    "active_finding_types": ["..."]
  },
  "patterns_run": K,
  "patterns_with_results": M,
  "critical": [
    {
      "pattern_id": "...",
      "name": "...",
      "category": "...",
      "result_count": N,
      "representative": [{ "name": "...", "object_id": "..." }, ...],
      "narrative": "one paragraph",
      "next_action": "vuln-triage / tier-zero-audit / ..."
    },
    ...
  ],
  "high": [...],
  "medium": [...],
  "informational": [...],
  "negatives": [
    { "pattern_id": "kerb-asreproast", "rationale": "no users with PreAuth disabled — clean" },
    ...
  ],
  "follow_up_skills": [
    "attack-path-triage to rank for remediation",
    "tier-zero-audit to certify the new tier-zero inclusions surfaced",
    "ad-entity-walk for the top 3 critical principals"
  ]
}
```

The `negatives` list is value-add — confirming a pattern *doesn't* apply is itself information. Don't bury it.

## Cost budget

- One `list_attack_patterns` per session.
- One `list_attack_path_types` + one `list_attack_paths` per session.
- ≤25 `run_attack_pattern` calls.
- ≤10 `describe_attack_pattern` calls (use only for patterns whose results you'll surface).
- ≤15 follow-up `get_entity` / `entity_controllers` calls during the synthesis phase.

If the budget is exhausted, return a partial walk — categorise as "ran" vs "deferred" so the caller can resume.

## What NOT to do

- Don't run the catalog blindly without checking active findings first. The Tier 1 sequencing is what makes the walk efficient.
- Don't paste every result through the tool boundary. The graph summary is meant to be a digest — preserve detail behind `get_entity` calls when the caller wants to drill in.
- Don't write fresh Cypher when a catalog pattern almost matches. Adapt via `describe_attack_pattern` — read the body, copy into `run_cypher`, tweak. Composing on top of a curated pattern beats inventing from scratch.
- Don't propose remediation in the output. The walk is descriptive; remediation is `attack-path-triage`'s deliverable.
- Don't trigger `start_attack_path_analysis` mid-walk. The findings the walk references should match the analysis state at session start; recomputing mid-walk invalidates the evidence.
