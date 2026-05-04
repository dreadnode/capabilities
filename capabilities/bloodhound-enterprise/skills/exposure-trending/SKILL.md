---
name: exposure-trending
description: Compare BHE posture between two points in time — what got better, what got worse, and which specific findings drove the change. Use when the caller asks "how have we improved", "what changed since last week", "produce a trend report", or at the close of a remediation cycle.
---

# Exposure trending

The single most stakeholder-relevant artefact a BHE deployment produces is a delta: the exposure index dropped from 72 to 54 over the last two weeks, driven by remediation of 8 ESC1 findings and the certification of 12 new Tier Zero members. This skill produces that delta.

## Preconditions

`bhe-bootstrap` has run.

## Workflow

### 1. Pin the time window

The caller usually supplies two dates. Common shapes:

- "since last review" → a 30-day window.
- "this sprint" → 14 days.
- "this incident" → ad-hoc range tied to known events.

If the caller doesn't specify, default to a 30-day rolling window ending today. Format both dates as RFC3339 (`YYYY-MM-DDTHH:MM:SSZ`).

### 2. Pull the per-domain posture history

For each domain SID, call `posture_history(domain_sid, from_date, to_date)`. The response is a time series of (captured_at, exposure_index, tier_zero_count, critical_count). Compute the delta — first vs last datapoint — and the trajectory (monotonically improving, oscillating, regressing).

### 3. Pull the cross-domain finding trends

Call `attack_path_trends(from_date, to_date)`. The response shows per-(environment, finding) deltas: how many of each finding type were active at the start of the window vs. now. The big movers are usually a handful of categories — surface them.

### 4. Drill into the drivers

For the top 3–5 categories with significant negative deltas (more findings now than at start), inspect what drove the increase:

- Call `domain_attack_path_details(domain_sid, finding=<category>)` and look at `accepted_until` — were findings accepted but the acceptance expired?
- Call `tag_history(tag_id=<tier_zero>)` and look for additions in the window — new Tier Zero members typically multiply findings against everything that can reach them.
- Call `audit_logs(action="...")` for the window — were ingest jobs failing, leaving the graph stale?

For categories with significant positive deltas (fewer findings), confirm the cause via the same audit signals — risk acceptance versus actual remediation.

### 5. Build the narrative

Assemble:

- **Headline numbers**: exposure index Δ, tier-zero count Δ, critical-risk count Δ.
- **Top movers**: per-finding-category deltas, ordered by absolute change.
- **Drivers**: 1–2 sentences per top mover explaining why it changed.
- **Outliers**: domains where the trend diverged from the deployment-wide trajectory (one domain getting worse while others improve is signal).
- **Open recommendations**: findings still active that have been accepted with imminently-expiring acceptances.

### 6. Output

```
{
  "window": { "from": "...", "to": "..." },
  "headline": {
    "exposure_index": { "before": 72, "after": 54, "delta": -18 },
    "tier_zero": { "before": 23, "after": 27, "delta": +4 },
    "critical_risk": { "before": 11, "after": 4, "delta": -7 }
  },
  "domains": [
    { "domain_sid": "...", "exposure_delta": -22, "trajectory": "monotone" },
    ...
  ],
  "findings": {
    "improved": [
      { "finding": "ESC1", "before": 8, "after": 0, "driver": "remediation" },
      ...
    ],
    "regressed": [
      { "finding": "Kerberoastable", "before": 3, "after": 6, "driver": "Tier Zero growth" },
      ...
    ]
  },
  "open": [
    { "finding": "DCSync", "principal": "...", "accepted_until": "...", "concern": "expires in 5 days" }
  ]
}
```

Keep the narrative tight — stakeholder reports get worse with length, not better.

## Cost budget

- One `posture_history` per domain.
- One `attack_path_trends` per session.
- ≤5 `domain_attack_path_details` for top movers.
- One `tag_history` for Tier Zero (drift attribution).
- One `audit_logs` query for the window if drift attribution doesn't explain a regression.

## What NOT to do

- Don't extrapolate the trajectory into the future. Two datapoints don't make a forecast; communicate the observed change, not projections.
- Don't conflate "fewer findings" with "better security". Findings can drop because risk was accepted, not because the underlying issue was fixed — the audit-log driver attribution is what distinguishes the two.
- Don't rerun the analysis pass during the report cycle (`start_attack_path_analysis`). Trend stability requires the comparison to be against analysis cycles the caller already trusted.
