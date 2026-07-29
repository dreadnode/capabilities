---
name: recursive-code-analysis
description: Use when code analysis, vulnerability research, or architecture mapping needs a durable worklist that can resume across context or session boundaries.
---

# Recursive code analysis

Traverse code through an explicit durable frontier. Store conclusions and
remaining work in Analysis Ledger items; do not rely on conversation history as
the coverage record.

## Start or resume

1. Resolve the canonical repository path, normalized objective, and immutable
   revision. Use the Git commit when available; otherwise compute and record a
   source fingerprint. Derive `run_key` as the first 24 lowercase hex characters
   of SHA-256 over `repository + "\n" + revision + "\n" + objective`.
2. Call `search_items` with the computed `run_key` and
   `item_type="analysis_run"` before creating one. Read candidates and resume
   only an exact
   `run_key`/objective/repository/revision match; never mix revisions.
3. Create a run with `report_item(item_type="analysis_run")`. Use a stable,
   project-unique ref prefixed with `analysis-`.
4. Survey structure with `glob`, `grep`, and `filemap` when available. Seed
   three to ten high-value targets, not every file. Favor entry points, sinks,
   trust boundaries, dispatchers, and nodes that gate deeper code.
5. Link each target to the run with `part_of`; link discovered children from
   their parent with `expands_to`.

Prefix target and claim refs with the run ref because refs are project-unique.
Use a stable path-and-symbol key and a deterministic run-prefixed target ref.
Resolve that exact ref before reporting; update an existing target instead of
duplicating it.

## Advance one target

Repeat this bounded iteration:

1. Call `analysis_progress`, then `analysis_next_targets`. Stop with a legible
   incomplete-scan error if `scan.complete` or `selection_complete` is false.
2. Read the selected target and relevant claims with the built-in `read_item`
   (by ref). If `target_state` is `queued`, set it to `in-progress` before
   investigating it. If it is already `in-progress`, resume it; this is
   single-agent crash recovery.
3. Inspect only the code neighborhood necessary to answer the target rationale:
   the complete definition, direct callers/callees, relevant validation, and
   nearby configuration. Keep bulk scanner output on disk and retain paths.
4. Record durable conclusions as `analysis_claim` items with a
   `claim_category` and concrete file:line or artifact `evidence_refs`. Link
   each claim to its target with `about`.
5. Try to refute security-relevant claims. Set the disposition to `verified`,
   `refuted`, or `unresolved`; never erase a refutation.
6. Add a child target only when evidence exposes a meaningful new path or
   uncertainty. Respect the run's maximum depth and target budget.
7. Update the target with a compact summary, `evidence_refs`, open questions,
   and a terminal `target_state` of `analyzed`, `blocked`, or `skipped`.
8. Update the run counters after the target completes:
   `iterations_completed += 1`; set `targets_discovered` to the current target
   count; reset `non_expanding_iterations` to zero when the iteration added a
   useful claim or child target, otherwise increment it.

For list-valued fields such as `evidence_refs` and open questions, send the
complete replacement list when updating because item data updates shallow-merge.

## Ground claims in shared taxonomy

Vulnerability `claim_category` records must carry a standard anchor so the
ledger speaks the vocabulary practitioners and reports use, not invented terms:

- Set the claim's `weakness` to the [CWE](https://cwe.mitre.org/) id (e.g.
  `CWE-89` for SQL injection) and, where the code is a web surface, the relevant
  [OWASP Top 10](https://owasp.org/Top10/) or
  [OWASP API Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
  category.
- Set the claim's `severity` from a [CVSS](https://www.first.org/cvss/)-style
  reading of impact and exploitability (`critical`/`high`/`medium`/`low`/`info`),
  justified by the recorded evidence rather than asserted.

## Promote findings

Create a built-in `finding` only after the vulnerability claim has:

- an attacker-controlled source or realistic precondition,
- a concrete path to impact,
- file:line evidence for the relevant controls and sink,
- an explicit attempt to disprove the issue,
- a `weakness` (CWE / OWASP) anchor and a CVSS-aligned `severity`,
- deployment assumptions and residual uncertainty.

The schema rejects a verified claim without `evidence_refs`; a verified
vulnerability also requires `weakness`, `severity`, and `impact`.

When promoting, carry the claim's `weakness` into the finding's `category` and
its `severity` into the finding's `severity` so the standard taxonomy survives.
Keep weaker observations as claims. Link a promoted finding to the verified
claim with `derived_from` and to the affected target with `affects`.

## Stop and report

Stop when any configured condition holds:

- the frontier is exhausted,
- the maximum target count or depth is reached,
- three consecutive targets add no valuable claim or child target,
- remaining work is blocked on unavailable tooling or user authorization.

Call `analysis_progress` and stop only when `scan.complete` and `stop_ready` are
both true, or when tooling/user authorization blocks progress. Update
`run_state` and `stop_reason`, then summarize:
revision and scope, target-state counts, verified/refuted/unresolved claims,
promoted findings, and the highest-priority remaining targets. A later session
must be able to continue from those records alone.

## Boundaries

- Use Items for the active frontier and durable conclusions, not as a complete
  AST or callgraph database.
- This is a single-agent loop. Claiming a target is not atomic; do not run two
  sessions against the same run.
- Platform connectivity, an active project, and an item-read grant are required
  for durable reads; item-write is also required for durable updates. Browse,
  read, and search with the built-in
  `list_items`, `read_item`, and `search_items`; use `analysis_next_targets` and
  `analysis_progress` for frontier control.
- The frontier tools ask server search to narrow candidates by `run_ref`, then
  exact-filter and scan at most 1,000 records of a type. They refuse to select
  or stop when that candidate scan is incomplete.
