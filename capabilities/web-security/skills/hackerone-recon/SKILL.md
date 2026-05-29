---
name: hackerone-recon
description: Pre-engagement reconnaissance workflow using HackerOne MCP tools to enumerate program scope, study prior disclosures, and identify high-value targets. Use when starting a new HackerOne program engagement, building an asset inventory, or planning target selection before active testing.
---

# HackerOne Pre-Engagement Recon

Prerequisite: HackerOne MCP server running with valid credentials (`H1_USERNAME` + `H1_API_TOKEN`). Verify with `hackerone_health`.

## Phase 1: Program Intelligence

### 1.1 Retrieve program details
```
hackerone_get_program(program_handle="<handle>")
```
Extract: program type (bounty vs VDP), submission state, response metrics, bounty splitting, excluded vuln types, severity thresholds.

**Checkpoint:** If program is not accepting submissions, stop. If response metrics show >30 day triage, prepare stronger evidence.

### 1.2 Enumerate scope assets
```
hackerone_get_program_scope(program_handle="<handle>")
```
Record for each asset: type, identifier, bounty eligibility, max severity, per-asset instructions.

**Prioritize:** (1) bounty-eligible + critical severity cap, (2) wildcard domains, (3) API endpoints, (4) recently added assets.

### 1.3 Map accepted weaknesses
```
hackerone_get_program_weaknesses(program_handle="<handle>")
```
Record CWE categories accepted. You need `weakness_id` values for report submission.

## Phase 2: Prior Art Analysis

### 2.1 Study disclosed reports
```
hackerone_search_hacktivity(program="<handle>")
```
Identify: previously found vuln types, bounty amounts by severity, triage patterns. Avoid duplicating known findings.

### 2.2 Review your own history
```
hackerone_search_reports(program="<handle>")
```
Check for `informative`/`not-applicable` verdicts (understand rejections), `duplicate` (known issues), `triaged`/`new` (avoid testing same surface).

## Phase 3: Target Selection

1. Build asset inventory with types, bounty eligibility, max severity
2. Cross-reference with hacktivity -- deprioritize heavily-tested surfaces
3. Record `structured_scope_id` for each target
4. Record `weakness_id` for expected vuln types
5. Respect per-asset instructions and policy restrictions

**Checkpoint:** Before active testing, confirm you have: scope IDs, weakness IDs, asset inventory, and have read the full program policy.

## Phase 4: Report Submission

After the full pipeline (`assess_confidence` -> `report-preflight` -> `exploit-verifier` -> `report-writer`):

```
hackerone_submit_report(
    program_handle="<handle>",
    title="[Vuln Type] in [Component] Leads to [Impact]",
    vulnerability_information="<detailed report with PoC>",
    impact="<concrete impact statement>",
    severity_rating="<none|low|medium|high|critical>",
    weakness_id="<CWE weakness ID from Phase 1.3>",
    structured_scope_id="<scope asset ID from Phase 1.2>"
)
```

Monitor with `hackerone_get_report_activities`. Respond to triager questions via `hackerone_add_comment`.

## Anti-Patterns

- **Skipping Phase 1** -- wastes time on excluded categories, risks violating rules
- **Submitting without scope/weakness IDs** -- signals low researcher quality
- **Skipping verification pipeline** -- leads to `informative` verdicts
- **Ignoring hacktivity** -- submitting known duplicates damages signal score
- **Testing out-of-scope assets** -- findings closed as `not-applicable`
