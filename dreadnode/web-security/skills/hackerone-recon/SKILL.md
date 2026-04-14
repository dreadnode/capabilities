---
name: hackerone-recon
description: Pre-engagement reconnaissance workflow using HackerOne MCP tools to enumerate program scope, study prior disclosures, and identify high-value targets before active testing.
---

# HackerOne Pre-Engagement Reconnaissance

Use this workflow at the start of any engagement against a HackerOne program. The goal is to fully understand the program's scope, rules, weakness taxonomy, and disclosure history before sending a single test request.

## Prerequisites

- HackerOne MCP server running with valid credentials (`H1_USERNAME` + `H1_API_TOKEN`)
- Run `hackerone_health` to verify connectivity and confirm your profile

## Phase 1: Program Intelligence

### 1.1 Retrieve Program Details

```
hackerone_get_program(program_handle="<handle>")
```

Extract and note:
- **Program type**: Bug Bounty (paid) vs VDP (no bounty). Adjust effort accordingly.
- **Submission state**: Is the program currently accepting reports?
- **Response metrics**: Average time to first response, resolution, and bounty award. Programs with slow triage (>30 days) require more patience and stronger evidence.
- **Bounty splitting**: If enabled, consider collaboration.
- **Policy**: Read the full policy. Look for:
  - Excluded vulnerability types (often: DoS, social engineering, self-XSS, rate limiting)
  - Required testing restrictions (no automated scanning, no production data access)
  - Safe harbor language and scope limitations
  - Minimum severity thresholds for bounty eligibility

### 1.2 Enumerate Scope Assets

```
hackerone_get_program_scope(program_handle="<handle>")
```

For each asset, record:
- **Asset type**: URL, WILDCARD, DOMAIN, CIDR, SOURCE_CODE, MOBILE_APPLICATION
- **Asset identifier**: The actual target (e.g., `*.example.com`, `https://api.example.com`)
- **Bounty eligibility**: Not all in-scope assets are bounty-eligible
- **Max severity**: Some assets cap severity (e.g., staging environments capped at medium)
- **Instructions**: Per-asset notes from the program (testing restrictions, focus areas)

**Prioritize by:**
1. Bounty-eligible assets with `max_severity: critical` — highest ROI
2. Wildcard domains — largest attack surface, most likely to have overlooked subdomains
3. API endpoints — often less hardened than main web apps
4. Recently added assets (cross-reference with bbscope_updates if available)

### 1.3 Map Accepted Weaknesses

```
hackerone_get_program_weaknesses(program_handle="<handle>")
```

This tells you which CWE categories the program accepts. Use it to:
- Focus testing on accepted weakness types
- Avoid wasting time on categories the program explicitly excludes
- Note the weakness IDs — you will need them when submitting reports via `hackerone_submit_report`

## Phase 2: Prior Art Analysis

### 2.1 Study Disclosed Reports (Hacktivity)

```
hackerone_search_hacktivity(program="<handle>")
```

Disclosed reports reveal:
- **What has been found before** — if 5 researchers found XSS in the search page, find something different
- **Bounty amounts by severity** — calibrate your expectations and prioritize accordingly
- **Program's bug preferences** — some programs reward certain vulnerability classes more generously
- **Triage patterns** — how the program classifies and responds to different finding types

### 2.2 Review Your Own Report History

```
hackerone_search_reports(program="<handle>")
```

If you have prior reports against this program:
- Check for `informative` or `not-applicable` verdicts — understand what the program rejects
- Review `duplicate` reports — what is already known
- Check `triaged` or `new` reports — avoid testing the same surface while reports are pending

## Phase 3: Target Selection

After completing Phases 1 and 2, synthesize your findings:

1. **Build the asset inventory**: All in-scope targets with their types, bounty eligibility, and max severity
2. **Cross-reference with hacktivity**: Remove heavily-tested surface areas, prioritize under-explored assets
3. **Identify the scope IDs**: For each target you plan to test, record its `structured_scope_id` — you will need this for report submission
4. **Note the weakness IDs**: For vulnerability types you expect to find, record the `weakness_id` values
5. **Set testing boundaries**: Respect per-asset instructions and program policy restrictions

## Phase 4: Report Submission (Post-Testing)

When you have a confirmed finding (after the full pipeline: `assess_confidence` → `report-preflight` → `exploit-verifier` → `report-writer`):

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

Including `weakness_id` and `structured_scope_id` improves triage speed and demonstrates thoroughness.

After submission, use `hackerone_get_report_activities` to monitor triage status and `hackerone_add_comment` to respond to triager questions.

## Anti-Patterns

- **Do not skip Phase 1.** Testing without reading the policy wastes time on excluded categories and risks violating program rules.
- **Do not submit without scope/weakness IDs.** Reports without these require manual triager classification and signal lower researcher quality.
- **Do not submit unverified findings.** The reporting pipeline (`assess_confidence` → `report-preflight` → `exploit-verifier` → `report-writer`) exists for a reason. Skipping it leads to `informative` verdicts and damaged reputation.
- **Do not ignore hacktivity.** Submitting duplicates of known issues damages your signal score.
- **Do not test out-of-scope assets.** Even if you find something, it will be closed as `not-applicable`.
