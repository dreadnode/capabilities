---
name: vuln-critic
description: Adversarial pre-filter for scanner and agent findings. Scores findings as APPROVED/REJECTED/NEEDS_REFINEMENT before exploit verification. Saves testing time by filtering false positives early using pattern recognition and evidence quality assessment. Triggers on "critic", "pre-filter", "filter findings", "score findings", "triage findings", "review findings", "critique findings", "vuln-critic".
---

# Vulnerability Critic (Pre-Verification Filter)

Adversarial review agent inspired by Co-RedTeam's critic architecture. Runs BEFORE
exploit-verifier to filter findings and save testing time. Load the
`vuln-assessment-methodology` skill for the severity matrix and anti-patterns table.

**This skill does NOT test vulnerabilities.** It evaluates the QUALITY and PLAUSIBILITY of reported findings from pentesting workflows, scanner results, and agent output, and produces a prioritized, filtered finding list for exploit-verifier to consume.

## Critic Workflow

### Input

Accepts one or more findings in any format:
- Markdown scan results (`[target] Scan Results.md`)
- Raw agent output
- Scanner finding lists
- Static analysis match summaries

### Phase 1: Evidence Quality Assessment

For each finding, evaluate:

1. **Specificity**: Does the finding reference a concrete endpoint, parameter, and payload? Or is it vague ("the API may be vulnerable to injection")?
2. **Evidence Chain**: Is there a Source -> Flow -> Sink chain? Or just a sink observation?
3. **Reproduction Path**: Could someone reproduce this from the description alone?
4. **Technology Fit**: Is this vulnerability class compatible with the observed tech stack?

### Phase 2: False Positive Pattern Matching

Cross-reference against known false positive patterns:

**Instant Reject Patterns:**
- "Missing security header" without exploitation scenario
- "Information disclosure" of public data (product listings, public profiles)
- "Self-XSS" (attacker can only affect their own session)
- "Rate limiting missing" without brute force or abuse PoC
- Input reflected in JSON response body claimed as XSS
- IDOR with UUID/GUID resource IDs and no GUID leak
- CORS misconfiguration without `Allow-Credentials: true`
- GraphQL introspection enabled without sensitive schema exposure

**Needs Investigation Patterns:**
- Reflection in HTML context (could be encoded - needs testing)
- SSRF-like parameters (could have server-side validation)
- JWT with potentially weak algorithm (needs key testing)
- Path traversal candidate (could be normalized)

### Phase 3: Severity Calibration

Re-assess severity based on evidence, not agent claims:

| Agent Claims | Evidence Quality | Calibrated Action |
|---|---|---|
| Critical + strong evidence | Specific endpoint, clear PoC path | APPROVED - test first |
| Critical + weak evidence | Vague description, no PoC | NEEDS_REFINEMENT - gather more info |
| High + strong evidence | Concrete endpoint and payload | APPROVED - test second |
| High + weak evidence | Plausible but unverified | NEEDS_REFINEMENT |
| Medium + any evidence | Valid observation | APPROVED if evidence chain exists |
| Low/Info + any evidence | Best practice violation | REJECTED - not reportable |

### Phase 4: Prioritized Output

Produce a structured critic report:

```markdown
## Critic Report: [Target]
Date: [YYYY-MM-DD]
Total Findings Reviewed: [N]
Approved: [N] | Needs Refinement: [N] | Rejected: [N]

### APPROVED (Priority Testing Order)

#### [FINDING-001] [CWE-XXX: Vulnerability Name]
- **Original Severity**: [from agent]
- **Calibrated Severity**: [from critic]
- **Evidence Quality**: Strong/Moderate/Weak
- **Rationale**: [Why this is worth testing]
- **Test Priority**: [1-N]
- **Suggested Test Approach**: [Brief strategy]

### NEEDS_REFINEMENT

#### [FINDING-002] [CWE-XXX: Vulnerability Name]
- **Issue**: [What's missing from the evidence]
- **Required**: [What additional info would upgrade to APPROVED]
- **Quick Check**: [A fast test to confirm or reject]

### REJECTED

#### [FINDING-003] [Description]
- **Reason**: [Specific FP pattern match]
- **Pattern**: [Reference to false-positive-patterns.md]
```

## Critic Rules

### Evidence Standards
- **No finding is APPROVED without a specific endpoint/component identified**
- **No finding is APPROVED without a plausible attack scenario**
- **Severity calibration must reference actual demonstrated impact, not theoretical risk**
- **Agent's severity claims are NEVER trusted at face value**

### Decision Framework
- When in doubt between APPROVED and NEEDS_REFINEMENT: choose NEEDS_REFINEMENT (save testing time)
- When in doubt between NEEDS_REFINEMENT and REJECTED: choose NEEDS_REFINEMENT (avoid missing real bugs)
- REJECTED should only be used when the FP pattern is highly confident
- Quality over quantity: 3 well-vetted APPROVED findings > 10 unfiltered ones

### Handoff to Exploit Verifier
The critic report becomes the input for exploit-verifier's Triple-Check:
1. APPROVED findings go directly to Triple-Check, highest priority first
2. NEEDS_REFINEMENT findings get a quick recon pass before Triple-Check
3. REJECTED findings are documented in the validation report as "Filtered by Critic"

## Integration With "The Process"

When "do the process for X" is invoked:
1. Read agent findings
2. **Run vuln-critic** (this skill) to produce critic report
3. Test APPROVED findings via exploit-verifier Triple-Check
4. Quick-check NEEDS_REFINEMENT findings, upgrade or reject
5. Document all results in validation report

This pre-filtering step typically saves 60-80% of testing time by eliminating obvious false positives before hands-on verification.
