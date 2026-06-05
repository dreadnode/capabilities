---
name: vuln-assessment-methodology
description: "Load when performing vulnerability assessment in any domain. Enforces source-to-sink tracing, disprove-first analysis, threat-model-aware severity, and finding quality standards. Prevents false positives and severity inflation."
---

# Vulnerability Assessment Methodology

**The goal is accurate, honest findings — not volume.** One correctly-assessed
finding is worth more than ten inflated ones.

## Hard Rules

### 1. NEVER report a sink without tracing the full data flow

Seeing a dangerous function is NOT a finding. Trace from **attacker-controlled
source** through every transformation to the sink. If sanitization exists, the
finding is invalid unless you demonstrate a specific bypass.

**Before reporting, answer:**
- What is the attacker-controlled input?
- What transformations does it undergo?
- Does any transformation neutralize the attack?
- Can you construct a concrete input that reaches the sink?

### 2. Try to DISPROVE your finding before reporting it

Actively look for evidence it is NOT exploitable. Read the FULL function. Look
for validation, input filtering, authorization checks, type constraints,
config gates. If you find defensive code, demonstrate a bypass or retract.

### 3. Severity must reflect the ACTUAL threat model

Assign severity by source, access, and context — not vulnerability class name.

| Source of dangerous input | Access required | Severity |
|---|---|---|
| HTTP request param | Unauthenticated, internet-facing | Critical/High |
| HTTP request param | Authenticated user | High/Medium |
| HTTP request param | Internal network only | Medium |
| Config/env var | Container-level access | Low |
| Hardcoded value (as sink input) | N/A | Not a finding (but hardcoded credentials are — see below) |

**What each level requires:**
- **Critical**: Unauth RCE, hardcoded prod credentials, full auth bypass. Attacker needs nothing beyond a network connection.
- **High**: Authed RCE, SQL injection via HTTP params, stored XSS, SSRF from internet-facing endpoint.
- **Medium**: Incomplete validation bypass, internal-only exposure, defense-in-depth gaps.
- **Low**: Defense-in-depth issues (env var in SQL), code quality that could become exploitable.
- **Not a finding**: Complete upstream sanitization, config-as-designed, token parsed for metadata only, framework defaults, attacker already needs higher privileges.

### 4. Read the COMPLETE defensive code

If validation exists but is incomplete (e.g., blocks `;` but not `"`), report
the **specific bypass**, not "no sanitization." Severity reflects the bypass
narrowness, not unrestricted injection impact.

- BAD: "Command injection via bash -c with no sanitization" (HIGH)
- GOOD: "Incomplete validation in ValidateCommand() — misses `\"`, allowing
  quote-escape from bash -c wrapping" (MEDIUM)

### 5. Configuration options are not vulnerabilities

Dev mode / unsecured mode is a design decision unless attacker-toggleable.

### 6. Internal tools have different threat models

Report missing auth on internal tools as a **dependency on network controls**,
not "missing security." Don't assign CRITICAL unless evidence shows internet
exposure.

### 7. AI prompt injection is a design concern, not a code bug

Not a code vulnerability unless AI output feeds `eval()`, SQL, or unencoded HTML.

### 8. Distinguish application code from framework code

Don't report framework defaults as vulnerabilities.

## Reporting Standards

Reports must:
- State access prerequisites explicitly
- Note existing defensive code and why it's insufficient
- Be defensible under peer review by a senior security engineer

Credential reports are for actual hardcoded secrets — not error messages,
placeholders, or example values.

## Anti-patterns

| Anti-pattern | Example | Why it's wrong |
|---|---|---|
| Sink-only analysis | "Dangerous function found → vuln" | Didn't check upstream defenses |
| Ignoring defensive code | "Injection, no sanitization" when validation exists | Didn't read the full function |
| Class-name severity | "SQL injection → HIGH" regardless of source | Env var source ≠ HTTP param source |
| Feature-as-vulnerability | "Unsecured mode exists" | Documented design decision |
| Framework noise | "Framework uses cookies" | Expected framework behavior |
| Theoretical-only | "If attacker could modify env vars..." | Attacker already has code exec |
| Quantity over quality | 10 low-confidence findings | 1 verified > 10 guesses |
| Context-free severity | "No auth → CRITICAL" on internal tool | Deployment model matters |
| Confirmation bias | Rationalizing why mitigations don't count | Try to disprove first |
