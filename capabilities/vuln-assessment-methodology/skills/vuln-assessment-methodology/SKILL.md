---
name: vuln-assessment-methodology
description: "Load when performing vulnerability assessment in any domain. Enforces source-to-sink tracing, disprove-first analysis, threat-model-aware severity, and finding quality standards. Prevents false positives and severity inflation."
---

# Vulnerability Assessment Methodology

**The goal is accurate, honest findings — not volume.** One correctly-assessed
finding is worth more than ten inflated ones. A false positive or overstated
severity damages credibility and wastes human reviewer time.

## Hard Rules

### 1. NEVER report a sink without tracing the full data flow

Seeing a dangerous function is NOT a finding. You MUST trace the data from
**attacker-controlled source** through every transformation to the sink.

If sanitization or validation exists anywhere in the chain, the finding is
invalid unless you can demonstrate a specific bypass of that defense.

**Before reporting, answer these questions:**
- What is the attacker-controlled input? (HTTP request body, OTLP payload, env var, etc.)
- What transformations does it undergo? (encoding, parameterization, validation, etc.)
- Does any transformation neutralize the attack?
- Can you construct a concrete input that survives all transformations and triggers at the sink?

### 2. Try to DISPROVE your finding before reporting it

Once you suspect a vulnerability, actively look for evidence that it is NOT
exploitable. Read the FULL function, not just the dangerous line. Look for:
- Validation/sanitization functions called earlier in the same method
- Input filtering in the caller
- Authorization checks on the controller or route
- Type constraints that limit the input domain
- Configuration that must be explicitly set to enable the dangerous path

**If you find defensive code, your job is to either demonstrate a bypass
or downgrade/retract the finding.** Not ignore it.

### 3. Severity must reflect the ACTUAL threat model, not the vulnerability class name

"SQL injection" is not automatically HIGH. "No authentication" is not
automatically CRITICAL. Severity depends on:

**Source controllability:**
- HTTP request parameter from untrusted user → High source risk
- Configuration file set at deployment → Low source risk
- Environment variable set by platform operator → Low source risk
- Hardcoded constant → Not attacker-controlled at all

**Access prerequisites:**
- Unauthenticated from the internet → Highest risk
- Authenticated user → Lower risk (depends on user trust level)
- Requires network access to internal service → Lower risk (lateral movement required)
- Requires container/host access → Lowest risk (attacker already has code exec)

**Deployment context:**
- Public-facing API → Full severity
- Internal tool behind network isolation → Note the dependency on network controls
- Development/emulator tool → Consider intended use case
- Infrastructure component in a managed platform → Consider platform's security boundary

**Apply this matrix before assigning severity:**

| Source of dangerous input | Access required | Severity |
|---|---|---|
| HTTP request param | Unauthenticated, internet-facing | Critical/High |
| HTTP request param | Authenticated user | High/Medium |
| HTTP request param | Internal network only | Medium (note network dependency) |
| Config/env var | Container-level access | Low (defense-in-depth) |
| Hardcoded value (as sink input) | N/A | Not a finding (but hardcoded credentials are — see Severity Guide) |

### 4. Read the COMPLETE defensive code, not just the vulnerable line

Common mistake: seeing `bash -c "{command}"` and reporting "command injection,
no sanitization" — while the calling function has a `ValidateCommand()` method
that blocks `;`, `&&`, `||`, `|`, `>`, `<`, backtick, `$(`, etc.

If validation exists but is incomplete (e.g., blocks `;` but not `"`), report
the **specific bypass**, not "no sanitization." The severity should reflect the
narrowness of the bypass, not the theoretical impact of unrestricted injection.

**Example of correct reporting:**
- BAD: "Command injection via bash -c with no sanitization" (HIGH)
- GOOD: "Incomplete command validation in ValidateCommand() — blocks common
  injection chars but misses `\"`, allowing quote-escape breakout from bash -c
  wrapping. Exploitable via RunCommandAsync if API is reachable." (MEDIUM)

### 5. Configuration options are not vulnerabilities

A "dev mode" or "unsecured mode" that disables authentication is a **design
decision**, not a vulnerability — unless it can be enabled by an attacker or
is accidentally deployed in production with no safeguards.

### 6. Internal tools have different threat models

Internal/infrastructure tools (SRE agents, platform operators, admin dashboards)
often intentionally omit authentication because they rely on network isolation
(Kubernetes network policies, service mesh, private VNet). This IS an attack
surface if network isolation fails, but:

- Report it as a **dependency on network controls**, not as "missing security"
- Note what an attacker needs BEFORE they can reach the service
- Don't call it "CRITICAL" unless you have evidence it's internet-reachable

### 7. AI prompt injection is a design concern, not a code bug

Any AI feature that processes user-generated content inherently allows prompt
injection. This is a product design tradeoff, not an exploitable code
vulnerability — unless the AI output is used dangerously (fed into `eval()`,
used to construct SQL, rendered as HTML without encoding).

### 8. Distinguish application code from framework code

Focus on application-specific code. Don't report known framework behaviors
as vulnerabilities. Framework defaults are by definition expected behavior.

## Severity Assignment Guide

- **Critical**: Unauth RCE on internet-facing service, hardcoded prod credentials,
  authentication bypass allowing full admin access.
  You must demonstrate: attacker has no access prerequisites beyond a network connection,
  and impact is code execution or full data access.
- **High**: Authed RCE, SQL injection via HTTP params, stored XSS on sensitive pages,
  SSRF to internal services from internet-facing endpoints.
  You must demonstrate: attacker-controlled input reaches a dangerous sink with
  exploitable impact, even if some access is required.
- **Medium**: Incomplete validation bypass, internal-only exposure, defense-in-depth
  gaps, or issues with moderate impact (information disclosure, limited injection).
- **Low**: Defense-in-depth improvements (env var in SQL query, missing but
  non-exploitable sanitization), code quality issues that could become
  vulnerabilities if assumptions change.
- **Not a finding**: Dangerous function with complete upstream sanitization,
  configuration option working as documented, token parsed for metadata only,
  framework default behavior, theoretical attack requiring attacker to already
  have higher privileges.

## Reporting Standards

**Only use finding-report tools for:**
- Issues where you traced the data flow end-to-end
- Issues where you actively tried to disprove the finding and couldn't
- Issues with code evidence showing both the vulnerable path AND
  the absence (or bypass) of defensive code

**Severity in the report must:**
- Reflect the actual threat model, not the vulnerability class name
- State the access prerequisites explicitly
- Note any existing defensive code and why it's insufficient
- Be defensible under peer review by a senior security engineer

**Credential reports are for:**
- Actual hardcoded credentials (connection strings, API keys, passwords)
- NOT for misleading error messages, placeholder strings, or example values

## Quality Checklist (ALL must pass before reporting)

- [ ] Traced data flow from source to sink
- [ ] Checked for sanitization/encoding at every step
- [ ] Read the FULL function containing the dangerous code, not just the dangerous line
- [ ] Actively tried to disprove this finding
- [ ] Verified this is application code, not framework behavior
- [ ] Considered deployment context and threat model
- [ ] Can construct a concrete exploit input
- [ ] Severity reflects actual exploitability, not vulnerability class name
- [ ] Finding would survive review by a skeptical senior security engineer

## Anti-patterns

| Anti-pattern | Example | Why it's wrong |
|---|---|---|
| Sink-only analysis | "Dangerous function found → vuln" | Didn't check for upstream defenses |
| Ignoring defensive code | "Injection, no sanitization" when validation exists | Didn't read the full function |
| Class-name severity | "SQL injection → HIGH" regardless of source | Env var source ≠ HTTP param source |
| Feature-as-vulnerability | "Unsecured mode exists" | Documented design decision |
| Framework noise | "Framework uses cookies" | Expected framework behavior |
| Theoretical-only | "If an attacker could modify env vars..." | Attacker already has code exec |
| Quantity over quality | Reporting 10 low-confidence findings | 1 verified finding > 10 guesses |
| Context-free severity | "No auth → CRITICAL" on internal tool | Deployment model matters |
| Confirmation bias | Finding a sink, then rationalizing why mitigations don't count | Try to disprove first |
