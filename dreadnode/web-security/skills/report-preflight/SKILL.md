---
name: report-preflight
description: Pre-submission eligibility check for bug bounty findings. Catches ineligible patterns, AI/scanner false positives, and generates impact justification for borderline lows. Use before writing a report or when assessing whether a finding is worth reporting.
---

# Report Preflight

Pre-submission eligibility gate. Run BEFORE committing to a report.

## Usage

```
/report-preflight <target> <finding-type> <severity> <one-line description>
```

Or invoke with no args during active testing to check the current lead.

## Process

### Step 1: Map finding against three tiers

**HARD INELIGIBLE** — Platform core ineligible (see Tier 1). Do not report regardless of program.

**SOFT INELIGIBLE** — Common AI/scanner over-inflation (see Tier 2). Reportable ONLY with demonstrated impact beyond the pattern itself.

**PROGRAM-SPECIFIC** — Check target program policy for per-program exclusions. Do not conflate with universal ineligibility.

### Step 2: Check against lists

#### Tier 1: Core Ineligible Findings

Universally ineligible across major bug bounty platforms. **Do not report.**

Source: [HackerOne Core Ineligible Findings](https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings). Other platforms (Bugcrowd, YesWeHack, Intigriti) maintain similar lists — check the specific platform's policy.

**Theoretical / unlikely user interaction:**
- Vulns only affecting unsupported/EOL browsers or OS
- Broken link hijacking
- Tabnabbing
- Content spoofing / text injection (no security impact)
- Self-exploitation (self-XSS, self-DoS) unless cross-account
- Attacks requiring physical device access (unless in scope)

**Theoretical / no real-world impact:**
- Clickjacking on pages without sensitive actions
- CSRF on non-sensitive forms (logout, language change, etc.)
- Permissive CORS without demonstrated exploitation
- Software version disclosure / banner identification / descriptive error messages or headers
- CSV injection
- Open redirects without additional security impact (no OAuth chain, no token theft)

**Missing hardening / best practices (not bugs):**
- SSL/TLS configuration opinions
- Lack of SSL pinning
- Missing jailbreak detection in mobile apps
- Cookie flags (missing HttpOnly/Secure) without demonstrated exploitation
- CSP configuration opinions
- Email security features (SPF/DKIM/DMARC)
- Most rate limiting issues

**Hazardous testing (never attempt):**
- DoS/DDoS / availability attacks
- Social engineering / phishing
- Notification/form spamming
- Attacks on physical facilities

#### Tier 2: Common AI/Scanner Over-Inflated Patterns

NOT vulnerabilities without specific proof of impact. **Reportable only with demonstrated exploitation.**

| Pattern | Not a bug because | IS a bug when |
|---------|-------------------|---------------|
| Source map exposure | Dev tooling artifact | Contains hardcoded secrets, API keys, or PII |
| `REACT_APP_*` env vars in webpack | Client-side config by design | Contains actual secrets (write-access API keys, not public client IDs) |
| Services returning 401/403 | Auth working correctly | Bypass found, or response body leaks data despite status code |
| CORS misconfiguration | Informational without exploit | Demonstrates credential theft or data exfil cross-origin |
| Staging/dev endpoint exposure | May be intentional | Contains real user PII, valid creds, or unauth admin access |
| Blind SSRF (boolean oracle only) | No demonstrated data access | Demonstrates port scanning, internal service interaction, or metadata access |
| Username/email enumeration | Low impact, often by design | Enables account takeover chain or violates privacy regulations |
| Rotated/expired credentials in JS | No longer valid | Still valid and grant access |
| Public OpenAPI/Swagger schemas | Documentation, not a vuln | Contains validated API keys or reveals exploitable unauth endpoints |
| Exposed admin panels | Access != vulnerability | Unauth access to sensitive data or actions |
| GraphQL introspection enabled | Often intentional | Reveals hidden mutations with unauth access |
| Verbose stack traces | Informational | Leaks secrets, internal IPs, or exploitable version info |
| Public .git directory | Depends on contents | Contains secrets, credentials, or sensitive source |
| "Dummy" data on staging | Test data, not real | Contains real PII or valid production credentials |
| Open redirect | Informational alone | Chains with OAuth token theft, session fixation, or phishing |
| Missing rate limiting | Best practice | Enables brute force with demonstrated account compromise |
| Subdomain takeover candidate | Often false positive | Verified against can-i-take-over-xyz and actually claimable |

#### Tier 3: Program-Specific Exclusions

Check the target's program policy for:
- Explicit out-of-scope vulnerability types
- Severity minimums (some programs only reward High/Critical)
- Specific endpoint or domain exclusions
- Testing restrictions

### Step 3: Render verdict

**ELIGIBLE** — No ineligible pattern matched. Proceed to report.

**NEEDS_JUSTIFICATION** — Matches soft-ineligible but has demonstrated impact. Generate the justification block (Step 4).

**INELIGIBLE** — Matches hard-ineligible or lacks demonstrated impact. Do not report. Log as a gadget or lead if useful as a chain component.

### Step 4: Generate justification block for NEEDS_JUSTIFICATION

For borderline findings (especially lows matching common ineligible patterns), include in the report:

> **Note for program review:** This finding surfaces a pattern commonly associated with [ineligible category]. However, the demonstrated impact differs materially: [concrete evidence with specifics]. Full reproduction steps and network evidence are provided below for independent verification. We acknowledge this is a nuanced scenario and present it based on the demonstrated impact rather than the pattern classification alone.

Adapt to the specific finding. No filler, no inflation — if the impact is genuinely low, say so honestly. The goal is to prevent instant triage-as-informational by surfacing evidence that distinguishes this case from the generic pattern.

### Step 5: Confidence check

After classification, use `assess-confidence` to evaluate the finding with the evidence gathered, exploitation demonstrated, and verdict from this preflight. If confidence is low, reconsider reporting. Document override reasoning if proceeding anyway.

## Skill Pipeline

```
vuln-critic (evidence quality) → report-preflight (eligibility) → exploit-verifier (confirmation) → report-writer (deliverable)
```
