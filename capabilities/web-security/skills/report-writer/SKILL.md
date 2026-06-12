---
name: report-writer
description: Write HackerOne vulnerability reports from validated findings. Enforces evidence quality, pre-report gating, CVSS blocks, PoC rules, and clear reproduction steps. Use when writing a vulnerability report, drafting a submission, or converting validated findings into a deliverable.
---

# Vulnerability Report Writer

Converts validated, reproduced findings into structured vulnerability reports.

**This skill writes reports. It does NOT validate findings.** If the finding hasn't been reproduced with ground truth evidence, stop and validate first using the exploit-verifier skill.

## Pre-Report Gate

Before writing, confirm ALL of the following. If any fail, halt and state what's missing:

1. **Reproduced?** PoC executed, response matches expected vulnerable behavior
2. **Ground truth?** Evidence from actual HTTP responses, not inferred or differential
3. **Escalated?** Maximum demonstrable impact pursued (read one -> read all? self-only -> cross-user?)
4. **Scope confirmed?** Target and endpoint in-scope per program policy
5. **Not a known FP?** Cross-checked against exploit-verifier false positive patterns
6. **Preflight passed?** report-preflight skill returned ELIGIBLE or NEEDS_JUSTIFICATION with documented impact

If uncertain on escalation, state: "Impact may not be fully escalated. Consider: [suggestions]"

## Report Path

```
reports/R<NNN>-<slug>.md
```

NNN = next sequential number (zero-padded: 001, 002, ...). slug = lowercase-hyphenated summary.

## Confidence Trace

- Use the `trace_id` returned by the final `assess_confidence` call for this report.
- Copy that value into the report metadata so the report can be correlated with the confidence check.

## PoC Rules

- If Caido proxy is available, route curl commands through it: `curl -x http://localhost:8080 -k`
- Add `X-PoC-Step: step-X-<description>` headers to each request for proxy screenshot filtering
- Add bug bounty authorization header per program policy if required
- After each HTTP response block, add: `<!-- screenshot: [description] -->`
- If tokens/credentials required, first steps must show how to obtain them — no bare `<TOKEN>` placeholders
- Use `1.` for ALL step numbers (markdown auto-increments, avoids gaps on copy-paste)
- Reference JS source paths if discovered via static analysis

## Section Notes

- **Description**: If JS static analysis led to discovery, reference source paths
- **Impact**: If testing limitations exist (e.g., "only verified on free tier"), state inline after impact list
- **References**: Ground-truth only (OWASP, CWE, MITRE, vendor docs). Max 5
- **Recommendations**: Root cause fix first, then defense-in-depth. Concise and actionable

## Report Template

````markdown
---
confidence_trace_id: "<trace_id from assess_confidence>"
---

# Title

<!-- FORMAT: [Vulnerability Type] in [Component/Feature] via [Vector] Leading to [Impact] -->
<!-- Max ~85 chars, ~15 words. Specific about WHERE and WHAT. -->

# H1 Description

## Summary

<!-- ONE paragraph: what, where, business impact. Triager reading ONLY this understands the finding. No exploitation steps. -->

**Weakness:** <!-- Pick from H1 weakness type table below -->

**CVSS 4.0:** [`CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_`](https://www.first.org/cvss/calculator/4.0)

**CVSS 3.1:** [`CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=)

| | |
|---|---|
| **Asset** | <!-- Program asset name/URL from scope --> |
| **Endpoint(s)** | <!-- Affected API paths or URLs --> |
| **Parameter(s)** | <!-- Affected parameters, headers, or fields --> |
| **CWE** | <!-- e.g., [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) --> |

---

## Description

<!-- Technical root cause. 2-4 paragraphs. Do NOT repeat summary or PoC steps. -->
<!-- If root cause not determinable from black-box: state that explicitly. -->

---

## Proof of Concept

### Prerequisites (optional)

1. *e.g., Victim account must have X feature enabled*

### Setup (optional)

| | |
|---|---|
| **Accounts** | See role table below |
| **Other** | <!-- Any other requirements --> |

**Test Accounts:**

| Role | Email | Description |
|------|-------|-------------|
| Attacker | `attacker@example.com` | <!-- Role/permissions --> |
| Victim | `victim@example.com` | <!-- Role/permissions --> |

### Reproduction Steps

#### As the Victim

1. Sign into the application at `<target URL>`
1. Navigate to **Feature X** and observe current state

<!-- screenshot: victim baseline state -->

#### As the Attacker

1. Sign into the application at `<target URL>`
1. Navigate to **Feature X**
1. Observe/Intercept the following request:

> _Original request:_

```http

```

1. Forward this request to Replay/Repeater
1. Modify the request as follows:

<!-- State WHAT you changed and WHY -->

> _Modified request:_

```http

```

1. Observe the server response:

> _Server response:_

```http

```

<!-- screenshot: attacker receiving unauthorized data -->

#### As the Victim (verification)

1. Sign into the application at `<target URL>`
1. Observe that <!-- describe victim-visible impact or state it is silent -->

### Video PoC

_placeholder_

---

# H1 Impact

## Impact

<!-- Concrete demonstrated impact. Privilege escalation delta: BEFORE vs AFTER. -->

With this vulnerability, an attacker can:

1. **X**: Y
1. **Y**: Z

---

## References

- [CWE-XXX: Name](https://cwe.mitre.org/data/definitions/XXX.html)
- [OWASP Reference](https://owasp.org/)

## Recommendations

1. **Primary fix**: <!-- Root cause fix -->
1. **Defense-in-depth**: <!-- Additional hardening -->
````

## H1 Weakness Type Mappings

| Vulnerability Class | H1 Weakness Type |
|---|---|
| IDOR / Broken Access Control | Insecure Direct Object Reference (IDOR) |
| XSS (Stored/Reflected/DOM) | Cross-site Scripting (XSS) - Stored/Reflected/DOM |
| SSRF | Server-Side Request Forgery (SSRF) |
| SQLi | SQL Injection |
| Auth bypass | Improper Authentication |
| CSRF | Cross-Site Request Forgery (CSRF) |
| Info disclosure | Information Disclosure |
| Privilege escalation | Privilege Escalation |
| Business logic | Business Logic Errors |
| Open redirect | Open Redirect |
| Race condition | Time-of-check Time-of-use (TOCTOU) Race Condition |
| Prompt injection / AI | AI/ML Security or Privilege Escalation (context dependent) |

## Style

- Human-written tone. No AI slop, no excessive dashes, no tautology, no emojis.
- One vulnerability per report unless chaining required for impact.
- Concise — tight descriptions, no redundant prose.
- Technical — write for a security engineer, not a manager.
- Factual — state what happened, not what might happen.
- Both CVSS 4.0 and 3.1 required with clickable calculator links matching demonstrated impact.
- Never fabricate PoC output — every response block must be from actual execution.
- Include a control test showing non-vulnerable behavior (invalid key -> denied, unauthed -> 401) to prove the delta.
- Every impact claim must trace to a PoC step — if you claim "quota abuse", demonstrate batch requests succeeding.
- Delineate scope: document what doesn't work alongside what does to prevent inflation.
- If report-preflight returned NEEDS_JUSTIFICATION, include the justification block in Impact.
