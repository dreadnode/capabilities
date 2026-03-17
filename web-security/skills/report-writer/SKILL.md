---
name: report-writer
description: Write structured vulnerability reports from validated findings. Enforces evidence quality, pre-report gating, and clear reproduction steps. Use when writing a vulnerability report, drafting a submission, or converting validated findings into a deliverable.
---

# Vulnerability Report Writer

Converts validated, reproduced findings into structured vulnerability reports.

**This skill writes reports. It does NOT validate findings.** If the finding hasn't been reproduced with ground truth evidence, stop and validate first using the exploit-verifier skill.

## Pre-Report Gate

Before writing, confirm ALL of the following. If any fail, halt and state what's missing:

1. **Reproduced?** PoC executed, response matches expected vulnerable behavior
2. **Ground truth?** Evidence from actual HTTP responses, not inferred or differential
3. **Escalated?** Maximum demonstrable impact pursued (read one → read all? self-only → cross-user?)
4. **Scope confirmed?** Target and endpoint within authorized testing scope
5. **Not a known FP?** Cross-checked against false positive patterns in exploit-verifier

If uncertain on escalation, state: "Impact may not be fully escalated. Consider: [suggestions]"

## Report Structure

Every report must contain these sections in order.

### Title

Format: `[Vulnerability Type] in [Component/Feature] via [Vector] Leading to [Impact]`

Be specific about where and what. Bad: "XSS found". Good: "Stored XSS in /api/comments via unescaped markdown rendering leading to session hijacking".

### Summary

One paragraph. A triager reading only this understands the finding — what, where, business impact. No exploitation steps here.

Include:
- Vulnerability class and CWE
- Affected asset and endpoint(s)
- Affected parameter(s), header(s), or field(s)
- CVSS score with vector string

### Description

Technical root cause. 2-4 paragraphs. Do NOT repeat the summary or PoC steps. If root cause is not determinable from black-box testing, state that explicitly.

### Proof of Concept

#### Prerequisites

State any setup requirements — test accounts, feature flags, specific user roles.

If multiple accounts are needed (e.g., IDOR, privilege escalation), list them:

| Role | Description |
|------|-------------|
| Attacker | Low-privilege user account |
| Victim | Standard user with target resource |

#### Reproduction Steps

Numbered steps. Each step must include:
- What action to take
- The full HTTP request (method, URL, headers, body)
- The server response proving the step worked
- What to observe and why it matters

Rules:
- No bare `<TOKEN>` or `<SESSION>` placeholders — first steps must show how to obtain credentials
- One variable per step so the reader can attribute each result
- Request/response pairs for every claim — no "then observe that it works"
- If a step requires waiting or timing, state the duration and why

#### Evidence

For each claim, provide the actual HTTP request and response. Format:

```
REQUEST:
POST /api/users/42/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"role": "admin"}

RESPONSE:
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 42, "role": "admin", "updated": true}
```

For multi-step exploits, document each step as a discrete request/response pair and explain the causal chain — why step 1 enables step 2.

### Impact

Concrete demonstrated impact. State what an attacker can achieve, not what "could" happen.

Format as privilege escalation delta — BEFORE vs AFTER:
- **Before:** Regular user with read access to own profile
- **After:** Can read and modify any user's profile including admin accounts

### Remediation

1. **Primary fix** — root cause fix (e.g., "add authorization check on /api/users/{id}/profile to verify requesting user matches resource owner")
2. **Defense-in-depth** — additional hardening (e.g., "implement rate limiting on profile endpoints, add audit logging for cross-user access attempts")

### References

Ground-truth only. Max 5.
- CWE reference with link
- OWASP reference if applicable
- Vendor documentation if relevant

## Style

- Concise — tight descriptions, no redundant prose
- Technical — write for a security engineer, not a manager
- Factual — state what happened, not what might happen
- One vulnerability per report unless chaining is required to demonstrate impact
