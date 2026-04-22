---
name: report-writer
description: Write structured vulnerability reports from validated SAST findings. Enforces exploitability gating, evidence quality, and clear remediation guidance. Use when writing a vulnerability report, drafting a finding, or converting a validated issue into a deliverable.
---

# Vulnerability Report Writer

Converts validated SAST findings into structured vulnerability reports.

**This skill writes reports. It does NOT validate findings.** If the issue has not been confirmed with source-to-sink reasoning, concrete code evidence, and a plausible attacker path, stop and validate first.

## Pre-Report Gate

Before writing, confirm ALL of the following. If any fail, halt and state what is missing:

1. **Exploitability confirmed?** The finding has a concrete attacker-controlled source reaching a dangerous sink or security boundary failure.
2. **Evidence grounded?** The report cites actual files, functions, line numbers, data flow, or tool output. Do not rely on vague pattern matches alone.
3. **Impact demonstrated?** The report explains what an attacker gains in practice, not just the bug class.
4. **False positives checked?** The finding was cross-checked against sanitization, validation, authorization, or framework protections.
5. **Scope appropriate?** The issue is materially actionable and not a best-practice nit or speculative hardening note.

If uncertain on impact, state: "Impact needs stronger demonstration. Consider: [specific escalation path]"

## Report Structure

Every report should contain these sections in order.

### Title

Format: `[Vulnerability Type] in [Component/Function] via [Vector] Leading to [Impact]`

Be concrete. Bad: "Potential SQL injection". Good: "SQL Injection in `build_user_query()` via unsanitized `sort` parameter leading to arbitrary query execution"

### Summary

One paragraph. A reviewer reading only this should understand:
- Vulnerability class and CWE
- Affected file(s), function(s), and entry point(s)
- Attacker-controlled input
- Concrete impact

### Description

Explain the technical root cause in 2-4 paragraphs:
- Where tainted input enters
- How it propagates
- What sink or trust boundary it reaches
- Why existing checks do not stop exploitation

If any part of the chain is inferred rather than observed directly, say so explicitly.

### Evidence

Include precise references:
- File path and line numbers
- Relevant function names
- Key code snippets or tool findings summarized in your own words
- Any CodeQL, Semgrep, or custom scanner output that supports the claim

Rules:
- Do not dump raw tool output without interpretation
- Do not claim exploitability from a matcher hit alone
- Tie each piece of evidence to the attacker path

### Exploitation Path

Spell out the attacker workflow step by step:
1. Source of attacker control
2. Intermediate transforms or missing guards
3. Dangerous sink or authorization failure
4. Resulting attacker capability

For defense-sensitive findings, explicitly note the missing control:
- input validation
- output encoding
- parameterization
- path normalization
- permission check
- cryptographic verification

### Impact

State demonstrated or strongly supported impact, not hypothetical maximum impact.

Prefer BEFORE vs AFTER framing:
- **Before:** attacker can submit arbitrary template text
- **After:** attacker can trigger server-side template evaluation and execute attacker-controlled expressions

If the issue is high-confidence but full end-to-end exploitation depends on deployment details, say exactly which assumption remains.

### Remediation

1. **Primary fix**: address the root cause directly
2. **Defense-in-depth**: additional controls, logging, or validation that reduce blast radius

Recommendations should be implementation-oriented, not generic policy advice.

### References

Keep to relevant grounding:
- CWE
- OWASP or language/framework guidance
- Vendor or library documentation if the bug depends on specific behavior

## Style

- Concise
- Technical
- Evidence-driven
- One vulnerability per report unless chaining is required to show impact
