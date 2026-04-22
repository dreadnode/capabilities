---
name: report-writer
description: Write structured vulnerability reports from validated SAST findings. Enforces exploitability gating, evidence quality, and clear remediation guidance. Use when writing a vulnerability report, drafting a finding, or converting a validated issue into a deliverable.
---

# Vulnerability Report Writer

Converts validated findings into structured vulnerability reports.

**This skill writes reports. It does NOT validate findings.** If the finding has not been verified with concrete code evidence, source-to-sink reasoning, and a plausible attacker path, stop and validate first using `fp-check`.

## Pre-Report Gate

Before writing, confirm ALL of the following. If any fail, halt and state what is missing:

1. **Reproduced?** The claim is validated with source-to-sink reasoning or equivalent concrete evidence, not just a pattern match.
2. **Ground truth?** Evidence comes from actual files, functions, line numbers, code snippets, or tool output you can explain.
3. **Escalated?** The report pursues the maximum demonstrable impact supported by the code path.
4. **Scope confirmed?** The issue is materially actionable and not merely a best-practice gap or theoretical hardening note.
5. **Not a known FP?** The finding was checked against sanitization, validation, permission checks, framework protections, and other false-positive patterns.

If uncertain on escalation, state: "Impact may not be fully demonstrated. Consider: [specific escalation path]"

## Report Structure

Every report must contain these sections in order.

### Title

Format: `[Vulnerability Type] in [Component/Function] via [Vector] Leading to [Impact]`

Be concrete. Bad: "Potential SQL injection". Good: "SQL Injection in `build_user_query()` via unsanitized `sort` parameter leading to arbitrary query execution"

### Summary

One paragraph. A reviewer reading only this should understand the finding without reading the rest.

Include:
- Vulnerability class and CWE
- Affected file(s), function(s), and entry point(s)
- Attacker-controlled input or violated trust boundary
- Concrete impact

### Description

Technical root cause. 2-4 paragraphs. Do NOT repeat the summary or PoC steps.

Explain:
- Where tainted input enters
- How it propagates
- What sink or trust boundary it reaches
- Why existing checks do not stop exploitation

If any part of the chain is inferred rather than observed directly, say so explicitly.

### Proof of Concept

#### Prerequisites

State any setup requirements:
- repository or branch context
- build/runtime assumptions
- language or framework assumptions
- privilege requirements, if any

If no setup beyond reading the code is required, say so.

#### Reproduction Steps

Numbered steps. Each step must include:
- What the reviewer should inspect
- The relevant file/function/line references
- What the reviewer should observe and why it matters

Rules:
- One variable per step so the reader can attribute each conclusion
- Do not rely on a raw scanner hit without interpretation
- If a step depends on deployment assumptions, state them explicitly

#### Evidence

For each claim, include precise references:
- File path and line numbers
- Relevant function names
- Key code snippets or tool findings summarized in your own words
- Any CodeQL, Semgrep, or custom scanner output that supports the claim

Rules:
- Do not dump raw tool output without interpretation
- Do not claim exploitability from a matcher hit alone
- Tie each piece of evidence to the attacker path

#### Exploitation Path

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

For multi-step findings, explain the causal chain so the reviewer can follow why step 1 enables step 2.

### Impact

Concrete demonstrated impact. State what an attacker can achieve, not what "could" happen.

Prefer BEFORE vs AFTER framing:
- **Before:** attacker can submit arbitrary template text
- **After:** attacker can trigger server-side template evaluation and execute attacker-controlled expressions

If the issue is high-confidence but full end-to-end exploitation depends on deployment details, say exactly which assumption remains.

### Remediation

1. **Primary fix**: address the root cause directly
2. **Defense-in-depth**: additional controls, logging, or validation that reduce blast radius

Recommendations should be implementation-oriented, not generic policy advice.

### References

Ground-truth only. Keep to relevant grounding:
- CWE
- OWASP or language/framework guidance
- Vendor or library documentation if the bug depends on specific behavior

## Style

- Concise
- Technical
- Factual
- Evidence-driven
- One vulnerability per report unless chaining is required to demonstrate impact
