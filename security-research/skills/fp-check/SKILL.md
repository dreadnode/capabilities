---
name: fp-check
description: Systematically verifies suspected security bugs to eliminate false positives. Produces true positive or false positive verdicts with documented evidence for each bug.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Write
  - Edit
---

# False Positive Check

Use this skill when the task is to validate a specific suspected bug, not to discover new ones.

## Core Rule
Do not report a vulnerability from pattern recognition alone. Every claim must survive:
1. precise restatement
2. complete source-to-sink tracing
3. exploitability validation
4. adversarial review of alternative explanations

## Workflow

### 1. Restate the claim
If the claim cannot be restated clearly, ask the user to clarify it before continuing.

Document:
- exact vulnerability claim
- alleged root cause
- trigger conditions
- expected impact
- attacker model
- execution context

For bug-class-specific checks, consult
[references/bug-class-verification.md](references/bug-class-verification.md).

### 2. Choose the path
- Use [references/standard-verification.md](references/standard-verification.md) for straightforward, single-component bugs.
- Use [references/deep-verification.md](references/deep-verification.md) for cross-component, async, concurrency, or otherwise complex bugs.

Perform the workflow yourself. If the original version of this skill mentions plugin agents or task graphs, treat those as methodology, not required runtime features.

### 3. Collect evidence
Use the templates in
[references/evidence-templates.md](references/evidence-templates.md)
and apply the gate checks in
[references/gate-reviews.md](references/gate-reviews.md).

### 4. Try to disprove the claim
Before concluding true positive, apply the false-positive heuristics in
[references/false-positive-patterns.md](references/false-positive-patterns.md).

## Output
Return one verdict per bug:
- `TRUE POSITIVE`
- `FALSE POSITIVE`
- `NEEDS MORE EVIDENCE`

Each verdict should include:
- the claim being tested
- the evidence chain
- any assumptions or blockers
- the reason competing explanations were rejected
