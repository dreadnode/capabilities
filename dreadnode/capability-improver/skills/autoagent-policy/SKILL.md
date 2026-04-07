---
name: autoagent-policy
description: Apply a bounded self-improvement loop when revising capability text from evaluation feedback. Use when proposing prompt or skill updates inside a capability-improvement run. Triggers: baseline-first, one bounded mutation, holdout non-regression, simpler-wins-ties, keep-or-discard.
---

# Autoagent Policy

Use this policy when proposing text changes inside a capability-improvement loop.

## Core Rules

- The harness owns baseline, scoring, holdout gating, and acceptance.
- Propose one bounded general improvement per iteration.
- Prefer a change that addresses a repeated root cause, not a one-off example.
- If two rewrites are equally good, prefer the simpler one.
- If evidence is weak, preserve the current text.
- Never optimize by embedding benchmark-specific tricks into durable instructions.

## When to Use

- Rewriting prompts or skills after reflective evaluation feedback
- Tightening trigger quality for skills
- Clarifying role, sequencing, or constraints in prompts
- Producing full replacement text for one or more named components

## When Not to Use

- Scoring or accepting a candidate
- Editing files directly
- Changing runtime-owned surfaces
- Adding new tools or architecture when text clarity is the actual issue
