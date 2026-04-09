---
name: component-rewrite
description: Rewrite capability-owned text components with full replacement values. Use when the requested component names include agent_prompt, capability_prompt, skill_description:*, or skill_body:* and the output must be strict JSON.
---

# Component Rewrite Guide

Use this guide when proposing replacement text for capability-owned components.

## Rewrite Rules

- Return full replacement text for each requested component.
- Keep component keys exactly unchanged.
- Do not invent missing components.
- Prefer focused edits over total rewrites when the existing text is mostly correct.
- Preserve stable structure unless the structure itself is causing failure.

## Component-Specific Guidance

### `agent_prompt`

- Clarify role, priorities, and stop conditions.
- Encode durable operating rules.
- Remove ambiguous or duplicative wording.

### `capability_prompt`

- Keep it short and cross-cutting.
- Use it to reinforce shared capability behavior, not to restate everything.

### `skill_description:*`

- Make triggering obvious.
- Say when to use the skill and why it helps.
- Avoid vague descriptions that could match unrelated tasks.

### `skill_body:*`

- Use imperative workflow steps and decision points.
- Add ordering when failures suggest the current flow is too loose.
- Keep examples only when they sharpen behavior.

## When to Use

- The harness requests component updates from reflective feedback
- A capability-improvement run needs stricter JSON-only replacement text
- The current failure pattern points to prompt or skill wording, not tooling

## When Not to Use

- The right fix is outside the requested components
- The evidence is too weak to justify changing durable text
- The task is to score candidates or decide acceptance
