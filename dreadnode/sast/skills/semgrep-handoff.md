---
name: semgrep-handoff
description: Local handoff wrapper for the imported Trail of Bits `semgrep` skill. Use when you need a reminder that Semgrep scanning and ruleset orchestration should go through the Trail of Bits workflow.
---

# Semgrep Handoff

This capability imports the Trail of Bits `semgrep` skill from `trailofbits/static-analysis/skills/semgrep/`.

## Directive

When the task is to run Semgrep scans, choose rulesets, use Semgrep Pro, or merge Semgrep SARIF:
- use the imported `semgrep` skill
- use `semgrep-rule-creator` for custom rule authoring
- use `variant-analysis` for bug-family hunting after an initial finding

## Why

The imported Trail of Bits skills are better tailored for:
- multi-language scan orchestration
- explicit scan planning and approval gates
- third-party ruleset selection
- Semgrep rule authoring and test-first workflows
- systematic variant hunting

## Imported Skills

- `semgrep`
- `semgrep-rule-creator`
- `variant-analysis`
