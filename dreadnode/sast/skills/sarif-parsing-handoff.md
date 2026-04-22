---
name: sarif-parsing-handoff
description: Local handoff wrapper for the imported Trail of Bits `sarif-parsing` skill. Use when you need a reminder that SARIF processing should go through the Trail of Bits workflow.
---

# SARIF Parsing Handoff

This capability imports the Trail of Bits `sarif-parsing` skill from `trailofbits/static-analysis/skills/sarif-parsing/`.

## Directive

When the task is to parse, aggregate, deduplicate, diff, or post-process SARIF output:
- use the imported `sarif-parsing` skill
- keep this file only as a local pointer
- use `variant-analysis` or `fp-check` after parsing when the next step is verification or bug-family hunting

## Why

The imported Trail of Bits skill is better tailored for:
- SARIF structure-aware processing
- jq and scriptable workflows
- deduplication and diffing
- clean separation from scan execution

## Imported Skill

- `sarif-parsing`
