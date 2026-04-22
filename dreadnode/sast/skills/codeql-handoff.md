---
name: codeql-handoff
description: Local handoff wrapper for the imported Trail of Bits `codeql` skill. Use when you need a reminder that CodeQL execution, database building, and modeling should go through the Trail of Bits workflow.
---

# CodeQL Handoff

This capability imports the Trail of Bits `codeql` skill from `trailofbits/static-analysis/skills/codeql/`.

## Directive

When the task is to run CodeQL, build a database, create data extensions, or process CodeQL SARIF:
- use the imported `codeql` skill, not this wrapper
- treat the Trail of Bits skill as authoritative
- keep this file only as local capability documentation

## Why

The imported Trail of Bits workflow is better tailored for:
- database quality checks
- data extension modeling
- explicit workflow gating
- result processing and output directory handling

## Imported Skill

- `codeql`
