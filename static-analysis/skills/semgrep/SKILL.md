---
name: semgrep
description: Run Semgrep static analysis on a codebase. Supports broad scans, focused security scans, SARIF merging, and workflow-driven result review.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Semgrep Security Scan

Use this skill to run Semgrep systematically and report findings without losing scan context.

## Core Rules
- Always disable metrics.
- Show the planned rulesets and scope before long or expensive scans.
- Prefer reproducible output directories and merged SARIF artifacts.

## Resources
- [references/rulesets.md](references/rulesets.md)
- [references/scan-modes.md](references/scan-modes.md)
- [workflows/scan-workflow.md](workflows/scan-workflow.md)
- [scripts/merge_sarif.py](scripts/merge_sarif.py)

## Workflow
1. Detect the languages and technologies in the target.
2. Choose scan mode and rulesets.
3. If the user did not clearly approve the exact scan plan, ask for approval directly.
4. Run the scans. Parallelize by language when practical, but sequential execution is acceptable if no subagent system exists.
5. Merge SARIF output and summarize the highest-signal findings.

## Notes
- For custom rule authoring, use `semgrep-rule-creator`.
- For rule porting across languages, use `semgrep-rule-variant-creator`.
