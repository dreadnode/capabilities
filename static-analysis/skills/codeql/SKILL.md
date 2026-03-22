---
name: codeql
description: Scans a codebase for security vulnerabilities using CodeQL. Supports database creation, analysis runs, custom modeling, and SARIF processing. Use when asked to run CodeQL, build a CodeQL database, or review CodeQL results.
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
---

# CodeQL Analysis

Run CodeQL in a structured way: build a good database first, then analyze it, then validate the output.

## Core Rule
Zero findings are not automatically a clean result. Always verify database quality before trusting the analysis.

## Resources
- [references/build-fixes.md](references/build-fixes.md)
- [references/quality-assessment.md](references/quality-assessment.md)
- [references/ruleset-catalog.md](references/ruleset-catalog.md)
- [references/sarif-processing.md](references/sarif-processing.md)
- [workflows/build-database.md](workflows/build-database.md)
- [workflows/create-data-extensions.md](workflows/create-data-extensions.md)
- [workflows/run-analysis.md](workflows/run-analysis.md)

## Workflow
1. If the user gave a database path, use it. Otherwise inspect the workspace for existing databases.
2. If multiple reasonable options exist and the user did not specify one, ask the user directly which database or path to use.
3. Build or rebuild the database if quality is poor or no suitable database exists.
4. Choose scan mode and rulesets.
5. Run analysis.
6. Process SARIF output and summarize the findings.

## Notes
- Prefer explicit suite files over ambiguous pack defaults.
- Use data extensions when project-specific wrappers would otherwise hide sources or sinks.
- Keep all outputs in a dedicated directory for reproducibility.
