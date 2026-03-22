---
name: second-opinion
description: Runs external LLM code reviews with Codex CLI or Gemini CLI on uncommitted changes, branch diffs, or specific commits. Use when the user asks for a second opinion or an external model review.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Second Opinion

Use an external review model when you want an independent pass over code changes.

## Supported Reviewers
- Codex CLI
- Gemini CLI

Reference invocation details:
- [references/codex-invocation.md](references/codex-invocation.md)
- [references/gemini-invocation.md](references/gemini-invocation.md)

## Workflow
1. Determine review scope: uncommitted diff, branch diff, or specific commit.
2. If the user did not specify reviewer or scope, ask them directly in plain text.
3. Build a focused prompt that states the review objective, such as security, correctness, or regression risk.
4. Run one or both external reviewers with the prepared diff or files.
5. Compare the findings and summarize only concrete issues.

## Notes
- Treat this as read-only review unless the user explicitly asks for remediation.
- If neither CLI is installed or authenticated, stop and report that limitation.
- The schema file for structured Codex output is available at
  [references/codex-review-schema.json](references/codex-review-schema.json).
