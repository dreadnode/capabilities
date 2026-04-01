---
name: review-code
description: >
  Reviews code changes on the current branch for PR readiness. Runs ruff formatting
  and pyright type checking, identifies logic errors and type mismatches, flags security
  concerns, and ensures proper docstrings and documentation. Use when the user asks to
  "review my code", "check if this is ready for PR", "review the branch", "pre-PR review",
  "check code quality", or before opening a pull request.
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Bash
---

# Review Code

Pre-PR code review workflow that validates formatting, types, logic, security, and documentation on the current branch's changes.

## Workflow

Run these steps sequentially. Fix issues as you find them before moving to the next step.

### Step 1: Identify Changed Files

Determine what changed on this branch relative to the base branch:

```bash
git diff --name-only --diff-filter=d main...HEAD -- '*.py'
```

Only review files that were added or modified on this branch. Do not review unchanged files.

### Step 2: Ruff Formatting and Linting

Run ruff format check and lint on all changed Python files:

```bash
ruff format --check <files>
ruff check <files>
```

If there are formatting issues, fix them:

```bash
ruff format <files>
```

If there are lint errors, review each one and fix where appropriate. For lint rules that are intentionally violated, add inline `# noqa: XXXX` comments with justification only when suppression is the correct choice.

### Step 3: Pyright Type Checking

Run pyright on all changed Python files:

```bash
pyright <files>
```

Fix any type errors found:

- **Missing type annotations**: add parameter and return type annotations to public functions and methods
- **Type mismatches**: fix incorrect types, bad assignments, wrong return types
- **Import errors**: fix missing or incorrect imports
- **Incompatible types**: resolve union type issues, None checks, narrowing

If pyright is not installed, inform the user and suggest `pip install pyright`.

### Step 4: Logic Errors and Type Mismatches

Read through each changed file's diff and review for:

- **Logic errors**: incorrect conditionals, off-by-one errors, wrong boolean logic, unreachable code, missing edge cases
- **Type mismatches**: runtime type issues that static checkers may miss (e.g., dict key assumptions, implicit conversions, wrong container types)
- **Error handling**: bare excepts, swallowed exceptions, missing error propagation, incorrect exception types
- **Resource management**: unclosed files/connections, missing context managers
- **Concurrency issues**: race conditions, missing locks, shared mutable state
- **API contract violations**: wrong argument order, missing required fields, incorrect return shapes

Fix any issues found. If a fix is non-trivial or ambiguous, flag it to the user rather than guessing.

### Step 5: Security Review

Review all changed code for security concerns:

- **Injection**: command injection, SQL injection, path traversal, template injection
- **Authentication/Authorization**: missing auth checks, privilege escalation paths
- **Secrets**: hardcoded credentials, API keys, tokens (even in tests, flag for review)
- **Deserialization**: unsafe pickle/yaml/json loading, untrusted input deserialization
- **Cryptography**: weak algorithms, bad randomness, hardcoded keys/IVs
- **Input validation**: missing sanitization, unchecked user input reaching sensitive operations
- **File operations**: TOCTOU races, symlink attacks, unsafe temp file creation
- **Dependency concerns**: known vulnerable patterns, unsafe dependency usage

For each security concern found, report it clearly with:

- **File and line number**
- **Issue description**
- **Severity** (critical / high / medium / low)
- **Recommended fix**

Fix issues where the fix is clear and safe. For complex security issues, report them and let the user decide.

### Step 6: Documentation Review

Check that all changed code has proper documentation:

- **Module docstrings**: every new Python file should have a module-level docstring explaining its purpose
- **Class docstrings**: every new or modified class should have a docstring describing its responsibility
- **Public method/function docstrings**: every public function or method should have a docstring with:
  - Brief description of what it does
  - Args (with types if not annotated)
  - Returns description
  - Raises (if applicable)
- **Inline comments**: complex logic should have explanatory comments
- **Type annotations**: public interfaces should have complete type annotations

Add missing docstrings and documentation. Follow the existing style in the codebase. Do not add docstrings to private helper methods unless the logic is non-obvious.

## Output Format

After completing all steps, provide a summary:

```
## PR Review Summary

### Formatting & Linting
- [x] ruff format: <status>
- [x] ruff check: <status>

### Type Checking
- [x] pyright: <status>
- Issues fixed: <count>

### Logic Review
- Issues found: <count>
- Issues fixed: <count>
- Flagged for user: <count>

### Security Review
- Issues found: <count>
- Severity breakdown: <critical/high/medium/low counts>
- Issues fixed: <count>
- Flagged for user: <count>

### Documentation
- Docstrings added: <count>
- Comments added: <count>
```

## Guidelines

- Only modify files changed on this branch. Never edit unrelated files.
- Make minimal, targeted fixes. Do not refactor or "improve" code beyond what is needed.
- If ruff or pyright config exists in `pyproject.toml` or config files, respect those settings.
- When in doubt about a fix, report it rather than changing it.
- Group related fixes into logical chunks so the user can review them easily.
