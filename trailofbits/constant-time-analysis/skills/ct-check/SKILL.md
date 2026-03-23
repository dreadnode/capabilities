---
name: ct-check
description: Detects timing side-channels in cryptographic code
argument-hint: "<source-file> [--warnings] [--json] [--arch <arch>]"
allowed-tools:
  - bash
  - read
  - grep
  - glob
---

# Check Constant-Time Properties

**Arguments:** $ARGUMENTS

Parse arguments:
1. **Source file** (required): Path to source file to analyze
2. **Flags** (optional): `--warnings`, `--json`, `--arch <arch>`, `--opt-level <level>`, `--func <pattern>`

Invoke the `constant-time-analysis` skill with these arguments for the full workflow.
