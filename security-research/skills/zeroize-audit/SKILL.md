---
name: zeroize-audit
description: Detects missing zeroization of sensitive data in source code and identifies zeroization removed by compiler optimizations, with source-level and compiler-artifact verification. Use for auditing C, C++, or Rust code that handles secrets.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Write
---

# Zeroize Audit

Audit secret cleanup in C, C++, and Rust codebases.

## Goal
Detect:
- missing source-level zeroization
- secret copies that are not wiped
- wipes removed by optimization
- partial wipes and cleanup gaps on error paths

## Inputs
The audit works best with:
- a repository path
- `compile_commands.json` for C or C++
- `Cargo.toml` for Rust

Reference schemas:
- [schemas/input.json](schemas/input.json)
- [schemas/output.json](schemas/output.json)

## Workflow
1. Run preflight checks and tool validation.
2. Perform source-level analysis using the references and helper tools in this skill directory.
3. Emit and compare IR, MIR, or assembly where applicable to confirm whether wipes survive optimization.
4. Generate a structured findings report.

Use these references and workflows as the execution guide:
- [references/detection-strategy.md](references/detection-strategy.md)
- [references/compile-commands.md](references/compile-commands.md)
- [references/ir-analysis.md](references/ir-analysis.md)
- [workflows/phase-0-preflight.md](workflows/phase-0-preflight.md)
- [workflows/phase-1-source-analysis.md](workflows/phase-1-source-analysis.md)
- [workflows/phase-2-compiler-analysis.md](workflows/phase-2-compiler-analysis.md)

## Compatibility Note
The original version of this skill used agent orchestration and optional semantic MCP helpers. In this repo, treat those documents as methodology only. Perform the phases directly with local files and bundled tools instead of relying on external task agents.
