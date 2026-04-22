# SAST Agent Skills

This directory contains security analysis skills for the SAST capability.

This capability imports several Trail of Bits skills directly so the SAST agent can use the more specialized implementations without duplicating them locally.

Imported Trail of Bits skills:
- `codeql`
- `semgrep`
- `sarif-parsing`
- `semgrep-rule-creator`
- `variant-analysis`
- `fp-check`

## Overview

Skills provide specialized knowledge and workflows that the SAST agent can reference during analysis.

## Available Skills

### Code Auditing

- **review-code** - Pre-PR code review: ruff, pyright, logic errors, security, and documentation
- **fix-review** - Verify fix commits address audit findings without introducing bugs
- **triage-priority** - Prioritize vulnerability findings by exploitability and impact
- **false-positive-filters** - Filters to avoid reporting false positives during security analysis
- **fp-check** - Imported Trail of Bits exploitability verification workflow for confirming true vs false positives

### Static Analysis Tools

- **codeql** - Imported Trail of Bits CodeQL workflow for database creation, modeling, and analysis
- **semgrep** - Imported Trail of Bits Semgrep scan orchestration
- **sarif-parsing** - Imported Trail of Bits SARIF parsing and processing guidance
- **semgrep-rule-creator** - Imported Trail of Bits workflow for authoring Semgrep rules
- **variant-analysis** - Imported Trail of Bits workflow for hunting bug variants
- **codeql-handoff** - Local pointer to the imported `codeql` skill
- **semgrep-handoff** - Local pointer to the imported `semgrep` skill
- **sarif-parsing-handoff** - Local pointer to the imported `sarif-parsing` skill
- **report-writer** - Convert validated findings into concise, evidence-driven vulnerability reports

### Security Domains

- **threat-modeling** - Systematic threat identification and risk assessment
- **supply-chain-security** - Analyze dependencies and supply chain risks
- **ci-cd-security** - CI/CD pipeline security analysis
- **compliance-check** - Security compliance verification
- **secure-code-patterns** - Reference patterns for secure coding

### PoC Development

- **file-construction-libraries** - Python libraries for constructing PoC input files

## Usage

Once skills support is available in the SDK, the agent will automatically:

1. Discover local `.md` files in this directory and imported skill directories on startup
2. Parse YAML frontmatter to extract name and description
3. Add skills to the system prompt under `<available_skills>`
4. Provide a `view_skill(name)` tool for the agent to access detailed content

The agent can then reference skills by name during analysis, viewing full content on demand to avoid overwhelming the context window.

## Skill Structure

Each skill follows this format:

```markdown
---
name: skill-name
description: Brief description for skill discovery
allowed-tools:  # Optional: restrict to specific tools
  - Read
  - Grep
---

# Skill Content

[Detailed guidance, workflows, patterns, etc.]
```

Supporting files (references, workflows, examples) are kept in subdirectories alongside the main skill file.

## Integration with SAST Agent

The skills complement the agent's core capabilities:

- **Tools** (glob, grep, read, ls, codesearch, report_vulnerability) provide codebase exploration
- **Skills** provide domain expertise on vulnerability patterns, analysis methodologies, and tool usage
- **Instructions** define the overall agent behavior and goals

Skills enable the agent to leverage security expertise without bloating the core prompt, maintaining focus while having deep knowledge available on demand.

For static-analysis domains where Trail of Bits ships a deeper workflow, the local SAST wrappers act only as handoffs and the imported Trail of Bits skills are the authoritative implementations.
