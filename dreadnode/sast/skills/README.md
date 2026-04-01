# SAST Agent Skills

This directory contains security analysis skills for the SAST capability.

Note: Several skills are available in the trailofbits capability and not duplicated here:
audit-context-building, differential-review, entry-point-analyzer, semgrep-rule-creator, sharp-edges, variant-analysis

## Overview

Skills provide specialized knowledge and workflows that the SAST agent can reference during analysis.

## Available Skills

### Code Auditing

- **fix-review** - Verify fix commits address audit findings without introducing bugs
- **triage-priority** - Prioritize vulnerability findings by exploitability and impact
- **false-positive-filters** - Filters to avoid reporting false positives during security analysis

### Static Analysis Tools

- **codeql** - CodeQL query writing and analysis guidance
- **semgrep** - Semgrep rule usage and pattern matching
- **sarif-parsing** - Parse and analyze SARIF (Static Analysis Results Interchange Format) output

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

1. Discover all `.md` files in this directory on startup
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
