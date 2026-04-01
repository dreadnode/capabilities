# SAST Agent Skills

This directory contains security analysis skills adapted from [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills).

## Overview

Skills provide specialized knowledge and workflows that the SAST agent can reference during analysis. When the Dreadnode SDK includes skills support (feat/skills branch, expected in v1.18.0+), these skills will be automatically loaded and made available to the agent.

## Available Skills

### Code Auditing

- **audit-context-building** - Ultra-granular, line-by-line code analysis for building deep architectural context
- **differential-review** - Security-focused review of code changes with git history analysis
- **fix-review** - Verify fix commits address audit findings without introducing bugs
- **variant-analysis** - Find similar vulnerabilities across codebases using pattern-based analysis

### Static Analysis Tools

- **codeql** - CodeQL query writing and analysis guidance
- **semgrep** - Semgrep rule usage and pattern matching
- **semgrep-rule-creator** - Create and refine Semgrep rules for custom vulnerability detection
- **sarif-parsing** - Parse and analyze SARIF (Static Analysis Results Interchange Format) output

### Vulnerability Detection

- **sharp-edges** - Identify error-prone APIs, dangerous configurations, and footgun designs
- **entry-point-analyzer** - Identify state-changing entry points for security auditing

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
