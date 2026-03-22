---
name: skill-improver
description: Iteratively improves skill quality by reviewing a skill, fixing issues, and re-reviewing until the skill meets a clear quality bar.
allowed-tools:
  - Read
  - Edit
  - Write
  - Glob
  - Grep
---

# Skill Improver

Use this skill to tighten a `SKILL.md` and its supporting files through repeated review and cleanup.

## When to Use
- improving a newly written skill
- normalizing imported skills
- fixing weak descriptions, bad references, or missing usage guidance

## Review Loop
1. Review the target skill for structural issues.
2. Categorize findings as critical, major, or minor.
3. Fix critical and major issues first.
4. Re-read the skill and supporting files to confirm the fixes actually helped.
5. Repeat until no major problems remain.

## Quality Bar

### Critical
- invalid or missing frontmatter
- missing referenced files
- broken paths
- instructions that require unavailable runtime features

### Major
- vague description or trigger guidance
- unclear "when to use" boundaries
- excessive length without references
- imported platform-specific instructions that do not fit this runtime

### Minor
- wording polish
- formatting cleanup
- examples that can be made tighter

## Output
Summarize:
- what was wrong
- what changed
- what still needs manual follow-up
