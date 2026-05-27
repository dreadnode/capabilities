---
name: jxscout-security-research
description: Coordinates end-to-end jxscout vulnerability assessment workflows including target enumeration, static analysis triage, and finding documentation -- routes to specific jxscout-* skills for each phase. Use when starting a new target assessment, planning attack surface mapping, performing security testing, finding vulnerabilities, or understanding how jxscout tools fit together.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

jxscout is a JS security analysis proxy -- intercepts traffic, ingests JS/HTML, runs static analyzers, reverses source maps, and maps client-side attack surface.

Prerequisites: `JXSCOUT_PROJECT_NAME` env var must be set (from project `.env`). All CLI commands use `jxscout-pro-v2 -c` (client mode).

## Routing Table

| Need | Skill | Key command |
|---|---|---|
| Query static analysis matches | `jxscout-static-analysis` | `jxscout-pro-v2 -c get-matches --match-kind <type>` |
| Document a finding | `jxscout-findings` | `jxscout-pro-v2 -c create-finding` |
| Bookmark interesting code | `jxscout-bookmarks` | `jxscout-pro-v2 -c bookmark create` |
| Send/replay HTTP requests | `jxscout-repeater` | `jxscout-pro-v2 -c repeater <path>` |
| Create custom analyzers | `jxscout-custom-analyzers` | edit `settings.jsonc` analyzer section |
| Map asset relationships | `jxscout-relationships` | `jxscout-pro-v2 -c get-loaded-js-files <url>` |
| Setup, settings, hooks | `jxscout-setup` | `jxscout-pro-v2 -c print-full-project-settings` |

## Research Workflow

### 1. Orient
```bash
# Understand what traffic was captured
ls http_requests/
# Check project settings
jxscout-pro-v2 -c print-full-project-settings
```

### 2. Enumerate attack surface
```bash
# List all match kinds available
jxscout-pro-v2 -c list-match-kinds --json

# Get high-value matches
jxscout-pro-v2 -c get-matches --match-kind secret --json --show-only-unseen
jxscout-pro-v2 -c get-matches --match-kind onmessage --json --show-only-unseen
jxscout-pro-v2 -c get-matches --match-kind path --json --show-only-unseen
```

**Checkpoint:** Record total unseen match counts per kind. Prioritize: secrets > sinks > onmessage > paths.

### 3. Triage matches
For each match: read surrounding code, trace data flow, assess exploitability.
- Sink with attacker-controlled input -> potential vulnerability, bookmark and investigate
- Interesting pattern but no clear exploit -> bookmark as gadget for later chaining
- False positive -> mark as seen: `jxscout-pro-v2 -c mark-matches-seen --match-ids 1,2,3`

### 4. Deep-dive interesting files
```bash
# What JS runs on a specific page?
jxscout-pro-v2 -c get-loaded-js-files https://target.com/app --json

# Which pages load a vulnerable script?
jxscout-pro-v2 -c get-js-file-loader-page /path/to/vulnerable.js --json
```

### 5. Test and validate
Use `jxscout-repeater` to replay/modify requests. Confirm findings with working PoCs.

### 6. Document
Log confirmed findings via `jxscout-findings`. Bookmark key code patterns via `jxscout-bookmarks`.

### 7. Automate patterns
If you spot a recurring pattern, create a custom analyzer via `jxscout-custom-analyzers`. Then retrigger: `jxscout-pro-v2 -c retrigger-events --subscriber analyzer`

**Checkpoint:** After each investigation round, verify all reviewed matches are marked seen (`--show-only-unseen` should return only new/unreviewed items).
