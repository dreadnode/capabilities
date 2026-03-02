# Customizing the DreadAIRT Capability

This directory defines the **dreadairt** capability — a bundle of tools, skills,
and agent definitions for the DreadAIRT agent. The DreadAIRT agent uses the same
dreadnode runtime but loads this capability at startup when
`AGENT_CAPABILITY=dreadairt` is set.

## Quick Reference

| What | Where | Format |
|------|-------|--------|
| Agent definition | `agents/dreadairt.md` | Markdown with YAML frontmatter |
| Tool definitions | `tools.yaml` | YAML tool definitions |
| Tool scripts | `scripts/` | Python (stdin/stdout JSON protocol) |
| Skills | `skills/<name>/SKILL.md` | Each skill in its own subdirectory |

## Directory Structure

```
dreadairt/
├── capability.yaml                              # V1 capability manifest
├── tools.yaml                                   # Tool definitions (11 tools)
├── CUSTOMIZING.md                               # This file
├── agents/                                      # Agent definitions
│   └── dreadairt.md                             # Agent identity + workflow protocol
├── scripts/                                     # Tool implementations (stdin/stdout JSON)
│   ├── assessment_tracker.py                    # register, status, update assessment
│   ├── attack_runner.py                         # generate_attack, generate_category_attack
│   ├── goal_loader.py                           # list_goal_categories
│   ├── results_inspector.py                     # inspect output files, summarize analytics
│   └── workflow_helper.py                       # save/list Python workflow scripts
├── skills/                                      # Bundled knowledge skills
│   ├── attack-selection-guide/SKILL.md          # Decision tree for attack selection
│   ├── workflow-patterns/SKILL.md               # Complete Python workflow templates
│   ├── compliance-mapping/SKILL.md              # OWASP/ATLAS/NIST/SAIF mapping
│   └── analytics-interpretation/SKILL.md        # How to read analytics output
└── data/
    └── goals.csv                                # Bundled harm category goals
```

## Design Philosophy

DreadAIRT uses **11 orchestration tools** because the SDK does the heavy lifting.
The agent generates Python workflows and the SDK executes the actual attacks.
Compare with DreadWeb's fine-grained tools where the agent IS the attacker.

## 1. Agent (`agents/dreadairt.md`)

The agent definition contains the system prompt with workflow instructions,
parameter reference tables, model aliases, and example interactions.

## 2. Tools

Tool definitions live in `tools.yaml`, with implementations in `scripts/`.
Five scripts handle multiple tool methods each:

- **assessment_tracker.py** — `register_assessment`, `get_assessment_status`, `update_assessment_status`
- **attack_runner.py** — `generate_attack`, `generate_category_attack`
- **goal_loader.py** — `list_goal_categories`
- **results_inspector.py** — `inspect_results`, `get_analytics_summary`
- **workflow_helper.py** — `save_workflow`, `list_workflows`

All follow the shell runtime protocol: read JSON from stdin, write JSON to stdout.

## 3. Skills

Four knowledge skills provide the agent with reference material:

- **attack-selection-guide** — Which attacks to use for which goals
- **workflow-patterns** — Copy-paste Python templates
- **compliance-mapping** — Framework coverage matrices
- **analytics-interpretation** — How to read and present results

## Architecture Reference

For the full capability system API:
- Type definitions: `packages/dreadnode/src/capability/types.ts`
- Capability loader: `packages/dreadnode/src/capability/loader.ts`
- Capability wrapper: `packages/dreadnode/src/capability/wrapper.ts`
- Runtime protocol: `packages/dreadnode/src/capability/runtime.ts`
- Server runner integration: `packages/dreadnode/src/cli/server-runner.ts`
