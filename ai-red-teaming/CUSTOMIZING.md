# Customizing the DreadAIRT Capability

This directory defines the **dreadairt** capability — a bundle of tools, skills,
and system prompt customizations for the DreadAIRT agent. The DreadAIRT agent uses
the same dreadnode runtime but loads this capability at startup when
`AGENT_CAPABILITY=dreadairt` is set.

## Quick Reference

| What | Where | Format |
|------|-------|--------|
| System prompt | `system-prompt.md` | Markdown with YAML frontmatter |
| Tools | `tools.yaml` | YAML tool definitions |
| Skills | `skills/<name>/SKILL.md` | Each skill in its own subdirectory |
| Config | `capability.yaml` | YAML capability metadata |

## Directory Structure

```
dreadairt/
├── capability.yaml                              # Capability metadata
├── system-prompt.md                             # Agent identity + workflow protocol
├── tools.yaml                                   # 12 tool definitions
├── CUSTOMIZING.md                               # This file
├── data/
│   └── goals.csv                                # 261 goals (safety + security + agentic)
├── scripts/                                     # Tool implementations (stdin/stdout JSON)
│   ├── assessment_tracker.py                    # register, status, update assessment
│   ├── attack_runner.py                         # generate + execute attack workflows
│   ├── goal_loader.py                           # list categories, load goals from CSV
│   ├── results_inspector.py                     # inspect output files, summarize analytics
│   └── workflow_helper.py                       # save/execute/list Python workflow scripts
└── skills/                                      # Bundled knowledge skills
    ├── attack-selection-guide/SKILL.md          # Decision tree for attack selection
    ├── workflow-patterns/SKILL.md               # Python workflow templates
    ├── compliance-mapping/SKILL.md              # OWASP LLM/ASI, ATLAS, NIST, SAIF mapping
    └── analytics-interpretation/SKILL.md        # How to read analytics output
```

## Design Philosophy

DreadAIRT is an **orchestrator** — the agent generates Python workflows and the
SDK executes the actual attacks. The 12 tools cover assessment lifecycle, attack
generation/execution, goal management, results inspection, and workflow management.

## 1. System Prompt (`system-prompt.md`)

Mode: `replace` — completely replaces the base dreadnode prompt since the
DreadAIRT agent has a fundamentally different operating model (orchestrator
that generates and executes SDK-based Python attack workflows).

## 2. Tools

Five tool scripts, handling 12 tool methods:

- **assessment_tracker.py** — `register_assessment`, `get_assessment_status`, `update_assessment_status`
- **attack_runner.py** — `generate_attack`, `generate_category_attack`, `generate_agentic_attack`
- **goal_loader.py** — `list_goal_categories`
- **results_inspector.py** — `inspect_results`, `get_analytics_summary`
- **workflow_helper.py** — `save_workflow`, `execute_workflow`, `list_workflows`

All follow the shell runtime protocol: read JSON from stdin, write JSON to stdout.

## 3. Skills

Four knowledge skills provide the agent with reference material:

- **attack-selection-guide** — Which attacks/transforms/scorers for which goals and target types
- **workflow-patterns** — Python templates covering diverse providers and attack categories
- **compliance-mapping** — OWASP LLM Top 10, OWASP ASI01-ASI10, MITRE ATLAS, NIST AI RMF, SAIF
- **analytics-interpretation** — How to read and present results including agentic scorer output

## Architecture Reference

For the full capability system API:
- Type definitions: `packages/dreadnode/src/capability/types.ts`
- Capability loader: `packages/dreadnode/src/capability/loader.ts`
- Capability wrapper: `packages/dreadnode/src/capability/wrapper.ts`
- Runtime protocol: `packages/dreadnode/src/capability/runtime.ts`
- Server runner integration: `packages/dreadnode/src/cli/server-runner.ts`
