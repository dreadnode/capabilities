# ai-red-teaming

An agent-driven harness for adversarially probing AI systems. The `ai-red-teaming-agent` extracts attack parameters from a request, generates a Python workflow against the target, executes it, and reports platform-tracked metrics. Each workflow assembles three pieces — an **attack algorithm** (iterative jailbreaks like TAP/PAIR/Crescendo, ML adversarial samplers like HopSkipJump), optional **transforms** that mutate the adversarial prompt (encoding, cipher, persuasion, MCP/multi-agent poisoning), and **scorers** that judge whether the target broke — and runs them as trials on the Dreadnode platform. Targets can be plain LLMs, agentic HTTP endpoints (tools/MCP/multi-agent), RAG pipelines, or traditional ML classifiers. The agent is a parameter extractor: it does not write attack code or interpret results, it drives the generator tools and relays raw platform numbers.

**Shape:** one agent (`ai-red-teaming-agent`, pinned to `claude-opus-4`), a Python tool surface (attack generation, workflow execution, assessment tracking, session context, platform analytics), and eight lazily-loaded skills (attack selection, transform/scorer reference, workflow patterns, compliance mapping, trace/analytics interpretation, troubleshooting). The attack-runner code generator and the catalogs of algorithms, transforms, and scorers live in `scripts/` and the skills — not here.

The attack catalog (45 algorithms, 500+ transforms, the scorer set, and 260 bundled harm goals across 25 sub-categories) is methodology, not setup — the agent enumerates it on request (`"show me all available attacks"`) and the skills document selection. This README is for standing the harness up.

## Setup

Configuration is entirely through the environment — the tools self-bootstrap their dependencies via `uv run`. No `.env` autoload; set these on the deployer (secrets screen or web app).

**Platform connection** (where assessments and trials are tracked):

| Var | Notes |
|---|---|
| `DREADNODE_API_KEY` | Required with `DREADNODE_SERVER` for sandbox mode. |
| `DREADNODE_SERVER` | Platform URL. |
| `DREADNODE_ORGANIZATION` / `DREADNODE_WORKSPACE` / `DREADNODE_PROJECT` | Scope the run; optional. |

If `DREADNODE_SERVER` + `DREADNODE_API_KEY` are unset, the runner falls back to a saved profile (`dreadnode login`). With neither, workflow execution aborts.

**Model provider keys** — the attack, attacker, and judge models can be any litellm-routable provider. Supply the matching key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, …) for whichever providers your target/attacker/judge models use; the runner warns at execution time when a model's key is missing. Alternatively, set `OPENAI_API_KEY` + `OPENAI_BASE_URL` to route prefix-less models through a LiteLLM proxy.

**Target endpoints** are not env config — they are passed as tool parameters at attack time: a model alias or full litellm path for LLMs, an `agent_url` (plus `agent_auth_type` and an `agent_auth_env_var` naming a platform secret) for agentic targets, or an `api_url` for ML classifiers. The skills cover the parameter shapes.

Outputs and session state land under `~/workspace/airt/` and `~/.dreadnode/airt/<org>/<workspace>/`; override with `AIRT_WORKFLOWS_DIR`, `AIRT_SESSION_PATH`, `AIRT_ASSESSMENT_PATH`.

## Usage

Drive it through the agent:

```
>>> @ai-red-teaming-agent Run TAP on gpt-4o, goal: extract the system prompt
>>> @ai-red-teaming-agent Full safety sweep on claude-sonnet
>>> @ai-red-teaming-agent Red team my agent at https://api.example.com/chat, make it execute shell commands
```

The agent picks a generator (`generate_attack`, `generate_category_attack`, `generate_agentic_attack`, `generate_image_attack`), executes the workflow, registers the assessment, validates the results, and reports the platform metrics. Session context carries target/goal/config across follow-ups so "now try Crescendo on the same target" reuses prior parameters.

## Before you trust it

- **This is offensive tooling against AI systems.** Attacks generate adversarial prompts, contact target endpoints, and attempt to elicit unsafe behavior. Only point it at models, agents, and endpoints you are authorized to test — the harm goals and prompts are test data, but the traffic to a target is real.
- **Agentic and ML attacks hit live endpoints.** `agent_url` / `api_url` attacks send real requests; agentic runs can invoke the target's tools. Scope auth and dangerous-tool lists deliberately.
- **Cost is query budget.** Iterative algorithms run hundreds to thousands of model queries per goal (see the per-attack budgets in the agent's table); a full category sweep multiplies that across 260 goals. Bound runs with `goals_per_category` and `n_iterations` before a kitchen-sink sweep.
- **The agent reports platform data only** — it never interprets ASR/risk scores or invents numbers. Deeper analysis lives in the platform web interface and the trace/analytics skills.
- **Compliance mappings are provenance, not a tour.** Goals and categories map to OWASP LLM Top 10, OWASP ASI01–ASI10, MITRE ATLAS, and NIST AI RMF; the `compliance-mapping` skill carries the crosswalk.
- Unit tests ship under `tests/` for the script layer (attack runner, goal loader, assessment tracker, results inspector, workflow helper); there is no live end-to-end target test.
