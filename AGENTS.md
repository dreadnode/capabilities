# AGENTS.md

Guidance for AI agents working in the capabilities repo.

Manifest fields, component types (agents / skills / tools / MCP / workers), and discovery rules live in the public docs at [docs.dreadnode.io/capabilities/overview](https://docs.dreadnode.io/capabilities/overview/). Read those before adding or restructuring a capability — this file covers repo-local conventions only.

---

## Layout

All capabilities live under `capabilities/`. Each is a directory with `capability.yaml` at its root plus any combination of `agents/`, `skills/`, `tools/`, `mcp/`, `workers/`, `tests/`.

---

## Validation

```bash
just validate                                         # every capability
pre-commit run --files <paths>                        # ruff, ruff-format, check-yaml, gitleaks
uv run --script <cap>/mcp/test_server.py              # when the capability ships tests
```

Run these before declaring work complete. Don't bypass hooks — fix the underlying issue.

---

## Authoring LLM-facing tools

- **Name the knob, not the mode.** A flag toggles what gets registered, it isn't the resulting mode. `apollo: on/off` beats `readonly: on/off`.
- **Defaults match the prescribing skill.** If the skill tells agents to pass `active_only=True`, that's the default. A default that contradicts documented usage is a trap.
- **Uniform return shapes within a family.** Don't mix `str` and `dict` returns across sibling tools — it forces the LLM to pattern-match.
- **Raise for failures; no `{"error": str}` unions.** FastMCP surfaces raised exceptions as tool-call errors. Clean for the LLM, clean for the return type.
- **Plain dicts, null-omitted, over Pydantic.** LLMs pay tokens for every null-coerced empty field. Return `dict[str, Any]`, drop `None`/`""`/`[]`/`{}`, keep `0` and `False`.
- **Disambiguate sibling tools by name.** Encode actor + action + destination when tools are close. Overloading one verb (three `download*` variants) is a pick-the-wrong-one landmine.
- **After renames, grep the skill/agent/doc layer.** Markdown callers don't fail a build, and LLMs read that prose to form tool-call intent.

---

## Reviewing tool layers

When asked "is this defensible?" or "good enough?", audit unit-by-unit — name clarity, arg disambiguity, return shape, docstring usefulness, defaults vs. prescribed usage — and return the honest punch list. The question is an invitation to find what isn't working, not a request for a rubber stamp.

---

## Design rules

- **Don't propose deleting a feature with active consumers.** A tool referenced by a skill, agent, or downstream capability is a sibling surface, not cruft. Subtraction applies only when the feature has actually lost its purpose. Ask before excising.
- **Check existing patterns first.** If other capabilities, hooks, or MCP servers already solve the concern, follow that pattern. Diverge only with a concrete reason.
- **Simplest fix first.** Don't introduce abstractions, plumbing, or shield patterns unless asked.

---

## MUST

- Run `just validate` and pre-commit before declaring work complete
- Semver-bump `capability.yaml` on breaking changes to a capability's public surface
- Type hints on public Python functions
- Update skill / agent markdown when tool names or args change

## NEVER

- Commit directly to `main` — use a feature branch and PR
- Bypass pre-commit hooks (`--no-verify`) to ship
- Invent tool / agent / MCP names — grep first
- Delete a capability, skill, or tool without confirming downstream consumers

## Ask first

- Deleting files
- Renaming tools, agents, or skills (ripples into markdown callers)
- Changing capability-level flags or env var contracts
