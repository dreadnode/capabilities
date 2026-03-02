# Customizing the Dreadweb Capability

This directory defines the **dreadweb** capability — a bundle of tools, skills, hooks,
commands, and system prompt customizations for the Dreadweb agent. The Dreadweb agent
uses the same dreadnode runtime but loads this capability at startup when
`AGENT_CAPABILITY=dreadweb` is set.

> **Note**: This capability loading mechanism is temporary scaffolding. In the future,
> capabilities will become a first-class runtime concept with dynamic loading and a
> proper registry. For now, this directory is the single source of truth for all
> dreadweb customizations.

## Quick Reference

| What | Where | Format |
|------|-------|--------|
| System prompt | `system-prompt.md` | Markdown with YAML frontmatter |
| Tools | `capability.yaml` → `tools:` | YAML tool definitions |
| Skills | `skills/<name>/SKILL.md` | Each skill in its own subdirectory |
| Hooks | `capability.yaml` → `hooks:` | YAML hook definitions |
| Commands | `capability.yaml` → `commands:` | YAML slash command definitions |
| Stop conditions | `capability.yaml` → `stopConditions:` | YAML condition definitions |
| Config | `capability.yaml` → `config:` | YAML config field definitions |

## 1. System Prompt (`system-prompt.md`)

The system prompt file uses YAML frontmatter to control how it integrates with the
base dreadnode prompt:

```markdown
---
mode: extend
---

Your custom instructions here...
```

**Modes:**
- `extend` (default) — Your content is **appended** to the base dreadnode system prompt.
  The agent keeps all standard coding instructions plus your additions.
- `replace` — Your content **completely replaces** the base system prompt. Use this when
  you need full control over agent behavior. Skills prompts are still appended regardless.

## 2. Tools (`capability.yaml`)

Add tool definitions under the `tools:` key. Each tool needs:

```yaml
tools:
  - name: scan_url
    description: Scan a URL for common web vulnerabilities
    runtime: shell           # shell | http
    entry: tools/scan.sh     # Script path relative to this directory
    parameters:
      type: object
      properties:
        url:
          type: string
          description: The URL to scan
        depth:
          type: number
          description: Crawl depth (default 1)
      required: [url]
```

**Runtime types:**
- `shell` — Runs a local script (bash, python, node). The script receives JSON on stdin
  and should output JSON on stdout. See `src/capability/runtime.ts` for the protocol.
- `http` — Calls a remote HTTP endpoint. Use `endpoint`, `method`, and `headers` fields.

**Working example:** See `packages/dreadnode/examples/capabilities/hello-world/capability.yaml`

## 3. Skills (`skills/` directory)

Each skill lives in its **own subdirectory** under `skills/`, containing a `SKILL.md` file
and any supporting resources. The directory name must match the `name:` in the frontmatter.

```
skills/
├── owasp-top-10/
│   ├── SKILL.md
│   └── references/         # Optional: supporting files
│       └── checklist.md
└── recon-methodology/
    ├── SKILL.md
    └── scripts/
        └── enumerate.sh
```

Each `SKILL.md` needs YAML frontmatter:

```markdown
---
name: owasp-top-10
description: Guide for testing OWASP Top 10 vulnerabilities
allowed-tools: scan_url run_command
---

# OWASP Top 10 Testing Guide

## A01: Broken Access Control
...
```

Skills are auto-discovered because `skills: true` is set in `capability.yaml`.
The loader scans for subdirectories containing `SKILL.md` — loose files in `skills/` are ignored.

## 4. Hooks (`capability.yaml`)

Hooks react to agent events and can validate, transform, or control behavior:

```yaml
hooks:
  - name: validate-target
    event: ToolStart
    runtime: shell
    entry: hooks/validate-target.sh
    when:
      - toolName: [scan_url, run_command]
```

**Available events:** `ToolStart`, `ToolEnd`, `ToolError`, `GenerationStart`, `GenerationEnd`

**Hook return values:** `continue`, `retry`, `fail`, `finish`, or structured reactions
like `{ type: "retryWithFeedback", feedback: "..." }`.

## 5. Commands (`capability.yaml`)

Slash commands provide quick actions for users:

```yaml
commands:
  - name: scan
    description: Run a security scan on a target URL
    args: <url>
    prompt: |
      Please scan the web application at {{args}} for security vulnerabilities.
      Use available security tools and report findings.
```

## 6. Config (`capability.yaml`)

Config fields are read from environment variables or can be overridden:

```yaml
config:
  target_url:
    type: string
    description: Default target URL for scans
    env: DREADWEB_TARGET_URL
  scan_timeout:
    type: number
    description: Scan timeout in seconds
    default: 300
    env: DREADWEB_SCAN_TIMEOUT
```

## 7. Stop Conditions (`capability.yaml`)

Custom conditions for when the agent should stop:

```yaml
stopConditions:
  - name: max-scan-steps
    type: stepCount
    config:
      maxSteps: 20
```

**Built-in types:** `stepCount`, `generationCount`, `toolUse`, `anyToolUse`, `output`,
`toolOutput`, `toolError`, `noToolCalls`, `tokenUsage`, `elapsedTime`,
`consecutiveErrors`, `never`, `always`.

## Architecture Reference

For the full capability system API:
- Type definitions: `packages/dreadnode/src/capability/types.ts`
- Capability loader: `packages/dreadnode/src/capability/loader.ts`
- Capability wrapper: `packages/dreadnode/src/capability/wrapper.ts`
- Runtime protocol: `packages/dreadnode/src/capability/runtime.ts`
- Server runner integration: `packages/dreadnode/src/cli/server-runner.ts`
