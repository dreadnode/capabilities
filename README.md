# Capabilities

- [Capabilities](#capabilities)
  - [Manifest](#manifest)
  - [Components](#components)
    - [Tools (`tools/`)](#tools-tools)
    - [Skills (`skills/`)](#skills-skills)
    - [Agents (`agents/`)](#agents-agents)
    - [MCP Servers (`mcp:` in manifest)](#mcp-servers-mcp-in-manifest)
  - [Discovery Rules](#discovery-rules)
  - [Catalog](#catalog)
  - [Local Development](#local-development)

Portable extension bundles that add agents, tools, skills, and MCP servers to Dreadnode.

## Manifest

Every capability is a directory with a `capability.yaml` at its root:

```yaml
schema: 1
name: my-capability        # kebab-case: [a-z0-9][a-z0-9-]*
version: "1.0.0"           # semver
description: What this capability does.

# Optional catalog metadata
author:
  name: Your Name
license: Apache-2.0
keywords: [security, scanning]
```

`schema`, `name`, `version`, and `description` are required. Everything else is optional.

## Components

Components are auto-discovered from conventional directories. Omit a directory to skip that component type. A capability must export at least one component.

### Tools (`tools/`)

Python files containing `@tool` functions or `Toolset` classes. Each `.py` file is imported at load time and scanned for tool definitions.

**Standalone tool:**

```python
# tools/scanner.py
import typing as t
from dreadnode.agents.tools import tool

@tool
def scan_target(url: t.Annotated[str, "Target URL"]) -> str:
    """Scan a URL for issues."""
    return "clean"
```

**Stateful toolset** (shared state across methods):

```python
# tools/http.py
import typing as t
from dreadnode.agents.tools import Toolset, tool_method

class HttpTools(Toolset):
    """HTTP client with persistent session."""

    base_url: str = "http://localhost"

    @tool_method
    async def get(self, path: t.Annotated[str, "Request path"]) -> str:
        """Send a GET request."""
        ...
```

Parameter descriptions come from `t.Annotated[type, "description"]`. Tool descriptions come from docstrings.

`Toolset` subclasses at module level are auto-instantiated with a no-arg constructor. If the constructor requires arguments, instantiate explicitly at module level instead.

Avoid expensive side effects at import time (network calls, subprocess launches). Defer initialization to tool invocation or `Toolset.__aenter__`.

Non-Python tools should use MCP servers instead.

### Skills (`skills/`)

Each skill is a subdirectory containing a `SKILL.md` file. The markdown body is the skill's instructions, passed to the model when invoked.

```
skills/
  code-review/
    SKILL.md              # required: frontmatter + instructions
    reference.md          # optional supporting files
    scripts/
      lint-check.sh
```

Frontmatter:

```yaml
---
name: code-review                              # optional, defaults to directory name
description: Reviews code for quality issues   # required
---

When reviewing code, check for...
```

Skills can reference supporting files in their directory. Use `${CAPABILITY_ROOT}` for absolute paths to the capability directory.

### Agents (`agents/`)

Markdown files with YAML frontmatter. The body after the closing `---` is the agent's system prompt.

```markdown
---
name: security-reviewer
description: Reviews code for security vulnerabilities
model: claude-sonnet-4-5-20250929
tools:
  scan-code: true
  check-deps: true
skills: [report]
---

You are a security review agent. Analyze code for OWASP Top 10 vulnerabilities.
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | No | Defaults to filename stem |
| `description` | Yes | When to use this agent |
| `model` | No | Model identifier; runtime picks if omitted |
| `tools` | No | Tool allow/deny rules (glob patterns, last match wins). Omit for unrestricted |
| `skills` | No | Skill allow-list. Omit for unrestricted |

### MCP Servers (`mcp:` in manifest)

For non-Python tools — shell scripts, remote APIs, Node.js tools:

```yaml
mcp:
  servers:
    code-analyzer:
      command: "${CAPABILITY_ROOT}/bin/analyzer"
      args: ["--stdio"]
```

Auto-discovers `.mcp.json` / `mcp.json` if `mcp:` is omitted. Set `mcp: {}` to disable.

## Discovery Rules

For `agents`, `tools`, and `skills`:

| Manifest state | Behavior |
|---|---|
| Field omitted | Auto-discover from conventional directory |
| `[]` | Disabled — nothing exported |
| `[path/to/extra/]` | Auto-discover conventional directory AND listed paths |

## Catalog

| Capability | Description |
|---|---|
| ai-red-teaming | AI red team assessment via Dreadnode AIRT SDK |
| crash-analysis | C/C++ crash analysis with rr, gcov, and multi-agent pipeline |
| dotnet-reversing | .NET assembly decompilation and analysis via ILSpy |
| exploit-feasibility | Binary exploit viability assessment |
| ghost-security | AI-native application security (SAST, SCA, secrets, DAST) |
| mythic-c2 | Mythic C2 framework integration |
| network-ops | Network operations and Active Directory exploitation |
| sliver-c2 | Sliver C2 framework integration |
| static-analysis | Semgrep-based static code analysis |
| web-security | Web application penetration testing |

## Local Development

The optimal method to developing capabilities and testing them, before pushing to this repository and therefore the registry is to copy your capabilities directory to `~/.dreadnode/capabilities` and then run `just dn tui` to test them with the agent.
