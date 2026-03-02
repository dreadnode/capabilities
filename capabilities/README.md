# Capabilities (Canonical v1 Examples)

This directory is the canonical home for capability examples and defaults.

## Purpose

These examples are used as Slice A fixtures for:

1. capability schema validation
2. runtime loading/resolution tests
3. API/UI fixture coverage

## Structure

Each capability is a directory containing:

1. `capability.yaml` (required metadata/config manifest)
2. optional resource directories (`agents/`, `tools/`, `skills/`, `commands/`, `hooks/`)
3. optional support files (for example `mcp.json`, `README.md`)

## Included Canonical Examples

1. `dreadweb/`
- Internal port from `packages/dreadnode/capabilities/dreadweb`.
- Rich local tools + skills baseline.

2. `claude-example-plugin/`
- Direct port from `~/code/claude-plugins-official/plugins/example-plugin`.
- Commands + skills + MCP config baseline.

3. `claude-learning-output-style/`
- Direct port from `~/code/claude-plugins-official/plugins/learning-output-style`.
- Hook-focused baseline.

4. `ghost-security/`
- Direct port from `~/code/ghostsecurity-skills/plugins/ghost`.
- Security workflow + rich skills baseline.
