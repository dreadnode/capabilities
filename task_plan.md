# Task Plan: Web-Security Issue Tracker Integrations

## Goal

Implement Jira, Linear, and GitHub integrations for the `web-security` capability, one Linear task per isolated git worktree/branch:

- ENG-6951: Jira integration
- ENG-6952: Linear integration
- ENG-6953: GitHub integration

Each connector must pass formatting, linting, type checks, tests, `just validate`, and work with the Dreadnode TUI through the `web-security` capability before PR readiness.

## Constraints

- Use one unique worktree and branch per connector.
- Commit/push/open PR only when fully confident.
- Preserve existing repo patterns.
- Do not rename existing tools/agents/skills without need.
- Keep integrations efficient and scoped to validated finding/report export.
- Leave planning files uncommitted unless explicitly requested.

## Phases

| Phase | Status | Notes |
|---|---|---|
| Planning and base inspection | complete | Established worktrees, shared patterns, validation commands |
| ENG-6951 Jira | complete | Implemented, tests/pre-commit/mypy/validate/MCP smoke passed |
| ENG-6952 Linear | complete | Implemented, tests/pre-commit/mypy/validate/MCP smoke passed |
| ENG-6953 GitHub | complete | Implemented, tests/pre-commit/mypy/validate/MCP smoke passed |
| Final review | complete | Branches ready for human review; no commits/pushes/PRs made |

## Validation Checklist Per Branch

- `uv run pytest capabilities/web-security/tests/<connector test>`
- `pre-commit run --files <changed paths>`
- `just validate`
- capability/MCP load smoke test for Dreadnode TUI compatibility
- `git diff --check`

## Errors Encountered

| Error | Attempt | Resolution |
|---|---|---|
| `timeout` command unavailable on macOS during MCP smoke | ENG-6951 attempt 1 | Use Python `subprocess.run(..., timeout=...)` instead |
| Full web-security pytest collection could not import bare `bbscope` | ENG-6951 attempt 1 | Rerun with `PYTHONPATH=capabilities/web-security/tools` |
