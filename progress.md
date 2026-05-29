# Progress: Web-Security Issue Tracker Integrations

## Session Log

- Started implementation planning for ENG-6951, ENG-6952, ENG-6953.
- Confirmed repo is on `main` tracking `origin/main`; untracked `.claude/` exists and must be left alone.

## Branches / Worktrees

| Issue | Branch | Worktree | Status |
|---|---|---|---|
| ENG-6951 | `ads/eng-6951-jira-web-security` | `/Users/ads/git/capabilities-eng-6951` | implementation validated, uncommitted |
| ENG-6952 | `ads/eng-6952-linear-web-security` | `/Users/ads/git/capabilities-eng-6952` | implementation validated, uncommitted |
| ENG-6953 | `ads/eng-6953-github-web-security` | `/Users/ads/git/capabilities-eng-6953` | implementation validated, uncommitted |

## Validation Results

| Issue | Command | Result | Notes |
|---|---|---|---|
| ENG-6951 | `uv run pytest capabilities/web-security/tests/test_jira_mcp.py` | passed | 10 tests |
| ENG-6951 | `mypy capabilities/web-security/mcp/jira.py capabilities/web-security/tests/test_jira_mcp.py --ignore-missing-imports` | passed | no issues |
| ENG-6951 | `pre-commit run --files capabilities/web-security/capability.yaml capabilities/web-security/mcp/jira.py capabilities/web-security/tests/test_jira_mcp.py` | passed | check-yaml, ruff, ruff-format, gitleaks |
| ENG-6951 | `just validate` | passed with warnings | 0 failed; unrelated warnings for bloodhound-enterprise runtime imports, web-security caido/burp checks, windows Java |
| ENG-6951 | MCP startup smoke via Python subprocess timeout | passed | `uv run capabilities/web-security/mcp/jira.py` starts and remains running |
| ENG-6951 | `PYTHONPATH=capabilities/web-security/tools uv run pytest capabilities/web-security/tests` | passed | 146 passed, 7 existing pytest warnings |
| ENG-6952 | `uv run pytest capabilities/web-security/tests/test_linear_mcp.py` | passed | 11 tests |
| ENG-6952 | `mypy capabilities/web-security/mcp/linear.py capabilities/web-security/tests/test_linear_mcp.py --ignore-missing-imports` | passed | no issues |
| ENG-6952 | `pre-commit run --files capabilities/web-security/capability.yaml capabilities/web-security/mcp/linear.py capabilities/web-security/tests/test_linear_mcp.py` | passed | check-yaml, ruff, ruff-format, gitleaks |
| ENG-6952 | `just validate` | passed with warnings | 0 failed; same unrelated warnings as ENG-6951 |
| ENG-6952 | MCP startup smoke via Python subprocess timeout | passed | `uv run capabilities/web-security/mcp/linear.py` starts and remains running |
| ENG-6952 | `PYTHONPATH=capabilities/web-security/tools uv run pytest capabilities/web-security/tests` | passed | 147 passed, 7 existing pytest warnings |
| ENG-6952 | `git diff --check` | passed | no whitespace errors |
| ENG-6953 | `uv run pytest capabilities/web-security/tests/test_github_mcp.py` | passed | 10 tests |
| ENG-6953 | `mypy capabilities/web-security/mcp/github.py capabilities/web-security/tests/test_github_mcp.py --ignore-missing-imports` | passed | no issues |
| ENG-6953 | `pre-commit run --files capabilities/web-security/capability.yaml capabilities/web-security/agents/web-security.md capabilities/web-security/mcp/github.py capabilities/web-security/tests/test_github_mcp.py` | passed | check-yaml, ruff, ruff-format, gitleaks |
| ENG-6953 | `just validate` | passed with warnings | 0 failed; same unrelated warnings as ENG-6951 |
| ENG-6953 | MCP startup smoke via Python subprocess timeout | passed | `uv run capabilities/web-security/mcp/github.py` starts and remains running |
| ENG-6953 | `PYTHONPATH=capabilities/web-security/tools uv run pytest capabilities/web-security/tests` | passed | 146 passed, 7 existing pytest warnings |
| ENG-6953 | `git diff --check` | passed | no whitespace errors |
