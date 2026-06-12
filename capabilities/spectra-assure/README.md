# spectra-assure

Software supply chain security capability for Dreadnode, powered by
[ReversingLabs Spectra Assure](https://www.reversinglabs.com/products/spectra-assure)
via the [rl-mcp-community](https://github.com/reversinglabs/rl-mcp-community)
MCP server.

This wraps the Portal scanner (a Docker MCP) for deep behavioral binary analysis. For lightweight supply-chain lookups — secure.software Community catalogue search by purl/hash, plus OSV/Scorecard enrichment — see the sibling `secure-software` capability.

## What's in the box

| Component | Purpose |
|-----------|---------|
| `mcp: spectra-assure` | Wraps the `reversinglabs/rl-mcp-community:latest` Docker MCP server — exposes `rl_protect_scan`, `rl_protect_scan_manifest`, `rl_protect_summarize`, `rl_protect_interpret`, `rl_protect_diff_behavior` |
| `skills/spectra-assure` | Triage playbook: decision tree, canonical workflows, report format, compliance framing |
| `agents/supply-chain-analyst` | Autonomous analyst agent — scans, pivots on tampering signals, produces tiered remediation plans |

## Setup

1. Docker running locally (the MCP server ships as `reversinglabs/rl-mcp-community:latest`).
2. Spectra Assure token in env — `RL_TOKEN` with `rlcmm-` prefix (Community) or `rls3c-` prefix (Enterprise).
3. Enterprise only: also set `RL_PORTAL_SERVER` and `RL_PORTAL_ORG` (optional `RL_PORTAL_GROUP`).

Copy this capability into `~/.dreadnode/capabilities/spectra-assure/` and run `just dn tui` to try it.

## Demo

See [`docs/DEMO.md`](docs/DEMO.md) — the "Ultralytics Moment" narrative, built around the December 2024 PyPI compromise, showing how the agent would have blocked the merge two hours after the malicious version went live.
