# web-security

An autonomous web-application penetration-testing capability: a single agent runs OODA-loop testing against a live target, backed by 68 attack-technique playbooks (skills) and a proxy + recon toolchain. The agent maps the surface, selects attack classes from the playbooks, and works them to proof — request smuggling, cache poisoning, SSRF, SSTI, DOM/client-side, auth bypasses, parser differentials, AEM/Sling, and more.

**Shape:** one agent (`web-security`, autonomous), 68 skills grouped by attack family (loaded on demand — not enumerated here), ~9 HTTP/recon tool modules, and 10 MCP servers.

## MCP servers

| Server | Role |
|---|---|
| `caido`, `burp` | Intercepting proxies — Caido (host SDK) and Burp (external, see setup) |
| `agent-browser` | Headless Chromium for DOM interaction |
| `jxscout` | JavaScript recon — wraps `jxscout-pro-v2` and its SQLite projects |
| `protoscope` | Protobuf inspection |
| `thermoptic` | Local browser-fingerprint HTTP camouflage proxy |
| `hackerone` | Query programs, scopes, reports, hacktivity |
| `jira`, `github`, `linear` | File findings into trackers (token-gated — see setup) |

## Setup

This is the most install-heavy capability in the catalog — the agent and MCP servers shell out to a large external toolchain.

**Toolchain.** On a hosted sandbox the runtime provisions everything automatically from `scripts/install_tools.sh` (Go + ProjectDiscovery tools via `pdtm`, katana, protoscope, interactsh-client, kiterunner, surf, 2fa, caido-cli) plus the `default-jre-headless` package. For local dev, `docker/Dockerfile.runtime` bundles the same binaries — build and run it, or run `install_tools.sh` yourself. The `checks:` block surfaces anything missing (nuclei, httpx, interactsh-client, protoscope, caido-cli, waymore, jxscout, and Burp at `/opt/burp/burpsuite.jar`) in the capability manager.

**Burp is external**, not bundled — the capability expects a Burp instance exposing the MCP endpoint at `http://127.0.0.1:9876/`. Start Burp (with its MCP extension) before relying on the `burp` server; the other nine servers self-bootstrap via `uv run`.

**Optional integration credentials** — set via the secrets screen only for the servers you want live:

| Var | Enables |
|---|---|
| `JIRA_BASE_URL` / `JIRA_EMAIL` / `JIRA_API_TOKEN` | `jira` |
| `GITHUB_TOKEN` (+ `GITHUB_API_URL` for Enterprise) | `github` |
| `LINEAR_API_KEY` or `LINEAR_ACCESS_TOKEN` | `linear` |
| `CAIDO_URL` / `CAIDO_PAT` | `caido` (or its device-flow login) |

HackerOne and the proxies work without extra secrets once the toolchain is present.

## Before you trust it

- **Active, autonomous penetration testing.** The agent plans and executes attacks against a live target on its own, in continuous OODA loops, and is built to be exhaustive. Only point it at targets you are explicitly authorized to test, and scope it deliberately.
- **It generates real attacker traffic** — OOB callbacks (interactsh), crawling, fuzzing, payload delivery. Expect noise and load on the target.
- Attack methodology, payloads, and per-class playbooks live in `skills/` — that's the agent's knowledge base and where to look when extending it.
