---
name: caido-proxy
description: "Caido proxy integration for HTTP history search, request replay, fuzzing results, sitemap, and security findings via MCP. Covers both the lightweight `caido` server and the full-surface `caido-go` server (batch send, race windows, intercept, environments, tamper rules, WebSocket streams). Use when you need to search proxy traffic, replay requests with modifications, triage fuzzing results, or document findings in Caido without writing code."
compatibility: "Requires a reachable Caido instance (CAIDO_URL) and at least one Caido MCP server connected."
---

# Caido Proxy

MCP integration with Caido proxy. Results load into context -- keep queries focused.

> If `python3 -c "import caido_sdk_client"` succeeds in the current runtime,
> prefer the **`caido-sdk`** skill instead — direct SDK calls avoid per-tool MCP
> round-trips and are more efficient. Use this MCP path when the SDK is not
> importable (its usual state outside the MCP's own env) or Caido is unreachable.

## Two MCP servers, one instance

The capability wires **both** Caido MCP servers; they target the same instance
via `CAIDO_URL` and can be used interchangeably or together.

| Server | Tools | Reach for it when |
|---|---|---|
| **`caido`** (Python) | 9 | history search, request detail, replay, scopes, findings |
| **`caido-go`** (Go) | 66+ | anything the lightweight one lacks: batch send, race windows, intercept queue, environments, filter presets, tamper (M&R) rules, WebSocket streams, sitemap, projects, workflows |

If a tool you want isn't in your schema, it's almost certainly on `caido-go`.
Tool names differ by prefix: the Python server exposes `caido_health`,
`caido_search_requests`, `caido_get_request`, `caido_replay_request`,
`caido_list_scopes`, `caido_create_scope`, `caido_list_findings`,
`caido_create_finding`, `caido_replay_sessions`. The Go server namespaces
everything as `caido_*` too (e.g. `caido_batch_send`, `caido_race_window_send`,
`caido_list_tamper_rules`) — check your live tool schema rather than assuming.

### Sibling non-MCP surfaces

- **`caido-mode`** — TypeScript CLI. Use for curl-through-Caido iteration,
  Match & Replace rules, and replay-session/collection handoff to the operator.
- **`caido-sdk`** — Python library for in-process read/replay.

### Credential redaction (`caido-go`)

The Go server **redacts** `Authorization`, `Cookie`, `Set-Cookie`, and API-key
headers in all output by default. On an authorized engagement where you need
real values (to replay a captured authenticated request, or produce a working
`caido_export_curl` PoC), set `CAIDO_ALLOW_SENSITIVE_HEADERS=true` in the
server env. If a replayed request unexpectedly 401s, suspect redaction before
suspecting the target.

## HTTPQL Quick Reference

```
req.host.eq:"example.com"           # Exact host match
req.host.cont:"example"             # Contains
req.path.cont:"/api/"               # Path contains
req.method.eq:"POST"                # Exact method
resp.code.eq:200                    # Status code
resp.code.gte:400                   # Greater than or equal

# Combinators
req.host.eq:"a.com" AND req.method.eq:"POST"
NOT req.path.cont:"/health"

# Security queries
req.header["authorization"].cont:"Bearer"
req.body.cont:"password"
resp.code.gte:500
```

## MCP Tools

> **Check your live tool schema first.** Names below are the complete surface of
> the **`caido` (Python)** server, taken from `mcp/caido.py`. Client runtimes
> namespace them differently (bare `caido_health`, or prefixed
> `mcp__caido__health`) — match whatever your schema actually shows. Anything
> not in this table lives on **`caido-go`**.

### `caido` (Python) — the full list, 9 tools

| Tool | Arguments |
|---|---|
| `caido_health` | — |
| `caido_search_requests` | `filter` (HTTPQL), `limit` = 20 |
| `caido_get_request` | `request_id`, `include` (comma string: `headers,body`) |
| `caido_replay_request` | `raw_request`, `host`, `port` = auto, `tls` = true |
| `caido_list_scopes` | — |
| `caido_create_scope` | `name`, `allowlist[]`, `denylist[]` |
| `caido_list_findings` | `filter`, `limit` = 20 |
| `caido_create_finding` | `request_id`, `title`, `description`, `reporter` = `dreadnode-agent`, `dedupe_key` |
| `caido_replay_sessions` | `limit` = 20 |

Note the argument style: `request_id` (singular, snake_case) and a comma-joined
`include` string — **not** an `ids` array or an `include` list. `caido_get_request`
fetches one request at a time.

### On `caido-go` only

Fuzzing/Automate (`caido_list_automate_sessions`, `caido_get_automate_session`,
`caido_get_automate_entry`), batch send, race windows, intercept, environments,
filter presets, tamper rules, sitemap, projects, workflows, WebSocket streams,
and `caido_export_curl`. If one of these is missing from your schema, the Go
server isn't connected — fall back to the equivalent Python tool or the
`caido-mode` skill.

## Common Workflows

### IDOR validation (`caido` Python server)
```
1. Search:   caido_search_requests(filter: 'req.path.cont:"/api/" AND req.method.eq:"GET"', limit: 50)
2. Inspect:  caido_get_request(request_id: "<id>", include: "headers,body")
3. Replay:   caido_replay_request(raw_request: "<modified request>", host: "target.com")
4. Document: caido_create_finding(request_id: "<id>", title: "IDOR in /api/users/{id}")
```

### Fuzzing result triage (requires `caido-go`)
```
1. caido_list_automate_sessions()
2. caido_get_automate_session(id: "<session_id>")
3. caido_get_automate_entry(id: "<entry_id>", limit: 20)
   Compare response sizes/codes for anomalies
```

## Troubleshooting

| Error | Fix |
|---|---|
| `Invalid token` | The Go server needs the **local instance access token**, not a Caido Cloud PAT (`caido_...`). Grab it in the Caido GUI devtools console: `JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken` → `CAIDO_ACCESS_TOKEN`. Or run `caido-mcp-server login` for OAuth (auto-refreshes). |
| `token expired, no refresh token` | Static access tokens last ~7 days; re-grab it, or switch to `caido-mcp-server login`. |
| `Unknown field collection on type ReplaySession` | Python `caido-sdk-client` < 0.3.0 against Caido >= 0.57. Upgrade to `>= 0.3.0`. |
| `Connection refused` | Caido isn't running, or `CAIDO_URL` points at the wrong port. |
| `No such tool` | Tool lives on the other Caido MCP server — check the table above. |
| `poll failed: timed out` | Target slow; fetch the result with the returned entry id. |

```bash
lsof -nP -i :8080 -sTCP:LISTEN   # Caido listening? (read-only check)
which caido-mcp-server           # Go MCP binary on PATH?
ls ~/.caido-mcp/token.json       # Shared OAuth token present?
```

> Diagnose read-only. Never kill a Caido process to "reset" it — the desktop app
> runs its backend as `caido-cli --listen`, so a broad `pkill` takes down the
> operator's running instance and their in-flight project state.
