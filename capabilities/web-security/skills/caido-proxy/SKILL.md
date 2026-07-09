---
name: caido-proxy
description: "Caido proxy integration for HTTP history search, request replay, fuzzing results, sitemap, and security findings via MCP. Use when you need to search proxy traffic, replay requests with modifications, triage fuzzing results, or document findings in Caido."
---

# Caido Proxy

MCP integration with Caido proxy. Results load into context -- keep queries focused.

> If `python3 -c "import caido_sdk_client"` succeeds in the current runtime,
> prefer the **`caido-sdk`** skill instead — direct SDK calls avoid per-tool MCP
> round-trips and are more efficient. Use this MCP path when the SDK is not
> importable (its usual state outside the MCP's own env) or Caido is unreachable.

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

### Search history
`mcp__caido__list_requests` -- search proxy history with HTTPQL
- `httpql`: filter string
- `limit`: max results (default 20, max 100)

### Get request details
`mcp__caido__get_request` -- full request/response
- `ids`: request ID array
- `include`: `["requestHeaders", "requestBody", "responseHeaders", "responseBody"]`

### Replay
`mcp__caido__send_request` -- send raw HTTP request
- `raw`: full HTTP request text
- `host`: target host
- `port`: target port (default 443)
- `tls`: use HTTPS (default true)

### Fuzzing results
`mcp__caido__list_automate_sessions` -- list fuzzing sessions
`mcp__caido__get_automate_session` -- session details
`mcp__caido__get_automate_entry` -- fuzzing results with pagination

### Findings
`mcp__caido__create_finding` -- document a security finding
- `requestId`: associated request ID
- `title`: finding title
- `description`: detailed description

## Common Workflows

### IDOR validation
```
1. Search: mcp__caido__list_requests(httpql: 'req.path.cont:"/api/" AND req.method.eq:"GET"', limit: 50)
2. Inspect: mcp__caido__get_request(ids: ["<id>"], include: ["requestHeaders","requestBody","responseHeaders","responseBody"])
3. Replay with modified ID: mcp__caido__send_request(raw: "<modified request>", host: "target.com")
4. Document: mcp__caido__create_finding(requestId: "<id>", title: "IDOR in /api/users/{id}")
```

### Fuzzing result triage
```
1. mcp__caido__list_automate_sessions()
2. mcp__caido__get_automate_session(id: "<session_id>")
3. mcp__caido__get_automate_entry(id: "<entry_id>", limit: 20)
   Compare response sizes/codes for anomalies
```

## Troubleshooting

| Error | Fix |
|---|---|
| `Invalid token` | Run `caido-mcp-server login` |
| `Connection refused` | Start Caido desktop app |
| `No such tool` | Check capability MCP config |

```bash
lsof -i :8080                          # Caido running?
which caido-mcp-server                 # Binary exists?
cat ~/.config/caido-mcp-server/token   # Authenticated?
```
