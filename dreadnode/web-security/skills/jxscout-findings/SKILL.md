---
name: jxscout-findings
description: Create, retrieve, and list jxscout findings to document security-relevant discoveries. Use when you've identified a vulnerability, interesting gadget, security-relevant primitive, or anything a bug bounty hunter would want to track. Also use when the user wants to review, list, filter, or summarize existing findings.
license: proprietary
metadata:
  source: jxscout-pro-v2
  author: francisconeves97
  origin: ported from jxscout-pro-v2 agent skills
---

# jxscout Findings

Findings are how you document security-relevant discoveries in a jxscout project. They persist in the project database and are visible across tools.

## What deserves a finding

Create findings for things that have **real security value**:

- Confirmed vulnerabilities (XSS, IDOR, SSRF, open redirect, etc.)
- Interesting gadgets or primitives that could be chained into exploits (JSONP endpoints, postMessage handlers without origin checks, DOM clobbering gadgets, controllable redirect parameters)
- Security-relevant misconfigurations (missing CORS restrictions, overly permissive CSP, exposed debug endpoints)
- Sensitive data exposure (hardcoded secrets, API keys, internal URLs)

The bar is: **would a security researcher find this useful?** Not just full exploits -- useful building blocks count too.

**What to avoid**: purely theoretical risks with no supporting evidence. "This file uses eval()" is not a finding unless you can show how user input reaches it. Generic observations without context on exploitability or reachability are noise.

## Prerequisites

The `JXSCOUT_PROJECT_NAME` environment variable must be set. All commands use `jxscout-pro-v2 -c` (client mode).

## Commands

### Create a finding

```bash
jxscout-pro-v2 -c create-finding \
  --kind <kind> \
  --severity <low|medium|high|critical> \
  --description "What was found, where, and why it matters" \
  --dedup-key <unique_key> \
  --metadata '{"key": "value"}'
```

**Required:**
- `--kind` -- finding category. Use descriptive, specific kinds: `xss`, `idor`, `ssrf`, `open-redirect`, `postmessage-sink`, `gadget`, `secret-exposure`, `missing-origin-check`, `dom-clobbering`, etc.
- `--severity` -- one of `low`, `medium`, `high`, `critical`

**Optional:**
- `--description` -- concise explanation of what was found, where, and why it matters
- `--dedup-key` -- prevents duplicate findings. If a finding with the same kind and dedup key already exists, the command returns a dedup message instead of creating a duplicate. Use a stable identifier (e.g. the endpoint path, the file + line, or a hash of the pattern).
- `--metadata` -- arbitrary JSON for structured data (e.g. affected endpoints, parameter names, payload used)

Returns JSON:
```json
{"success": true, "finding_id": 42, "message": "Finding created with ID: 42"}
```

Or if deduplicated:
```json
{"success": false, "finding_id": null, "message": "Finding was deduplicated (already exists)"}
```

### List findings

```bash
jxscout-pro-v2 -c get-findings [options]
```

**Options (all optional):**
- `--severity <value>` -- filter by severity (repeatable): `low`, `medium`, `high`, `critical`
- `--kind <value>` -- filter by finding kind (repeatable)
- `--limit <n>` -- maximum number of findings to return
- `--offset <n>` -- number of findings to skip (for pagination)

Returns JSON with the matching findings and total count:
```json
{"findings": [{"id": 1, "severity": "high", "kind": "xss", "description": "...", "dedup_key": "...", "metadata": {...}, "found_at": "2026-02-28T12:00:00"}], "total": 42}
```

**Examples:**

List all findings:
```bash
jxscout-pro-v2 -c get-findings
```

List only critical and high severity findings:
```bash
jxscout-pro-v2 -c get-findings --severity critical --severity high
```

List findings of a specific kind with pagination:
```bash
jxscout-pro-v2 -c get-findings --kind xss --limit 10 --offset 0
```

### Retrieve a finding

```bash
jxscout-pro-v2 -c get-finding --kind <kind> --dedup-key <key>
```

Returns JSON with the finding details if it exists, or `{"found": false}` if not.

## Guidelines

- **Be specific in descriptions**: "postMessage handler in `/static/js/widget.js:145` accepts messages from any origin and passes `event.data.url` to `window.location.href`" is useful. "Possible open redirect" is not.
- **Use dedup keys** to keep findings clean. Good dedup keys: endpoint paths, `filename:line`, handler signatures.
- **Severity guide**:
  - `critical` -- direct impact with no user interaction (e.g. auth bypass, RCE)
  - `high` -- significant impact, may need minimal interaction (e.g. stored XSS, IDOR on sensitive data)
  - `medium` -- real impact but with limitations (e.g. reflected XSS needing specific conditions, CSRF on state-changing actions)
  - `low` -- interesting but limited impact (e.g. information disclosure, useful gadget for chaining)
- **Metadata** is useful for machine-readable details: `{"endpoint": "/api/users", "parameter": "callback", "payload": "javascript:alert(1)"}`.
- **Reference HTTP evidence**: if `http_requests/` exists in the project, you can reference captured request/response files in metadata (e.g. `{"evidence_request": "http_requests/target.com/api/users/GET/20260208_155236_200.req"}`) to tie findings to real traffic.
