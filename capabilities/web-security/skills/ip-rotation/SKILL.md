---
name: ip-rotation
description: Deploy Cloudflare Workers proxies (Flareprox) to bypass rate limiting, IP bans, and geo-blocking during web security testing. Use only when IPROTATE_ENABLED is set and the target is blocking normal requests. Triggers on "rate limited", "IP banned", "blocked by WAF", "429", "403", "geo-blocked", "rotate IP", "IP rotation", "flareprox".
---

# IP Rotation with Flareprox

**Activation gate:** Only use this skill when the environment variable `IPROTATE_ENABLED` is set (any value). If unset, do not suggest, reference, or offer IP rotation. Do not ask the user to enable it.

Flareprox deploys Cloudflare Worker proxies for IP rotation. It is built into the web-security capability — no external repository or binary is required.

## When to Use

Use IP rotation when normal testing hits anti-automation defenses:

- **Rate limiting:** repeated `429 Too Many Requests`
- **IP ban:** sudden `403 Forbidden` or connection drops after sustained testing
- **WAF block:** Cloudflare/Akamai/Imperva challenges on automated requests
- **Geo-blocking:** target restricts access to specific regions
- **High-volume fuzzing:** content discovery that needs IP diversity

Do NOT use for:

- Routine requests that succeed normally
- CORS-sensitive tests (the worker may modify response headers)
- Tests that require exact source-IP attribution

## How It Works

The tool deploys Cloudflare Workers that forward requests. You send the target URL in the `X-Target-URL` header or as the `?url=` query parameter. Each worker exits from a different Cloudflare IP, so spreading requests across multiple workers rotates egress IPs.

Forwarded headers: `accept`, `authorization`, `content-type`, `cookie`, `user-agent`, `x-bug-bounty`, `x-poc-step`.

## Prerequisites

Set these environment variables before creating workers:

- `CF_API_TOKEN` — Cloudflare API token with **Workers Scripts:Edit** permission
- `CF_ACCOUNT_ID` — Cloudflare account ID that owns the workers

Verify the account has workers.dev enabled.

## Tool Reference

All tools are prefixed `flareprox_` and are self-contained.

### 1. Check status

```bash
flareprox_status
```

Reports whether credentials are configured and how many workers are active.

### 2. Create workers

```bash
flareprox_create --count 3
```

Deploys three workers. More workers = more egress IPs to rotate through.

### 3. Send a request through the proxy

```bash
flareprox_request --url https://target.com/api/endpoint --method GET
```

The tool picks a worker round-robin, sets `X-Target-URL`, and returns the response.

### 4. Get a proxy URL for manual use

```bash
flareprox_proxy_url
```

Returns a worker URL. Use it with `execute_http` or shell tools by sending the target in `X-Target-URL`:

```bash
curl -H "X-Target-URL: https://target.com/api/endpoint" "<worker-url>"
```

### 5. List active workers

```bash
flareprox_list
```

### 6. Clean up

```bash
flareprox_cleanup
```

Deletes all deployed workers from Cloudflare. Always run when finished.

## Integration with Other Tools

- Prefer `flareprox_request` for single requests.
- For complex flows, get a `flareprox_proxy_url` and use it with `execute_http` or `bash`/`curl`.
- If Caido or Burp is available, chain through them for evidence capture:
  `target → Flareprox worker → Caido/Burp → internet` is incorrect. The correct chain is `your client → Caido/Burp → Flareprox worker → target`.

## Lifecycle Example

```bash
# Verify configuration
flareprox_status

# Deploy workers
flareprox_create --count 3

# Test a request
flareprox_request --url https://target.com/ --method GET

# Clean up when done
flareprox_cleanup
```

## Important Constraints

- **Always clean up** after a session to avoid leaving worker scripts in the Cloudflare account.
- **Do not use for CORS tests** — Cloudflare or the worker may add response headers.
- **Cloudflare IPs are fingerprintable** — sophisticated bot detection may still block known cloud IP ranges.
- **Each worker is dynamic** — any target can be reached by changing `X-Target-URL`.
- **State persists** at `~/.flareprox/workers.json` in the runtime.
