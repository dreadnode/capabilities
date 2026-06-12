---
name: ip-rotation
description: Use IP rotation proxies (flareprox and fireprox) to bypass rate limiting, IP bans, and geo-blocking during web security testing. Use only when IPROTATE_ENABLED is set and the target is blocking normal requests. Triggers on "rate limited", "IP banned", "blocked by WAF", "429", "403", "geo-blocked", "rotate IP", "IP rotation", "flareprox", "fireprox".
---

# IP Rotation

**Activation gate:** Only use this skill when the environment variable `IPROTATE_ENABLED` is set (any value). If unset, do not suggest, reference, or offer IP rotation. Do not ask the user to enable it.

The web-security runtime provides two IP rotation backends:

- **flareprox** — self-contained Cloudflare Workers proxy (built-in tool, no external install)
- **fireprox** — AWS API Gateway proxy (installed at `~/git/fireprox/fire.py`)

## When to Use

Use IP rotation when normal testing hits anti-automation defenses:

- **Rate limiting:** repeated `429 Too Many Requests`
- **IP ban:** sudden `403 Forbidden` or connection drops after sustained testing
- **WAF block:** Cloudflare/Akamai/Imperva challenges on automated requests
- **Geo-blocking:** target restricts access to specific regions
- **High-volume fuzzing:** content discovery that needs IP diversity

Do NOT use for:

- Routine requests that succeed normally
- CORS-sensitive tests (proxies may modify response headers)
- Tests that require exact source-IP attribution

## Backend Selection

| Backend | Use When | Cost | Target Binding | Notes |
|---|---|---|---|---|
| **flareprox** | Unauthenticated recon, fuzzing, scraping, multi-target | Free (100K/day) | Dynamic per request | Built-in `flareprox_*` tools |
| **fireprox** | Authenticated testing, session/cookie-based exploits | ~$3.50/1M req | Static: one proxy per target URL | Use `~/git/fireprox/fire.py` CLI |

**Decision:**
- Need cookies/sessions preserved? Use fireprox.
- Need dynamic multi-target rotation? Use flareprox.
- Unsure? Start with flareprox.

## flareprox (Cloudflare Workers)

Built into the capability. No external install required.

Prerequisites: `CF_API_TOKEN` and `CF_ACCOUNT_ID`.

Lifecycle:

```bash
flareprox_status
flareprox_create --count 3
flareprox_request --url https://target.com/api/endpoint --method GET
flareprox_cleanup
```

See the tool descriptions for full argument lists.

## fireprox (AWS API Gateway)

Installed in the runtime at `~/git/fireprox/fire.py`. Requires AWS credentials at runtime.

### Prerequisites

Set one of:
- `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- Or mount `~/.aws/credentials` in the runtime

### CLI Reference

Tool path: `python3 ~/git/fireprox/fire.py`

```bash
python3 ~/git/fireprox/fire.py --command create --url https://target.com --region us-east-1
python3 ~/git/fireprox/fire.py --command list
python3 ~/git/fireprox/fire.py --command delete --api_id <api-id>
```

### Lifecycle

```bash
# 1. Create a proxy for a specific target
python3 ~/git/fireprox/fire.py --command create --url https://target.com --region us-east-1

# 2. Note the proxy URL from the output, then use it
PROXY="https://<api-id>.execute-api.us-east-1.amazonaws.com/fireprox/"
curl -x http://localhost:8080 -k "${PROXY}api/endpoint"

# 3. Clean up when done to avoid AWS charges
python3 ~/git/fireprox/fire.py --command delete --api_id <api-id>
```

`fireprox` creates one API Gateway per target URL. The proxy URL prefix is static for that target; AWS rotates the egress IP automatically.

## Important Constraints

- **Always clean up fireprox proxies** after sessions to avoid AWS charges.
- **Do not use for CORS tests** — proxies may add response headers.
- **Cloud IPs are fingerprintable** — sophisticated bot detection may still block known AWS/Cloudflare IP ranges.
- **fireprox = one proxy per target URL** — create a new proxy for each target.
- **flareprox state persists** at `~/.flareprox/workers.json`.

## Integration with Caido/Burp

If Caido or Burp is available, chain traffic through them for evidence capture:

```
your client → Caido/Burp → flareprox/fireprox → target
```

For fireprox:

```bash
curl -x http://localhost:8080 -k \
  -H "Cookie: session=abc123" \
  "https://<api-id>.execute-api.<region>.amazonaws.com/fireprox/api/endpoint"
```

For flareprox, use `flareprox_request` or set `X-Target-URL` when using a worker URL manually.
