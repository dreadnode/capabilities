---
name: nextjs-cache-poisoning
description: Internal cache poisoning in Next.js via stale cache entries and header manipulation. Use when target runs Next.js (/_next/ paths, x-nextjs-cache header, __nextjs_original-cache-control).
---

# Next.js Cache Poisoning

## Pattern
- `/_next/` paths in responses or `x-nextjs-cache` header (HIT/STALE/MISS)
- `x-nextjs-stale-time` or `__nextjs_original-cache-control` in responses
- SSR routes returning `s-maxage=31536000, stale-while-revalidate`
- `x-now-route-matches` header presence

## Probe
1. Identify SSR routes with aggressive cache headers (not `private, no-cache`)
2. Send request with injected `x-now-route-matches` header:
```
GET /target-page HTTP/1.1
Host: target.com
x-now-route-matches: 1
```
3. Target `/_next/data/{buildID}/page.json` directly with same header
4. If response contains user-controlled data (User-Agent, custom headers) AND `s-maxage` caching, the entry is poisoned for all visitors
5. Leverage `stale-while-revalidate` window — periodically re-inject to maintain poisoned entry

## Indicators
- `x-nextjs-cache: HIT` on subsequent requests returning attacker-controlled data
- Cached JSON endpoint (`/_next/data/`) contains injected content
- Other users receive poisoned response (verify with different session/IP)

## Chain With
- web-cache-deception-path (path delimiter confusion + Next.js cache)

## Reference
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
