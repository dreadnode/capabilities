---
name: browser-side-channel
description: Browser-based side channel attacks for cross-origin data leaks via connection pool exhaustion, ETag oracles, and timing differentials. Use when direct XSS fails but cross-origin information leakage is needed.
---

# Browser Side Channel Attacks

## Pattern
- Cross-origin data leakage without XSS
- Need to detect state (logged in, admin, specific content) on another origin
- Target has detectable behavioral differences based on auth state or content

## Techniques

### XSS-Leak via Connection Pool Exhaustion (Chrome)
Exploit Chrome's per-process socket pool limit to leak cross-origin redirects:

1. **Saturate** Chrome's 256-connection pool (open 255 persistent connections)
2. **Trigger** a cross-origin navigation that may redirect based on state
3. **Measure** which host resolves next — Chrome resolves DNS in lexicographic order when pool is full
4. **Binary search** the leaked hostname character by character

Prerequisites: Victim visits attacker page, target redirects to different hosts based on auth state.

Test setup:
```javascript
// Saturate pool with 255 WebSocket connections to different hosts
for (let i = 0; i < 255; i++) {
  new WebSocket(`wss://pad-${i}.attacker.com/hold`);
}
// Trigger cross-origin fetch — redirect destination leaks via timing
fetch('https://target.com/auth-redirect', {mode: 'no-cors'});
// Measure: if redirect went to admin.target.com vs login.target.com
// the DNS resolution timing differs due to pool exhaustion ordering
```

### Cross-Site ETag Length Oracle (Express.js)
Exploit Express's default 16KB header limit to create a boolean oracle:

1. **Observe**: Express auto-generates ETag headers for responses
2. **Trigger**: Browser caches ETag, sends it back as `If-None-Match`
3. **Overflow**: Pad the request to approach 16KB header limit
4. **Differentiate**: If ETag is long (large response) → 431 error. If short → 304 Not Modified.
5. **Leak**: Response size reveals content (e.g., admin panel vs 403)

```http
GET /api/user/profile HTTP/1.1
If-None-Match: "cached-etag-value"
X-Pad: AAAA...AAAA  (pad to ~16KB minus ETag length threshold)
```
- 431 = ETag + padding exceeded 16KB → response was large (user exists, has data)
- 304 = ETag matched, response was small → different state

### Timing-Based State Detection
Measure response time differences for cross-origin requests:
```javascript
const start = performance.now();
const img = new Image();
img.onload = img.onerror = () => {
  const elapsed = performance.now() - start;
  // Authenticated responses often larger/slower than 302 redirects
  if (elapsed > THRESHOLD) { /* user is logged in */ }
};
img.src = 'https://target.com/dashboard-asset';
```

### Cache Probing
Detect if a user has visited a URL by measuring cache hit vs miss timing:
- Cached resource loads in ~1-2ms
- Network fetch takes 50ms+
- Reveals browsing history for same-origin resources

## Detection Checklist
1. Map target redirects that differ based on auth/role state
2. Identify response size differences between states (admin vs user vs anon)
3. Check if Express.js (ETag auto-generation) or similar framework in use
4. Test `performance.now()` timing resolution in target browser
5. Determine if attack requires user interaction or is fully passive

## Key Insight
These attacks don't require XSS — they exploit browser resource management (sockets, cache, headers) as an oracle. The information leaks through metadata (timing, status codes, resource limits), not content.
