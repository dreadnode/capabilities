---
name: timing-attack-recon
description: Discover hidden parameters, headers, and scoped SSRFs via server-side timing differentials. Use when traditional fuzzing returns uniform responses but you suspect hidden backend logic or internal proxy routing.
---

# Timing Attack Recon

Measure response time deltas to find attack surface invisible in response bodies. Server-side operations (DNS lookup, DB query, log write, proxy routing) add 5-50ms. Isolate these from network jitter using single-packet synchronization.

## Why This Exists

Standard fuzzing keys on status codes, body diffs, content-length. When the app returns identical responses regardless of input, timing is the only remaining signal. This technique found hidden parameters and scoped SSRFs that content-based fuzzing missed entirely.

## Eliminate Network Jitter First

Server-side deltas are 1-50ms. Network jitter is 10-100ms+. You **must** eliminate jitter or you'll drown in noise.

**HTTP/2 single-packet**: Send N requests multiplexed in one TCP packet. All arrive within ~1ms. Compare response times — delta is pure server-side.

**HTTP/1.1 last-byte sync**: Open N connections, send all but final byte, release final bytes simultaneously. ~4ms spread.

Use Turbo Intruder's single-packet attack mode or `curl --parallel` over H2.

## Baseline

Before testing, establish what "normal" looks like:
1. Send 20 identical requests via single-packet
2. Record response times
3. Calculate mean and stddev
4. Anything >2 stddev above mean on a specific input = signal

## Hidden Parameter Discovery

Add candidate parameters one at a time. Parameters that trigger server-side logic add measurable delay.

**Why parameters cause delays:**
- DNS lookup on parameter value (app tries to resolve it)
- Log write for unexpected parameter name
- Validation/regex check on specific parameter names
- DB query triggered by parameter presence (feature flags, debug modes)

```bash
# Manual with curl timing
for param in debug admin internal test verbose trace; do
  time curl -s -o /dev/null -w "%{time_total}" "https://target.com/api?${param}=1"
done
```

**Better**: Use Param Miner (Burp) which automates this with statistical analysis, or Turbo Intruder with timing comparison.

Consistent 5ms+ delta on a specific parameter = that parameter triggers backend logic. Investigate further even if the response body is unchanged.

## Hidden Header Discovery

Same principle. Add candidate headers, measure timing.

Priority headers to test:
- `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`
- `X-Debug`, `X-Debug-Token`, `X-Admin`, `X-Internal`
- `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`

## Scoped SSRF Detection via Timing

This is the highest-value technique. Detect proxy endpoints that route to internal services — even when responses are identical.

**How it works**: A proxy that allows certain domains routes requests internally (fast). Blocked domains either timeout or get rejected (different timing). Even if both return `200 OK` with identical bodies, the timing differs.

```
?url=https://google.com        → 200ms (external, blocked or slow)
?url=https://internal.corp.com  → 45ms  (internal, routed directly)
?url=https://10.0.0.1           → 48ms  (internal, routed directly)
```

### Enumerate Internal Targets
Once you've identified a scoped proxy via timing:
1. Feed it your subdomain list — timing reveals which resolve internally
2. Test RFC1918 ranges on common ports (80, 443, 8080, 8443)
3. Use `surf -l hosts.txt` to pre-filter candidates that are internal-only

### Front-End Impersonation
If the proxy respects `X-Forwarded-For`:
```
Request without header:             150ms
Request with X-Forwarded-For: 10.0.0.1:  45ms (internal routing!)
```
The header convinced the proxy you're internal. Now access internal-only endpoints.

## Decision Logic

```
Target returns uniform responses to all inputs
  ├── Establish timing baseline (20 identical requests, single-packet)
  ├── Fuzz parameters → any with >2 stddev delay?
  │     └── Yes → investigate that parameter (feature flag? debug? SSRF?)
  ├── Fuzz headers → any with timing delta?
  │     └── Yes → test X-Forwarded-For/Host impersonation
  ├── Suspect proxy/SSRF endpoint?
  │     ├── Compare timing: external domain vs internal IP vs internal subdomain
  │     └── Fast response on internal = scoped SSRF → enumerate internal services
  └── All uniform → timing vector exhausted, try other approaches
```

## Chain With
- blind-ssrf-chains (exploit the scoped SSRF you discovered)
- 403-bypass (hidden headers may bypass ACLs)
- race-condition-single-packet (same single-packet technique, different goal)

## Reference
- https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work (James Kettle, 2023)
