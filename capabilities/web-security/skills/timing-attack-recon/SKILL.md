---
name: timing-attack-recon
description: Discover hidden parameters, headers, and scoped SSRFs via server-side timing differentials. Use when traditional fuzzing returns uniform responses but you suspect hidden backend logic or internal proxy routing.
---

# Timing Attack Recon

Measure response time deltas to find attack surface invisible in response bodies. Server-side operations (DNS lookup, DB query, log write, proxy routing) add 5-50ms. Isolate these from network jitter using single-packet synchronization.

## Eliminate Network Jitter First

Server-side deltas are 1-50ms. Network jitter is 10-100ms+. You **must** eliminate jitter or you'll drown in noise.

**HTTP/2 single-packet**: Send N requests multiplexed in one TCP packet. All arrive within ~1ms. Compare response times -- delta is pure server-side.

**HTTP/1.1 last-byte sync**: Open N connections, send all but final byte, release final bytes simultaneously. ~4ms spread.

## Baseline

```bash
# Statistical baseline: 20 requests, calculate mean and stddev
times=()
for i in $(seq 1 20); do
  t=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/api/endpoint")
  times+=("$t")
done

python3 -c "
import sys
times = [float(t) for t in '${times[*]}'.split()]
mean = sum(times) / len(times)
stddev = (sum((t - mean) ** 2 for t in times) / len(times)) ** 0.5
print(f'Baseline: mean={mean*1000:.1f}ms stddev={stddev*1000:.1f}ms')
print(f'Signal threshold: >{(mean + 2*stddev)*1000:.1f}ms (mean + 2*stddev)')
"
```

**Checkpoint:** Anything >2 stddev above mean on a specific input = signal worth investigating.

## Hidden Parameter Discovery

```bash
BASELINE_MEAN=0.045  # Set from baseline above (seconds)
BASELINE_STDDEV=0.003

for param in debug admin internal test verbose trace log callback url redirect next; do
  t=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/api?${param}=1")
  delta=$(python3 -c "print(f'{($t - $BASELINE_MEAN)*1000:.1f}')")
  sigma=$(python3 -c "d=($t-$BASELINE_MEAN)/$BASELINE_STDDEV; print(f'{d:.1f}')")
  echo "param=$param time=${t}s delta=${delta}ms (${sigma}sigma)"
done | sort -t'(' -k2 -rn | head -5
```

Params with >2 sigma trigger backend logic -- investigate even if response body is unchanged.

## Hidden Header Discovery

Same principle. Priority headers to test:
- `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`
- `X-Debug`, `X-Debug-Token`, `X-Admin`, `X-Internal`
- `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`

## Scoped SSRF Detection via Timing

Highest-value technique. Detect proxy endpoints routing to internal services -- even when responses are identical.

```
?url=https://google.com        -> 200ms (external, blocked or slow)
?url=https://internal.corp.com  -> 45ms  (internal, routed directly)
?url=https://10.0.0.1           -> 48ms  (internal, routed directly)
```

### Enumerate Internal Targets
Once scoped proxy is confirmed via timing:
1. Feed it your subdomain list -- timing reveals which resolve internally
2. Test RFC1918 ranges on common ports (80, 443, 8080, 8443)
3. Pre-filter candidates: `surf -l hosts.txt`

### Front-End Impersonation
If the proxy respects forwarded headers:
```
Request without header:                    150ms
Request with X-Forwarded-For: 10.0.0.1:    45ms (internal routing!)
```

## Decision Logic

```
Target returns uniform responses to all inputs
  |-- Establish timing baseline (20 identical requests, single-packet)
  |-- Fuzz parameters -> any with >2 sigma delay?
  |     +-- Yes -> investigate (feature flag? debug? SSRF?)
  |-- Fuzz headers -> any with timing delta?
  |     +-- Yes -> test X-Forwarded-For/Host impersonation
  |-- Suspect proxy/SSRF endpoint?
  |     |-- Compare timing: external domain vs internal IP vs internal subdomain
  |     +-- Fast response on internal = scoped SSRF -> enumerate internal services
  +-- All uniform -> timing vector exhausted, try other approaches
```

## Chain With
- blind-ssrf-chains (exploit the scoped SSRF you discovered)
- 403-bypass (hidden headers may bypass ACLs)
- race-condition-single-packet (same single-packet technique, different goal)

## Reference
- https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work (James Kettle, 2023)
