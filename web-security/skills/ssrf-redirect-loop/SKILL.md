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
1. Set up two attacker-controlled URLs that redirect to each other: `A -> B -> A` (infinite loop)
2. Submit URL A as SSRF payload — server follows until redirect limit (20-30 hops)
3. Observe: response time increases proportionally to redirect depth followed
4. Now vary the chain: `A -> internal_target -> B -> A`
5. Differential analysis: different internal targets produce different error types
   - `169.254.169.254` → connection timeout vs auth error (reveals metadata service exists)
   - Internal host → `NetworkException` vs `JSONParseException` (reveals service type)
6. Error message content, timing, and HTTP status code all serve as oracle channels

## Indicators
- Response time scales with redirect chain depth (confirms redirect following)
- Different exception types for different internal targets
- Status code or error message changes when internal service responds differently

## Chain With
- ssti-error-based-detection (SSRF to internal template rendering service)

## Reference
https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/
