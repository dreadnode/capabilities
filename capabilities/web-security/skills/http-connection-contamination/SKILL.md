---
name: http-connection-contamination
description: Misroute requests across subdomains via HTTP/2+ connection coalescing on shared infrastructure with wildcard TLS certs. Use when target has multiple subdomains on same IP with wildcard cert and reverse proxy.
---

# HTTP Connection Contamination

Browsers reuse HTTP/2+ connections across different origins when they share an IP and TLS certificate. If the reverse proxy routes by first request's Host header and reuses that routing for subsequent requests on the same connection, you can force requests to `secure.example.com` through `wordpress.example.com`'s backend.

## Prerequisites (all required)

1. Multiple subdomains resolve to **same IP**
2. **Wildcard TLS cert** covers both (e.g. `*.example.com`)
3. Reverse proxy uses **first-request routing** (routes connection based on initial Host header, not per-request)
4. Different backend applications behind different subdomains

## Why HTTP/3 Makes This Worse

HTTP/2 coalescing requires same IP + shared cert. HTTP/3 (QUIC) relaxes the IP match requirement — the browser can coalesce connections to different IPs if the cert covers both origins. This broadens the attack surface without needing MITM or shared infrastructure.

## Probe

### Step 1: Check coalescing conditions
```bash
# Same IP?
dig +short sub1.example.com sub2.example.com

# Shared cert? (check SAN/wildcard)
echo | openssl s_client -connect sub1.example.com:443 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

**Checkpoint:** Both conditions must hold: same IP AND shared cert (wildcard or multi-SAN). If either fails, connection coalescing will not occur.

### Step 2: Test for first-request routing
In browser DevTools (Network tab), observe if requests to `sub2.example.com` reuse the connection ID established for `sub1.example.com`. If the response content comes from sub1's backend, the proxy uses first-request routing.

### Step 3: Reproduce
```javascript
// From attacker page or XSS context:
// 1. Fetch to establish connection to attacker-controlled subdomain
fetch('https://attacker-sub.example.com/');
// 2. Subsequent fetch coalesces onto same connection
// but proxy routes to attacker-sub's backend
fetch('https://victim-sub.example.com/sensitive-page');
```

## Impact Scenarios

| Setup | Attack | Impact |
|-------|--------|--------|
| WordPress + admin panel on same infra | Route admin requests through WordPress backend | XSS via WordPress → admin session theft |
| API + web frontend shared cert | API requests misrouted to frontend | Auth bypass, CORS confusion |
| Multi-tenant customer portals | Tenant A requests routed to tenant B backend | Cross-tenant data access |
| CDN + origin shared cert | Poison CDN connection to route through origin | Cache poisoning, WAF bypass |

## Detection Checklist

- [ ] Multiple subdomains on same IP (`dig +short`)
- [ ] Wildcard or multi-SAN certificate
- [ ] Different applications behind different subdomains
- [ ] Reverse proxy with connection pooling (nginx, HAProxy, Envoy)
- [ ] Browser DevTools shows connection reuse across origins
- [ ] Response from wrong backend confirms misrouting

## Chain With
- web-cache-deception-path (poison cache via misrouted request)
- self-xss-escalation (XSS on one subdomain → contaminate connection to sensitive subdomain)
- oauth-flow-hijack (misroute OAuth callback to attacker-controlled backend)

## Reference
- https://portswigger.net/research/http-3-connection-contamination (James Kettle, PortSwigger)
