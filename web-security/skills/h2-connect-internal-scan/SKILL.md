---
name: h2-connect-internal-scan
description: Internal port scanning and SSRF via HTTP/2 CONNECT method. Use when target supports HTTP/2 and proxies may forward CONNECT requests to internal hosts.
---

# HTTP/2 CONNECT Internal Scan

## Pattern
- Target supports HTTP/2 (ALPN h2 negotiation succeeds)
- Reverse proxy or load balancer in front of application
- CONNECT method not explicitly blocked in H2 stream handlers
- Need to map internal network from external position

## Probe
1. Establish HTTP/2 connection: `curl --http2 -v https://target.com`
2. Send CONNECT requests per port on unique stream IDs:
```
:method: CONNECT
:authority: 127.0.0.1:6379
```
3. Multiplex 10-50 simultaneous probes across single connection
4. High-value internal ports: 6379 (Redis), 9200 (Elasticsearch), 5432 (Postgres), 27017 (MongoDB), 8080/8443 (internal apps), 3000 (Node), 11211 (Memcached)
5. Evaluate responses:
   - `:status 200` → open port (tunnel established)
   - `:status 502/503` → port unreachable but CONNECT processed
   - `RST_STREAM` → most reliable closed-port signal

## Indicators
- Status 200 on internal IP:port combinations (tunnel established)
- Different error codes for open vs closed ports (port scan confirmed)
- Successful tunnel allows sending arbitrary protocol data to internal service

## Chain With
- ssrf-redirect-loop (if CONNECT is blind, chain with redirect loop for visibility)
- te0-request-smuggling (if proxy handles H2, try smuggling variants)

## Reference
https://blog.flomb.net/posts/http2connect/
