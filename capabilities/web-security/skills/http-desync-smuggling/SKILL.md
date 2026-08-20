---
name: http-desync-smuggling
description: HTTP request smuggling via body framing disagreements — CL.TE, TE.CL, CL.0, TE obfuscation, duplicate Content-Length, multipart/byteranges confusion, bodyless-method CL, H2-to-H1 downgrade, and escalation to cache poisoning or victim response theft. Covers 11 confirmed mechanism families from production research. Use when testing for request smuggling, body framing confusion, or desync between a proxy and its backend.
---

# HTTP Request Smuggling — Body Framing Desync

Request smuggling exploits a disagreement between a front-end (proxy/CDN/WAF) and a back-end (origin) about where one HTTP request ends and the next begins. The attacker's body bleeds into the next request on the shared connection.

This skill covers **body framing disagreements** — Content-Length vs Transfer-Encoding conflicts, CL.0, TE obfuscation, duplicate CL, H2 downgrade injection. For CRLF-in-URL-path desync use `response-queue-poisoning`; for TE.0 specifically use `te0-request-smuggling`.

## Tools

| Tool | Use |
|------|-----|
| `desync_fingerprint(host, proxy)` | Which framing primitives the stack accepts — run this first, it eliminates most families |
| `desync_build_payload(family, host, path, method)` | Byte-exact raw request for one family; Content-Length and chunk sizes are computed for you |
| `desync_probe_cache(host, path, proxy)` | Cache layer detection + which headers are in the cache key |
| `desync_analyze_responses(responses, host)` | Classify stolen victim responses and assign severity |

Pass `proxy="http://127.0.0.1:8080"` to route probes through Caido.

**Never send a built payload through an HTTP client library.** `execute_http`, curl, requests, and httpx all normalise headers, deduplicate Content-Length, and recompute chunk framing — exactly the properties the attack depends on. Send the raw bytes over a socket, or via Caido/Burp repeater.

## Prerequisites

- A front-end/back-end split — check `Server`, `Via`, `X-Forwarded-For`, `X-Cache`
- Persistent connections between the two (default for most proxies)

## Phase 1: Fingerprint

```
desync_fingerprint("target.com", proxy="http://127.0.0.1:8080")
```

Read the result as a technique filter, not a summary:

| Field | Meaning |
|-------|---------|
| `te_chunked: false` | Server rejects chunked — families 7, 8, 10 are dead |
| `te_gzip: true` | Non-chunked TE accepted — family 6 is live |
| `duplicate_cl: accept` | Conflicting Content-Length survives — family 3 is live |
| `bodyless_cl: accept` | CL on GET is honoured — family 4 is live |
| `cdn` present | A cache exists — plan the Phase 4 escalation now |
| `server` vs `error_page_sig` disagree | Two distinct layers, i.e. a real desync surface |

If `server` and `error_page_sig` name the same product and no CDN is present, you may be talking to a single hop. Confirm a second layer exists before burning budget on payloads.

## Phase 2: Technique Selection

The 11 confirmed mechanism families, ordered by how many distinct production servers each was confirmed against. Higher count = try first.

| # | `family` | Confirmed | Mechanism |
|---|----------|-----------|-----------|
| 1 | `byteranges` | 20 | `multipart/byteranges` boundary read as a body terminator instead of CL |
| 2 | `cl-whitespace` | 14 | Whitespace/tab/obs-fold around `Content-Length` — one parser sees it, the other doesn't |
| 3 | `cl-duplicate` | 8 | Two conflicting `Content-Length` values; first-wins vs last-wins |
| 4 | `cl-bodyless` | 7 | `Content-Length` on GET/HEAD/DELETE — proxy drops the body, origin reads it |
| 5 | `connect-cl` | 5 | `CONNECT` with `Content-Length` creates a pseudo-body on keep-alive |
| 6 | `te-gzip` | 3 | `Transfer-Encoding: gzip` — "any TE means chunked" vs "unknown TE means ignore" |
| 7 | `cl.te` | 2 | Front-end uses CL, back-end uses chunked |
| 8 | `te.cl` | 2 | Front-end uses chunked, back-end uses CL |
| 9 | `expect-dup` | 3 | Duplicated `Expect: 100-continue` desyncs whether a layer waits for the body |
| 10 | `te-obfuscated` | 2 | Bogus second `Transfer-Encoding` so one layer falls back to CL |
| 11 | H2-to-H1 downgrade | 1 | See below — not a `desync_build_payload` family |

Build each with:

```
desync_build_payload("byteranges", "target.com", path="/admin")
```

`path` is the endpoint you want the *victim* to be forced onto. Pick something whose response is unmistakable — an admin panel, a 302, a distinctive error — so a poisoned victim response is unambiguous.

### Family 11: H2-to-H1 downgrade

Not buildable as raw H1 bytes; it needs an HTTP/2 client that permits illegal header values. When the front-end speaks H2 and downgrades to H1 for the origin:

- Inject `Transfer-Encoding: chunked` via an H2 header — some proxies don't strip it on downgrade
- Inject a `Content-Length` that conflicts with H2's `content-length` pseudo-header
- Embed `\r\n` inside an H2 header **value** — H2 binary framing permits bytes that become new headers in H1
- Use a header **name** containing a space, which survives some downgrade paths

If your H2 client rejects these, that is the client normalising, not the target refusing. Use Burp's HTTP Request Smuggler or a raw h2 frame writer. When a WAF blocks the H1 form of a payload, load `h2-waf-bypass`.

## Phase 3: Validation — The Interleaved Victim Check

A desync is only confirmed when the smuggled request affects a **different connection's** response. Your own response changing proves nothing.

1. **Canary the payload.** Set `path="/wrtzllsk-<random>"`. If that string appears in a victim response or a server log echo, you have definitive request bleed — stop, that alone is the finding.
2. **Interleave.** On the same connection send Attack, Victim, Attack, Victim. Victim requests are clean baselines.
3. **Erratic-domain check.** Send 20 baseline-only requests first. If status codes already vary without any attack, the domain is inherently inconsistent and any later anomaly is noise. Do not report.
4. **Correlate.** Run 5 cycles of (attack burst -> 12s pause -> clean burst). An anomaly appearing in clean bursts is time-correlated noise. An anomaly only in attack bursts, in 3+ of 5 cycles, is confirmed.

Step 3 is the one agents skip, and it is the single largest source of false-positive smuggling reports. Run it before escalating.

Record the outcome with `assess_confidence` — `poc_confirmed` requires a canary hit or a reproduced victim-response anomaly, not a suggestive status code.

## Phase 4: Escalation

A confirmed desync alone is typically medium. Escalate before reporting.

### Cache poisoning (medium -> critical)

```
desync_probe_cache("target.com", path="/")
```

`unkeyed_headers` is the payload: a header the origin reflects but the cache ignores is a stored-XSS primitive at CDN scale.

1. Trigger the desync with a smuggled request that serves attacker-controlled content
2. Wait ~2s for connection drainage
3. Send a clean GET from a **new** connection to the same path
4. Attacker content in that clean response = cache poisoned
5. Measure TTL by repeating step 3 at 5s intervals; cross-check against `ttl_seconds`

Chain into `web-cache-deception-path` or `nextjs-cache-poisoning` for framework-specific persistence.

### Victim response theft (VRT)

```
desync_build_payload("vrt", "target.com", path="/")
```

The smuggled request declares `Content-Length: 300`, which absorbs the next victim's request headers as its body. If the endpoint reflects the body, the victim's cookies and auth headers come back to you.

Then classify what you captured:

```
desync_analyze_responses([{"status": 200, "headers": {...}, "body": "..."}], host="target.com")
```

Returns severity — critical (session cookie / JWT / bearer), high (CSRF token), medium (PII) — with every value redacted. Report the severity and category; never paste a live victim token into a report.

## Permutation Strategy

A failed technique is a data point, not a verdict. Before abandoning a family, permute:

| Mutation | Yield | Why |
|----------|-------|-----|
| Change method (`method="GET"/"HEAD"/"OPTIONS"`) | High | Different methods take different parser paths |
| Merge headers from a family that *did* get an anomalous response | High | Confirmed donors transplant well |
| Change the smuggled `path` | High | The prefix itself changes detectability |
| Add `Expect: 100-continue` | Medium | The 100-continue flow can reset a parser |
| Add `Max-Forwards: 0` | Medium | Forces the proxy to answer locally |
| Downgrade to HTTP/1.0 | Medium | Different keep-alive and CL semantics |
| Upgrade to HTTP/2 | Medium | Exercises the downgrade path |
| Shuffle header order | Medium | First-wins vs last-wins parsers diverge |

For `cl-whitespace`, the four variants worth trying in order: leading space, space before colon, tab before colon, leading tab. For `te-obfuscated`: `xchunked`, `Transfer-Encoding : chunked`, tab before the value, trailing NUL, and `X: x\nTransfer-Encoding: chunked`.

## Chain With

- `response-queue-poisoning` — CRLF-based desync; different injection vector, same exploitation
- `te0-request-smuggling` — TE.0 variant where the back-end ignores TE entirely
- `h2-waf-bypass` — when a WAF blocks the H1 payload but H2 framing gets through
- `h2c-websocket-smuggling` — h2c upgrade as an alternative tunnel
- `parser-differential-bypass` — the general case when framing-specific families all fail
- `web-cache-deception-path`, `nextjs-cache-poisoning` — persistence after a cache hit
- `caido-mode` / `burp-suite` — raw socket delivery for the built payloads

## Reference

- Kettle, "HTTP Desync Attacks" (2019) — CL.TE, TE.CL, TE obfuscation
- Kettle, "HTTP/2: The Sequel is Always Worse" (2021) — H2 downgrade smuggling
- Kettle, "Browser-Powered Desync Attacks" (2022) — CL.0, pause-based desync
- Kettle, "Breaking the Chains on HTTP Request Smuggler" — permutation and validation methodology
- PortSwigger HTTP Terminator — 11 mechanism families, 66 confirmed techniques, interleaved-victim validation
