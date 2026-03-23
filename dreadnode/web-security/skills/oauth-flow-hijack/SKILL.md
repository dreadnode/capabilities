---
name: oauth-flow-hijack
description: Techniques to hijack OAuth flows by stopping redirects, leaking authorization codes, and exploiting popup or iframe name collisions. Use when testing OAuth implementations, especially when you have XSS on a subdomain, an open redirect, or a way to prevent callback consumption.
---

# OAuth Flow Hijack Techniques

## 1. Stopping Client-Side Redirects

### Navigation rate limiting
Some browser versions throttle excessive navigations. If the target relies on client-side redirects, throttling can leave the callback page rendered with the code still present in the URL.

### Sandboxed frame without `allow-forms`
Load the target in a sandbox that permits scripts but blocks form submission. This can break automatic callback completion logic while still allowing attacker-controlled JavaScript contexts nearby.

### Dangling markup in URL
Certain browser behaviors treat malformed client-side navigation targets as blocked. If part of the redirect URL is attacker-influenced, malformed fragments can stop the navigation.

### URL overflow
Large `state` values can trigger 414, 431, or 500 responses before the authorization code is consumed.

## 2. Leaking Authorization Codes

### Navigation API history leak
After forcing an error state, redirect to a readable origin such as `about:blank` and inspect navigation history where available.

### Cookie bombing -> 431
Oversized cookies scoped to the callback path can force a 431 response, leaving the code unconsumed.

### WAF-triggered callback failure
If a WAF blocks callback parameters, the code can remain valid because the application never processes it.

### Analytics endpoint abuse
In some CSP-constrained cases, attacker-controlled outbound POST destinations can still receive sensitive callback artifacts through trusted telemetry endpoints.

## 3. Popup or Iframe Name Hijack

If the application uses a predictable `window.open(url, "fixedName")` target:
1. Pre-create a same-origin frame or popup with that name.
2. Wait for the victim to trigger the OAuth flow.
3. Let the application reuse the attacker-controlled browsing context.
4. Redirect that context to an attacker-chosen callback or observe the resulting messages.

## Detection Checklist
- Static or predictable `window.open()` target names
- OAuth callback pages posting to `window.opener`
- Missing or inconsistent `frame-ancestors` protection on same-origin assets
- Weak `state` validation
- Large callback parameters accepted without strict bounds

## Chain With
- `dom-vulnerability-detection`
- `web-cache-deception-path`
- `race-condition-single-packet`

## References
- https://lab.ctbb.show/research/stopping-redirects
- https://lab.ctbb.show/research/can-a-predicted-window-open-target-really-be-that-impactful
- https://lab.ctbb.show/writeups/bypassing-csp-new-relic-custom-events-cspt
- https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/
