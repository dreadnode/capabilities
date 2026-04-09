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

## 4. PKCE Downgrade Attack

OAuth 2.1 mandates PKCE. Many servers added PKCE *support* without adding PKCE *enforcement* — they accept `code_challenge` when present but don't reject requests missing it.

### Test: Strip PKCE from Authorization Request

```
# Normal 2.1-compliant request
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&code_challenge=CHALLENGE&code_challenge_method=S256&state=STATE

# Downgrade: remove code_challenge and code_challenge_method
GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&state=STATE
```

If the server issues an authorization code without `code_challenge`, PKCE is decorative. The code can be exchanged without `code_verifier` — any interceptor (open redirect, Referer leak, proxy log) gets a usable code.

### CVE-2025-4144: Cloudflare Workers PKCE Bypass (Reverse Direction)

The `handleTokenRequest` function accepted `code_verifier` even when the authorization request omitted `code_challenge`. Attack: initiate OAuth without PKCE, steal the code (via Referer/open redirect/log), then exchange it with any arbitrary `code_verifier` — the server doesn't check because no challenge was stored.

```bash
# Step 1: authorize without PKCE (or steal code from a non-PKCE flow)
# Step 2: exchange with fabricated verifier
curl -X POST https://target.com/token \
  -d "grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=CALLBACK&client_id=CLIENT&code_verifier=anything"
```

If token is issued, PKCE enforcement is broken.

### Priority Targets for PKCE Downgrade

- Mobile apps with legacy non-PKCE codepaths still active
- Servers claiming OAuth 2.1 compliance (check `/.well-known/openid-configuration` for `code_challenge_methods_supported`)
- Hybrid deployments with 2.0 and 2.1 endpoints coexisting on same authorization server

## 5. Framework-Specific OAuth Bypasses

Fingerprint the OAuth stack first (error pages, headers, JS bundles, `/.well-known/openid-configuration`), then test framework-specific attack patterns.

### django-allauth Mutable Claim Takeover (< 65.13.0)

django-allauth uses `preferred_username` (OIDC claim) as the account UID for certain IdPs (Okta, NetIQ). This claim is mutable by the user on the IdP side.

**Attack:**
1. Identify target uses django-allauth + Okta/NetIQ (check `/accounts/login/`, error pages, `allauth` in JS/HTML)
2. Create account on the IdP
3. Change your `preferred_username` to the victim's username
4. Log in to the target — django-allauth matches your mutable claim to the victim's account

**Detection:** Any app using `preferred_username` or `email` as the sole identity anchor without an immutable IdP sub claim is vulnerable.

### CVE-2025-54576: OAuth2-Proxy skip_auth_routes Regex Bypass

`skip_auth_routes` regex is evaluated against the entire request URI including query parameters, not just the path.

```
# Server config
skip_auth_routes = [ "^/public/.*$" ]

# Bypass: match the regex via query string
GET /admin/secret?x=/public/anything HTTP/1.1
# -> regex matches -> authentication skipped
```

**Detection:** Identify oauth2-proxy via `Gap-Auth` response header or `_oauth2_proxy` cookie names.

## Detection Checklist (Extended)
- Static or predictable `window.open()` target names
- OAuth callback pages posting to `window.opener`
- Missing or inconsistent `frame-ancestors` protection on same-origin assets
- Weak `state` validation
- Large callback parameters accepted without strict bounds
- PKCE parameters optional on `/authorize` (strip and test)
- `code_verifier` accepted without prior `code_challenge` on `/token`
- `preferred_username` or `email` used as identity anchor (mutable claim risk)
- `oauth2-proxy` or `Gap-Auth` header present (regex bypass candidate)
- `/.well-known/openid-configuration` exposes `registration_endpoint` (DCR — see `mcp-auth-exploitation` skill)

## Chain With
- `dom-vulnerability-detection`
- `web-cache-deception-path`
- `race-condition-single-packet`
- `mcp-auth-exploitation` (DCR/CIMD SSRF when registration_endpoint is exposed)
- `auth-matrix-testing` (JWT algorithm confusion on OAuth-issued tokens)

## References
- https://lab.ctbb.show/research/stopping-redirects
- https://lab.ctbb.show/research/can-a-predicted-window-open-target-really-be-that-impactful
- https://lab.ctbb.show/writeups/bypassing-csp-new-relic-custom-events-cspt
- https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/
- https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-169-oauth-2-1-mcp-authorization-security (PKCE downgrade, framework CVEs)
