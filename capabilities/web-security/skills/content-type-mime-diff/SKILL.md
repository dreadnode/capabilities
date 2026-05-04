---
name: content-type-mime-diff
description: MIME Content-Type parser differentials between browsers and server-side libraries for XSS. Browsers treat Content-Type as list-based (last value wins), while server-side parsers treat it as singleton (first value wins). Use when application validates Content-Type server-side but reflects it verbatim in response headers.
---

# Content-Type MIME Parser Differential -> XSS

## Root Cause
- RFC 9110 defines `Content-Type` as a singleton field
- Browsers such as Chrome and Firefox treat it as list-based: split on comma and take the last valid MIME type
- Server-side MIME parsers usually take the first MIME type and ignore the rest
- If the application validates the parsed type but sets the original unparsed value in the response header, the parser differential becomes exploitable

## Core Payload Pattern
```
application/json;,text/html
```
- Server-side parser sees `application/json`
- Browser sees `application/json;` then `text/html` and renders as HTML

## Library-Specific Payloads

### Python `email.message`
```
application/json;,text/html
```

### Python `googleapiclient.mimeparse`
```
application/json;=,text/html
```
or:
```
application/json;,text/html,=
```

### Strict parsers
Parsers like Express.js `content-type`, `busboy`, and `rigour.mime` may throw exceptions on invalid characters. In those cases, exploitability depends on error handling:
- if the application falls back unsafely, the bug may still be reachable
- if the application returns the original header value anyway, the differential still matters

### Chromium parenthesis quirk
```
application/json;,text/html(=
```
Chrome treats `(` as a MIME comment delimiter and still resolves `text/html`.

## Vulnerable Code Pattern
```python
# DANGEROUS: validates parsed value but uses original in response
parsed = parse_mime(user_input)
if parsed != "application/json":
    return error
response.headers["Content-Type"] = user_input
```

Always emit the normalized parsed MIME type, never the original attacker-controlled value.

## Parser Behavior Summary

| Parser | Payload | Result |
|--------|---------|--------|
| Chrome/Firefox | `app/json;,text/html` | `text/html` |
| Python `email.message` | `app/json;,text/html` | `application/json` |
| Python `werkzeug` | `app/json;,text/html` | `application/json` |
| Python `cgi` | `app/json;,text/html` | `application/json` |
| Python `googleapiclient` | `app/json;=,text/html` | `application/json` |
| Node `whatwg-mimetype` | `app/json;,text/html` | `application/json` |
| Node `content-type` | `app/json;,text/html` | Exception |
| PHP `fileeye/mimemap` | `app/json;,text/html` | `application/json` |

## Testing Steps
1. Find an endpoint where you control the response `Content-Type` value.
2. Confirm whether `X-Content-Type-Options: nosniff` is present.
3. Test `application/json;,text/html` and observe whether the browser renders the response as HTML.
4. If validation exists, identify the server-side parser and adjust the payload accordingly.
5. Combine with HTML or JavaScript in the body to confirm XSS impact.

## Indicators
- Parameters such as `type`, `content-type`, or `format` influence response MIME type
- `X-Content-Type-Options: nosniff` is present, so browser behavior depends on the explicit MIME type
- The server validates MIME types but reflects the original input into the response header

## Chain With
- `crlf-response-splitting`
- `web-cache-deception-path`
- `parser-differential-bypass`

## References
- https://lab.ctbb.show/research/parse-and-parse-mime-validation-bypass-to-xss-via-parser-differential
- https://github.com/BlackFan/content-type-research
