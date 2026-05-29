---
name: vuln-kb
description: Local vulnerability knowledge base with CWE references, attack playbooks by tech stack, and detection signatures. Use when you need vulnerability context for a specific CWE, attack strategies for a technology stack, detection signatures for static analysis, or mapping between static analysis signals and vulnerability classes.
---

# Vulnerability Knowledge Base

Quick-reference for vulnerability classes, CWE mappings, and detection patterns. For full checklists and analysis strategies, see reference files in this directory.

## Lookup Workflow

1. **Identify signal** -- what did you find? (static analysis match, HTTP traffic pattern, error message)
2. **Map to vuln class** -- use the Signal -> Vulnerability table below
3. **Get CWE details** -- find the matching CWE section for test strategy and detection signals
4. **Verify** -- use the test commands and grep patterns to confirm

**Checkpoint:** Before reporting, confirm you have: CWE ID, working PoC, and impact statement.

## Signal -> Vulnerability Mapping

| Signal Pattern | Potential Vulnerability | Priority |
|---|---|---|
| `dangerouslySetInnerHTML` | DOM XSS (React) | High |
| `innerHTML` assignment | DOM XSS (vanilla JS) | High |
| `addEventListener('message')` | postMessage XSS / cross-origin abuse | High |
| `location.href` / `window.location` assignment | Open redirect / javascript: XSS | Medium |
| Hardcoded JWT / API keys in JS | Credential exposure | Critical |
| API paths with numeric IDs | IDOR candidates | Medium |
| `__schema` / `__type` in requests | GraphQL introspection | Medium |

## CWE Quick Reference

### Injection (OWASP A03)

| CWE | Name | Key Signal |
|-----|------|------------|
| CWE-89 | SQL Injection | Error messages with SQL syntax, boolean response differences |
| CWE-78 | OS Command Injection | Command output in response, time delays |
| CWE-79 | XSS | Unencoded reflection in HTML context |
| CWE-94 | Code Injection | Dynamic code execution via eval/Function |
| CWE-917 | Expression Language Injection | Template syntax in output (`49` from `{{7*7}}`) |

### Broken Access Control (OWASP A01)

| CWE | Name | Test Strategy |
|-----|------|---------------|
| CWE-639 | IDOR | Two accounts, cross-access resources |
| CWE-862 | Missing Authorization | Access without token/session |
| CWE-863 | Incorrect Authorization | Vertical/horizontal privilege escalation |
| CWE-22 | Path Traversal | `../` sequences to escape directory |

### SSRF (CWE-918)

| Pattern | Test | Impact |
|---------|------|--------|
| URL parameter | `url=http://127.0.0.1` | Internal network access |
| Webhook URL | Callback to internal IP | Internal service interaction |
| PDF/Image generation | Embed internal URL | Blind SSRF via render |

Detection: parameters named `url`, `fetch`, `proxy`, `callback`, `webhook`, `redirect`, `href`, `src`.

### CORS Misconfiguration (CWE-942)

```bash
# Test origin reflection
curl -s -H "Origin: https://attacker.com" "https://target.com/api/user" | grep -i "access-control"

# Test with credentials
curl -s -H "Origin: https://attacker.com" -H "Cookie: session=xyz" \
  "https://target.com/api/user" -v 2>&1 | grep -i "access-control"
```

**Reporting standard:** Origin reflection alone is NOT sufficient. Must provide working JS PoC demonstrating credential theft or state-changing action.

## Grep Patterns for HTTP Traffic

```bash
# IDOR candidates
rg '/[a-z]+/[0-9]+(/|$)' http_requests/

# Potential SSRF parameters
rg '(url|uri|href|src|redirect|callback|proxy|fetch)=' http_requests/

# Auth tokens in URLs (should be in headers)
rg '(token|key|api_key|secret|auth|session)=' http_requests/

# Error messages leaking info
rg '(exception|traceback|stack.trace|syntax.error|SQLSTATE)' http_requests/
```

## Reference Files

- [testing-checklist.md](testing-checklist.md) -- Full testing checklist by category
- [analysis-strategies.md](analysis-strategies.md) -- Six analysis lenses (taint, trust boundary, business logic, config audit, race conditions, cross-context)
