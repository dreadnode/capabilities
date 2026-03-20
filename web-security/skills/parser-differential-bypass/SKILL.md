---
name: parser-differential-bypass
description: Exploit parsing differences between frontend/backend, proxy/origin, or WAF/app to bypass auth, ACLs, and input validation. Use when multiple layers process the same request differently.
---

# Parser Differential Bypass

## Pattern
- Multiple processing layers (proxy, WAF, CDN, app server) parse the same input
- Frontend validates one interpretation, backend acts on another
- Auth or ACL decisions made by a different parser than the one executing the request

## Techniques

### Duplicate JSON Keys
Send the same key twice — parsers disagree on which value wins:
```json
{"role":"user","role":"admin"}
```
- RFC 8259 says duplicate keys have undefined behavior
- First-wins: Python `json.loads()` (older), Go `encoding/json`
- Last-wins: Python `json.loads()` (3.9+), JavaScript `JSON.parse()`, Ruby, PHP
- Test: Submit duplicate keys for any auth/role/permission field. If frontend validates first value but backend uses last (or vice versa), auth bypass.

### Double Authorization Headers
```http
Authorization: Bearer user_token
Authorization: Bearer admin_token
```
- HTTP/1.1 RFC 7230: multiple identical headers should be treated as comma-separated list
- In practice: proxies often validate first, backends often use last
- Nginx: forwards first header. Apache: forwards last. Express: uses first. Spring: uses last.
- Test: Send dual `Authorization` headers through proxy. If proxy validates token A but backend uses token B, auth bypass.

### Content-Type Confusion
```http
Content-Type: application/json; charset=utf-8
Content-Type: application/x-www-form-urlencoded
```
- WAF parses body as JSON (first Content-Type), app parses as form data (second)
- Inject SQL/XSS in form-encoded body that WAF skips because it parsed as JSON
- Also test: `Content-Type: application/json` with URL-encoded body, or vice versa

### HTTP Parameter Pollution
Same parameter, different values across locations:
```http
POST /transfer?amount=1 HTTP/1.1

amount=1000000
```
- PHP: uses POST body value. ASP.NET: concatenates (`1,1000000`). Flask: uses first (query).
- Test: Duplicate security-sensitive params across query string, body, and headers.

### Path Parsing Differentials
```http
GET /admin/./secret HTTP/1.1
GET /admin%2fsecret HTTP/1.1
GET /admin;jsessionid=x/../secret HTTP/1.1
```
- Reverse proxy normalizes differently than backend
- Nginx strips `../` before forwarding, Tomcat processes it after routing
- Test: Path traversal variants through proxy to access restricted endpoints

## Detection Checklist
1. Identify all processing layers (CDN, WAF, reverse proxy, app framework, ORM)
2. Determine parser behavior for each layer (first-wins vs last-wins, encoding handling)
3. Test duplicate keys/headers/params for auth-relevant fields
4. Compare responses when same input is formatted differently
5. Document which layer makes the security decision vs which layer acts on the data

## Key Insight
The bug is not in any single parser — it's in the assumption that all parsers agree. The vulnerability exists in the gap between interpretations.
