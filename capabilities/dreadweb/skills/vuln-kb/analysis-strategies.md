# Analysis Strategy Lenses

Codified mental models for vulnerability analysis. Apply these systematically before and during testing. Derived from Co-RedTeam research and field experience.

## Lens 1: Taint Analysis (Source-to-Sink)

**Goal**: Find injection flaws (SQLi, RCE, XSS, SSTI)

**Method**:
1. Identify all SOURCES of untrusted input:
   - URL parameters (`req.query`, `request.args`)
   - Request body (`req.body`, form data, JSON)
   - HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
   - Cookies
   - File uploads (filename, content, metadata)
   - External data (DNS, API responses ingested by the app)

2. Identify all dangerous SINKS:
   - Database queries (`execute`, `query`, `find`, `aggregate`)
   - System commands (`exec`, `system`, `popen`, `subprocess`, `child_process`)
   - Code evaluation (`eval`, `Function()`, `setTimeout(string)`, `vm.runInContext`)
   - HTML rendering (`innerHTML`, `document.write`, `dangerouslySetInnerHTML`, template output)
   - File operations (`readFile`, `writeFile`, `send_file`, `open`)
   - URL handling (`redirect`, `location.href`, `window.open`)

3. Trace the FLOW from source to sink:
   - Is there sanitization/encoding in between?
   - Is the sanitization correct for the output context?
   - Can the sanitization be bypassed?

**Example**:
```
Static analysis finds: innerHTML usage in dashboard.js:142
Trace back: innerHTML value comes from API response
API response: includes user-submitted content (product description)
Product description: submitted via form without server-side sanitization
Result: Stored XSS via product description -> innerHTML
```

## Lens 2: Trust Boundary Mapping

**Goal**: Find authentication/authorization bypasses

**Method**:
1. Map all trust boundaries:
   - Public internet -> Application (authentication boundary)
   - Regular user -> Admin (authorization boundary)
   - Tenant A -> Tenant B (isolation boundary)
   - Frontend -> Backend API (input validation boundary)
   - Application -> Internal services (network boundary)

2. For each boundary, verify:
   - Is the boundary enforced consistently? (All endpoints, all methods)
   - Is enforcement server-side? (Not just frontend checks)
   - Can the boundary be bypassed? (Path manipulation, method override, header injection)
   - Are there new endpoints that forgot boundary checks?

3. Specific checks:
   - Remove auth token/cookie - what's still accessible?
   - Change user ID in JWT/session - what's accessible?
   - Add admin role to request - does it elevate?
   - Access new/beta endpoints - do they enforce same auth?

Search HTTP traffic history for auth-related endpoints and test without auth.

## Lens 3: Business Logic Tracing

**Goal**: Find IDOR, workflow bypasses, state manipulation

**Method**:
1. Map multi-step workflows:
   - Registration -> Verification -> Activation
   - Browse -> Cart -> Checkout -> Payment -> Confirmation
   - Request password reset -> Receive email -> Click link -> Set new password

2. For each workflow, test:
   - Can you skip a step? (Go directly to step 3 without completing step 2)
   - Can you replay a step? (Use the same reset token twice)
   - Can you modify state between steps? (Change cart total after entering checkout)
   - Can you swap identifiers mid-flow? (Start as User A, switch to User B's resource)

3. State manipulation:
   - Does the server validate state transitions?
   - Is state stored client-side (JWT, hidden fields, cookies)?
   - Can client-side state be tampered with?

## Lens 4: Configuration & Dependency Audit

**Goal**: Find infrastructure flaws, leaked secrets, vulnerable dependencies

**Method**:
1. Configuration files:
   - Debug modes enabled (`DEBUG=True`, `NODE_ENV=development`)
   - Hardcoded secrets in source code
   - Default credentials
   - Overly permissive CORS/CSP policies
   - Exposed internal endpoints (health checks, metrics, debug panels)

2. Dependencies:
   - Known CVEs in libraries (check versions)
   - Outdated frameworks with security patches available
   - Client-side library versions visible in source/headers

3. Infrastructure:
   - Cloud metadata endpoint accessible (169.254.169.254)
   - Internal services exposed (Redis, Elasticsearch, databases)
   - Admin panels on non-standard ports
   - Docker/container misconfigurations

Search JS source for leaked secrets, hardcoded tokens, and dependency version strings.

## Lens 5: State Confusion & Race Conditions

**Goal**: Find TOCTOU bugs, double-spend, and state inconsistencies

**Method**:
1. Identify state-changing operations:
   - Financial transactions (transfer, purchase, refund)
   - Counter operations (votes, likes, quantity changes)
   - Status transitions (pending -> approved, draft -> published)

2. Test concurrent execution:
   - Send same request in parallel (5-10 concurrent requests)
   - Check if operation was applied multiple times
   - Check for inconsistent state (balance went negative, counter exceeded limit)

3. TOCTOU (Time of Check, Time of Use):
   - Does the app check permission, then perform action in separate steps?
   - Can state change between check and action?

## Lens 6: Cross-Context Leakage

**Goal**: Find data leakage between tenants, sessions, users

**Method**:
1. Identify isolation boundaries:
   - Multi-tenant: Store A vs Store B
   - Multi-user: User A session vs User B session
   - Multi-role: Admin view vs user view of same resource
   - AI context: Memory/preferences between sessions

2. For each boundary, test:
   - Store data in Context A, query from Context B
   - Check if caching leaks data across contexts
   - Check if shared resources (CDN, cache, search index) mix data
   - Test AI memory isolation (Shopify Sidekick cross-store test)

## When to Apply Which Lens

| Target Characteristic | Primary Lens | Secondary Lens |
|---|---|---|
| Has user input fields | Taint Analysis | Business Logic |
| Has user accounts/roles | Trust Boundary | Cross-Context |
| Has multi-step workflows | Business Logic | State Confusion |
| Is multi-tenant/multi-user | Cross-Context | Trust Boundary |
| Has financial/counting operations | State Confusion | Business Logic |
| Exposes source code/configs | Configuration Audit | Taint Analysis |
| Is a SPA/React app | Taint Analysis (client-side sinks) | Trust Boundary (API auth) |
| Has AI/LLM features | Cross-Context | Taint Analysis (prompt injection) |
