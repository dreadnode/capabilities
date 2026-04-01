---
name: threat-modeling
description: Systematic threat analysis using STRIDE methodology, attack trees, data flow diagrams, and trust boundary identification. Use for architecture security reviews, feature design, attack surface mapping, or identifying security requirements.
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash
---

# Threat Modeling

## When to Use

Use this skill when:
- Reviewing system architecture for security
- Designing new features that handle sensitive data
- Identifying security requirements before implementation
- Mapping attack surfaces and entry points
- Analyzing trust boundaries in distributed systems
- Creating security test cases
- Prioritizing security controls

## When NOT to Use

Do NOT use for:
- Finding specific code vulnerabilities (use semgrep, codeql)
- Penetration testing or active exploitation
- Compliance checklist validation
- Post-incident forensics

## STRIDE Methodology

STRIDE categorizes threats into six types:

| Threat | Description | Example |
|--------|-------------|---------|
| **S**poofing | Pretending to be someone/something else | Session hijacking, forged JWT tokens |
| **T**ampering | Modifying data or code | SQL injection, man-in-the-middle |
| **R**epudiation | Denying actions were performed | Missing audit logs, unsigned transactions |
| **I**nformation Disclosure | Exposing information to unauthorized parties | Data leaks, verbose errors, timing attacks |
| **D**enial of Service | Making system unavailable | Resource exhaustion, algorithmic complexity |
| **E**levation of Privilege | Gaining unauthorized capabilities | Privilege escalation, broken access control |

## Quick Threat Assessment

### Step 1: Identify Assets

```markdown
## High-Value Assets
1. **User Credentials** (passwords, API keys, tokens)
2. **Personal Data** (PII, payment info, health records)
3. **Business Logic** (pricing, permissions, workflows)
4. **System Integrity** (configs, binaries, databases)
```

### Step 2: Map Data Flows

```
User → Web App → API Gateway → Auth Service → Database
                              ↓
                         Cache Layer
```

### Step 3: Identify Trust Boundaries

```
Trust Boundary #1: Internet ←→ Web Server
Trust Boundary #2: Web Server ←→ Internal Services
Trust Boundary #3: Services ←→ Database
```

### Step 4: Apply STRIDE to Each Flow

**Example: User Login Flow**

| Component | S | T | R | I | D | E |
|-----------|---|---|---|---|---|---|
| Login Form | ✓ CSRF | ✓ XSS | - | ✓ Creds in URL | ✓ Brute force | - |
| Auth API | ✓ Token forgery | ✓ SQLi | ✓ No logs | ✓ Timing attack | ✓ Rate limit | ✓ JWT bypass |
| Database | - | ✓ SQL inject | - | ✓ Unencrypted | ✓ Connection pool | ✓ SQL role abuse |

## Detailed Analysis Process

### Phase 1: Decompose the System

#### 1.1 Create Architecture Diagram

```bash
# Find architecture docs
find . -name "architecture.*" -o -name "design.*" -o -name "system-diagram.*"

# Find Docker/K8s configs for system components
find . -name "docker-compose.yml" -o -name "*.k8s.yaml"
```

**Identify:**
- External entities (users, admins, external APIs)
- Processes (web servers, APIs, workers)
- Data stores (databases, caches, file storage)
- Data flows (HTTP, gRPC, message queues)
- Trust boundaries (firewalls, auth layers, network zones)

#### 1.2 Identify Entry Points

```bash
# Find HTTP endpoints
rg "route|endpoint|@app\.|@get|@post" . -t py -t js -t go

# Find CLI entry points
rg "if __name__|func main\(\)|exports\." . -t py -t go -t js

# Find message consumers
rg "consumer|subscriber|listener|on_message" . -t py -t js
```

#### 1.3 Identify Assets

```bash
# Find database models
rg "class.*Model|schema|type.*struct" . -t py -t go -t js

# Find sensitive data patterns
rg -i "password|credit_card|ssn|api_key|private_key" . -t py -t js -t go
```

### Phase 2: STRIDE Analysis

For each component, ask STRIDE questions:

#### Spoofing
- Can an attacker impersonate a user or system?
- Is authentication required and enforced?
- Are credentials properly validated?
- Can tokens be forged or replayed?

```bash
# Check auth enforcement
rg "require_auth|@login_required|authorize" . -t py -t js

# Check for missing auth
rg "route\(|@app\.|@get|@post" . -A 5 | grep -v "auth"
```

#### Tampering
- Can an attacker modify data in transit or at rest?
- Is input validated and sanitized?
- Are integrity checks in place?
- Can configuration be modified?

```bash
# Find input validation
rg "validate|sanitize|clean_input" . -t py -t js

# Find database writes
rg "INSERT|UPDATE|DELETE|save\(\)|create\(\)" . -t py -t js -t sql
```

#### Repudiation
- Can users deny their actions?
- Are actions logged with user identity?
- Are logs tamper-proof?
- Is there audit trail for sensitive operations?

```bash
# Find logging statements
rg "log\.|logger\.|console\.log" . -t py -t js

# Check for audit logs
rg -i "audit|trail" . -t py -t js
```

#### Information Disclosure
- Can attackers access unauthorized data?
- Are errors revealing sensitive information?
- Is data encrypted in transit and at rest?
- Are logs exposing secrets?

```bash
# Find error handling
rg "except|catch|error" . -t py -t js -A 3

# Find logging that might expose data
rg "log.*password|log.*token|log.*key" . -t py -t js
```

#### Denial of Service
- Can attackers exhaust resources?
- Are there rate limits?
- Is input size validated?
- Are expensive operations protected?

```bash
# Find rate limiting
rg "rate_limit|throttle|limiter" . -t py -t js

# Find unbounded operations
rg "while True|for.*in.*:|\.all\(\)" . -t py
```

#### Elevation of Privilege
- Can attackers gain admin access?
- Are privileges checked on every operation?
- Can users access others' resources?
- Is RBAC properly implemented?

```bash
# Find authorization checks
rg "is_admin|check_permission|authorize|can_access" . -t py -t js

# Find privilege escalation risks
rg "sudo|setuid|exec\(|eval\(" . -t py -t js
```

### Phase 3: Build Attack Trees

**Example: Compromise User Account**

```
Goal: Compromise User Account
├─ OR: Steal Credentials
│  ├─ AND: Phish User
│  │  ├─ Clone login page
│  │  └─ Send phishing email
│  ├─ AND: Brute Force Login
│  │  ├─ No rate limiting
│  │  └─ Weak password policy
│  └─ AND: Intercept Credentials
│     ├─ HTTP (no TLS)
│     └─ Man-in-the-middle
├─ OR: Session Hijack
│  ├─ XSS to steal session cookie
│  ├─ CSRF to perform actions
│  └─ Session fixation
└─ OR: Exploit Auth Bypass
   ├─ SQL injection in login
   ├─ JWT signature bypass
   └─ Authentication logic flaw
```

**Identify:**
- Leaf nodes = actual attack techniques
- AND nodes = all conditions must be met
- OR nodes = any condition is sufficient
- Easiest attack path = fewest AND nodes, most OR options

### Phase 4: Risk Rating

For each threat, calculate risk:

```
Risk = Likelihood × Impact
```

**Likelihood:**
- High (3): Easy to exploit, known techniques, no auth required
- Medium (2): Requires some skill or specific conditions
- Low (1): Difficult, requires insider access, or unlikely

**Impact:**
- High (3): Data breach, system compromise, financial loss
- Medium (2): Limited data exposure, partial availability loss
- Low (1): Informational, no direct harm

**Risk Matrix:**

| Likelihood\Impact | Low (1) | Medium (2) | High (3) |
|-------------------|---------|------------|----------|
| **High (3)** | 3 (Med) | 6 (High) | 9 (Critical) |
| **Medium (2)** | 2 (Low) | 4 (Med) | 6 (High) |
| **Low (1)** | 1 (Low) | 2 (Low) | 3 (Med) |

## Threat Modeling Templates

### Web Application Template

```markdown
# Threat Model: [Application Name]

## Assets
1. User credentials (password hashes)
2. User PII (name, email, address)
3. Payment information (credit cards)
4. Business data (orders, inventory)

## Trust Boundaries
1. Internet ←→ Load Balancer (TLS termination)
2. DMZ ←→ Internal Network (Firewall)
3. Application ←→ Database (Auth + Network)

## Data Flows
1. User → Web App: HTTPS (credentials, PII)
2. Web App → API: HTTP (authenticated requests)
3. API → Database: TCP (SQL queries)
4. API → Payment Gateway: HTTPS (payment tokens)

## STRIDE Analysis

### User Login Flow
- **Spoofing:** Credential stuffing, session hijacking
  - Mitigation: MFA, rate limiting, secure session tokens
- **Tampering:** MITM, XSS injecting malicious scripts
  - Mitigation: TLS, CSP, input validation
- **Repudiation:** No audit logs for login attempts
  - Mitigation: Log all auth events with IP, timestamp
- **Info Disclosure:** Verbose error messages reveal usernames
  - Mitigation: Generic error messages
- **DoS:** Login API has no rate limit
  - Mitigation: Rate limit by IP and username
- **Elevation:** JWT doesn't include role, can be modified
  - Mitigation: Include role in signed token

### Payment Processing
[Similar STRIDE analysis]

## Attack Trees
[Include attack tree diagrams]

## Risk Summary
- Critical: 2 threats
- High: 5 threats
- Medium: 12 threats
- Low: 8 threats

## Recommended Controls
1. Implement MFA (mitigates 3 critical threats)
2. Add rate limiting (mitigates 2 high threats)
3. Enable audit logging (mitigates repudiation)
```

### API Security Template

```markdown
# Threat Model: [API Name]

## Endpoints
1. POST /api/auth/login - Authentication
2. GET /api/users/{id} - User data
3. POST /api/payments - Payment processing
4. DELETE /api/users/{id} - Account deletion

## Authentication
- JWT tokens (RS256)
- API keys for service-to-service
- OAuth2 for third-party integrations

## STRIDE per Endpoint

### POST /api/auth/login
- S: Credential stuffing → Rate limit + CAPTCHA
- T: SQL injection → Parameterized queries
- R: Failed login not logged → Add audit logs
- I: Timing attack reveals valid usernames → Constant-time comparison
- D: No rate limit → Implement rate limiting
- E: N/A

### GET /api/users/{id}
- S: Forged JWT → Verify signature
- T: IDOR (access other user's data) → Check ownership
- R: Data access not logged → Add audit trail
- I: Response includes sensitive fields → Filter response
- D: Expensive query with no pagination → Add pagination, limit
- E: Can access admin user data → RBAC enforcement

[Continue for other endpoints]
```

## Microservices-Specific Threats

### Service-to-Service Communication

```bash
# Check for mutual TLS
rg "tls|ssl|certificate" . -t yaml -t json

# Check for service mesh
rg "istio|linkerd|consul" . -t yaml
```

**Threats:**
- Service impersonation (no mutual TLS)
- Unencrypted internal traffic
- Missing authorization between services
- Shared secrets across services

### API Gateway Threats

- Bypassing gateway to access services directly
- Rate limit per service vs per user
- JWT validation at gateway vs services
- Service enumeration via gateway

## Automated Threat Detection

```bash
# Find authentication bypasses
rg "if.*is_admin.*:?$" . -A 2 -t py | grep -v "return\|raise"

# Find IDOR vulnerabilities
rg "get_object_or_404\(.*request\." . -t py

# Find missing rate limits
rg "@app\.route|@get|@post" . -t py -t js -B 2 | grep -v "limit\|throttle"

# Find SQL injection risks
rg "execute\(.*%s|execute\(.*\+" . -t py
```

## Common Pitfalls

### Pitfall 1: Threat Modeling Too Late

**Wrong:** Building system first, then threat modeling

**Correct:** Threat model during design phase, update throughout development

### Pitfall 2: Ignoring Implementation Details

**Wrong:** "We use HTTPS" (assumed secure)

**Correct:** Verify TLS version, cipher suites, certificate validation

### Pitfall 3: One-Time Activity

**Wrong:** Single threat model document created and forgotten

**Correct:** Update threat model when architecture changes

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "We'll add security later" | Security must be designed in, not bolted on |
| "Our system is too simple to threat model" | Even simple systems have trust boundaries |
| "We use a WAF, we're protected" | WAF is defense-in-depth, not replacement for secure design |
| "Threat modeling takes too long" | Finding vulnerabilities in design is 10x cheaper than production |

## Output Template

```markdown
# Threat Model: [System Name]
**Date:** 2026-01-31
**Version:** 1.0
**Stakeholders:** Security, Engineering, Product

## Executive Summary
- **Critical Threats:** 2
- **High Threats:** 5
- **Primary Risks:** Authentication bypass, data exposure
- **Recommended Controls:** MFA, audit logging, rate limiting

## System Overview
[Architecture diagram]

## Assets
[List high-value assets]

## Data Flow Diagrams
[Show data flows across trust boundaries]

## STRIDE Analysis
[Per-component threat analysis]

## Attack Trees
[Show attack paths]

## Threat Summary

| ID | Threat | Category | Likelihood | Impact | Risk | Mitigation |
|----|--------|----------|------------|--------|------|------------|
| T1 | SQL Injection | Tampering | High | High | 9 | Parameterized queries |
| T2 | Brute Force | Spoofing | High | Medium | 6 | Rate limiting + MFA |
| T3 | IDOR | Elevation | Medium | High | 6 | Authorization checks |

## Recommended Controls
1. **Critical:** [Controls for critical threats]
2. **High:** [Controls for high threats]
3. **Defense-in-Depth:** [Additional security layers]

## Assumptions
- TLS is properly configured
- Secrets are stored in vault
- Infrastructure is patched regularly

## Out of Scope
- Physical security
- Social engineering
- Third-party service security
```

## Resources

- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- Microsoft STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- Threat Dragon: https://owasp.org/www-project-threat-dragon/
- PASTA Methodology: https://versprite.com/tag/pasta-threat-modeling/
- Related Skills: entry-point-analyzer, sharp-edges
