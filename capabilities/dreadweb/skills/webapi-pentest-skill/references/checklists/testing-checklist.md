# Web Application & API Security Testing Checklist

## Pre-Engagement

- [ ] Scope confirmed and documented
- [ ] Authorization in writing
- [ ] Rules of engagement defined
- [ ] Testing window established
- [ ] Emergency contacts available
- [ ] Backup/rollback plan discussed

## Reconnaissance

### Passive
- [ ] WHOIS lookup
- [ ] DNS enumeration
- [ ] Subdomain discovery
- [ ] Certificate transparency logs
- [ ] Wayback Machine/historical data
- [ ] Google dorking
- [ ] Shodan/Censys search
- [ ] Social media/LinkedIn research
- [ ] GitHub/code repository search
- [ ] Job postings analysis

### Active
- [ ] Port scanning
- [ ] Service enumeration
- [ ] Web technology fingerprinting
- [ ] CMS detection
- [ ] WAF detection
- [ ] Directory/file enumeration
- [ ] Virtual host enumeration
- [ ] API endpoint discovery

## Configuration & Deployment

### SSL/TLS
- [ ] Certificate validity
- [ ] Certificate chain complete
- [ ] Strong cipher suites only
- [ ] TLS 1.2+ only
- [ ] No SSL 2.0/3.0
- [ ] HSTS enabled
- [ ] Perfect forward secrecy
- [ ] No known vulnerabilities (Heartbleed, POODLE, etc.)

### HTTP Headers
- [ ] Strict-Transport-Security
- [ ] Content-Security-Policy
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Referrer-Policy
- [ ] Permissions-Policy
- [ ] Cache-Control (sensitive pages)
- [ ] No Server/X-Powered-By disclosure

### CORS

**Testing Requirements (per H1/Bugcrowd Standards):**
- [ ] Origin reflection test: Send custom `Origin` header, check if reflected
- [ ] Credentials test: Verify `Access-Control-Allow-Credentials: true` with reflected origin
- [ ] Null origin test: Send `Origin: null`, check if allowed
- [ ] Subdomain bypass: Test `attacker.target.com` pattern
- [ ] **CRITICAL: Working PoC Required for Report**
  - Must demonstrate actual credential/token theft via JavaScript
  - Must show state-changing action exploitation
  - Origin reflection alone is NOT sufficient
- [ ] Exploitation verification: Confirm no mitigating factors (no CSRF tokens, no additional auth)

**Note:** Theoretical CORS misconfigurations without exploitation = Informational/Rejected. Always provide working JavaScript PoC.

## Authentication

### Credential Handling
- [ ] Strong password policy enforced
- [ ] No default credentials
- [ ] Secure password storage (bcrypt/argon2)
- [ ] No password in URL/GET params
- [ ] Password field masked
- [ ] Autocomplete disabled for sensitive fields

### Login Security
- [ ] Account lockout after failures
- [ ] Brute force protection
- [ ] CAPTCHA on repeated failures
- [ ] Generic error messages
- [ ] Timing attack resistant
- [ ] No username enumeration
- [ ] MFA available/enforced

### Session Management
- [ ] Session ID entropy sufficient
- [ ] Session ID not in URL
- [ ] Secure cookie flags set
- [ ] Session timeout appropriate
- [ ] Session invalidation on logout
- [ ] Session invalidation on password change
- [ ] Concurrent session handling
- [ ] Session fixation prevented

### Password Reset
- [ ] Token-based reset (not password in email)
- [ ] Token single-use
- [ ] Token expires quickly
- [ ] Rate limiting on reset requests
- [ ] No user enumeration

## Authorization

### Access Control
- [ ] IDOR testing (horizontal)
- [ ] Privilege escalation (vertical)
- [ ] Role-based access verified
- [ ] Function-level access control
- [ ] Direct object references protected
- [ ] Admin functions segregated
- [ ] Parameter tampering tested

### API Authorization
- [ ] All endpoints require auth
- [ ] Token validation on every request
- [ ] Proper scope/permission checks
- [ ] Rate limiting implemented
- [ ] API key rotation possible

## Input Validation

### Injection Testing
- [ ] SQL injection (all inputs)
- [ ] NoSQL injection
- [ ] Command injection
- [ ] LDAP injection
- [ ] XPath injection
- [ ] XML injection / XXE
- [ ] Template injection (SSTI)
- [ ] Header injection
- [ ] Log injection

### XSS Testing
- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM-based XSS
- [ ] All input fields tested
- [ ] URL parameters tested
- [ ] Headers tested (User-Agent, Referer)
- [ ] JSON/XML responses tested

### File Handling
- [ ] File upload restrictions
- [ ] File type validation (magic bytes)
- [ ] Filename sanitization
- [ ] Path traversal prevention
- [ ] Storage outside webroot
- [ ] Execution prevention
- [ ] File size limits

## Business Logic

- [ ] Price/quantity manipulation
- [ ] Workflow bypass
- [ ] Race conditions
- [ ] Feature abuse
- [ ] Coupon/discount abuse
- [ ] Payment manipulation
- [ ] Order tampering
- [ ] Referral abuse

## API-Specific

### REST API
- [ ] BOLA/IDOR testing
- [ ] BFLA testing
- [ ] Mass assignment
- [ ] Excessive data exposure
- [ ] Lack of resources/rate limiting
- [ ] Improper inventory management
- [ ] SSRF via parameters

### GraphQL
- [ ] Introspection enabled
- [ ] Query depth limits
- [ ] Query cost analysis
- [ ] Batch query limits
- [ ] Alias abuse
- [ ] Injection in variables
- [ ] Authorization at resolver level
- [ ] Field-level permissions

### JWT
- [ ] None algorithm rejected
- [ ] Weak secret (brute force)
- [ ] Algorithm confusion
- [ ] Token expiration enforced
- [ ] Sensitive data in payload
- [ ] Token invalidation possible
- [ ] Refresh token security

## Client-Side

- [ ] Sensitive data in localStorage
- [ ] Sensitive data in sessionStorage
- [ ] Sensitive data in cookies
- [ ] Source map exposure
- [ ] Debug code in production
- [ ] API keys in JavaScript
- [ ] Console.log sensitive data
- [ ] DOM clobbering
- [ ] Prototype pollution
- [ ] Clickjacking
- [ ] Tabnabbing

## Error Handling

- [ ] Generic error messages to users
- [ ] No stack traces exposed
- [ ] No debug info in production
- [ ] No path disclosure
- [ ] No version disclosure
- [ ] Custom error pages

## Cryptography

- [ ] Strong algorithms only (no MD5/SHA1 for security)
- [ ] Proper key management
- [ ] No hardcoded keys/secrets
- [ ] Random number generation secure
- [ ] Salt usage correct
- [ ] IV usage correct

## SSRF

- [ ] URL parameter injection
- [ ] Internal IP access blocked
- [ ] Cloud metadata access blocked
- [ ] Protocol handlers restricted
- [ ] DNS rebinding prevented
- [ ] Redirect following restricted

## Post-Testing

- [ ] All findings documented
- [ ] PoC for each vulnerability
- [ ] Severity ratings assigned
- [ ] Remediation recommendations
- [ ] Clean up test data/accounts
- [ ] Remove uploaded files
- [ ] Report delivered securely
