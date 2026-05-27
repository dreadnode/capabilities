---
name: insecure-defaults
description: "Detect fail-open insecure defaults: hardcoded secrets, weak auth, permissive security that allow apps to run insecurely in production. Use when auditing security configuration, reviewing environment variable handling, or analyzing deployment files."
---

# Insecure Defaults Detection

Finds **fail-open** vulnerabilities where apps run insecurely with missing configuration.

- **Fail-open (CRITICAL):** `SECRET = env.get('KEY') or 'default'` -- App runs with weak secret
- **Fail-secure (SAFE):** `SECRET = env['KEY']` -- App crashes if missing

## When NOT to Use

- Test fixtures in `test/`, `spec/`, `__tests__/`
- Example/template files (`.example`, `.template`, `.sample`)
- Documentation examples in README.md or docs/
- Build-time configuration replaced during deployment
- Crash-on-missing behavior (fail-secure)

## Workflow

### 1. SEARCH: Find Insecure Defaults

Search `**/config/`, `**/auth/`, `**/database/`, and env files for:
- **Fallback secrets:** `getenv.*\) or ['"]`, `process\.env\.[A-Z_]+ \|\| ['"]`
- **Hardcoded credentials:** `password.*=.*['"][^'"]{8,}['"]`, `api[_-]?key.*=.*['"][^'"]+['"]`
- **Weak defaults:** `DEBUG.*=.*true`, `AUTH.*=.*false`, `CORS.*=.*\*`
- **Crypto algorithms:** `MD5|SHA1|DES|RC4|ECB` in security contexts

### 2. VERIFY: Trace Runtime Behavior

- When is this code executed? (Startup vs. runtime)
- What happens if the configuration variable is missing?
- Is there validation that enforces secure configuration?

### 3. CONFIRM: Production Impact

- If production config provides the variable: lower severity (but still code-level vulnerability)
- If production config missing or uses default: CRITICAL

### 4. REPORT: with Evidence

```
Finding: Hardcoded JWT Secret Fallback
Location: src/auth/jwt.ts:15
Pattern: const secret = process.env.JWT_SECRET || 'default';
Verification: App starts without JWT_SECRET; secret used in jwt.sign()
Exploitation: Attacker forges JWTs using 'default', gains unauthorized access
```

## Quick Verification Checklist

| Category | Pattern | Verify | Skip |
|----------|---------|--------|------|
| Fallback Secrets | `env.get(X) or Y` | App starts without var? Used in crypto/auth? | Test fixtures |
| Default Credentials | Hardcoded user/pass | Active in deploy? No override? | Disabled accounts |
| Fail-Open Security | `AUTH_REQUIRED = env.get(X, 'false')` | Default is insecure? | Default is secure |
| Weak Crypto | MD5/SHA1/DES in security | Used for passwords/tokens? | Non-security checksums |
| Permissive Access | CORS `*`, permissions `0777` | Default allows unauth access? | Justified permissiveness |
| Debug Features | Stack traces, introspection | Enabled by default? In responses? | Logging-only |

For detailed examples and counter-examples, see [references/examples.md](references/examples.md).
