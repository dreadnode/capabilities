---
name: false-positive-filters
description: Filters to avoid reporting false positives during security analysis. Use before reporting a finding to verify it's a real vulnerability, not a common false positive pattern.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# False Positive Filters

Check findings against these filters before reporting to avoid common false positives.

**This skill filters findings. It does NOT validate exploitability end-to-end.** If a finding survives these filters but still needs proof, continue with `fp-check`.

## When to Use

- Before calling `report_vulnerability`
- When a pattern match looks suspicious but context is unclear
- When validating automated scanner results
- During final review of findings

## When NOT to Use

- Initial discovery phase (scan first, filter later)
- When the vulnerability is clearly exploitable
- For informational/low findings that should be `highlight_for_review` instead

## Informational, Not Vulnerabilities

These are informational findings, not exploitable vulnerabilities:

| Finding | Why It's Not a Vuln |
|---------|---------------------|
| Hardcoded test credentials | No real access unless test env is production |
| Missing security headers (CSP, HSTS) alone | Defense-in-depth, not exploitable by itself |
| Debug mode in dev configs | Only matters if it reaches production |
| Verbose error messages | Only a vuln if they leak secrets/paths |
| Missing CSRF tokens | Need to demonstrate actual state-changing impact |
| Rate limiting absence | Availability concern, not a vulnerability |
| Outdated dependencies | Need specific CVE with exploit path |
| Generic coding style issues | Not security relevant |

## Common False Positives by Category

### SQL Injection

**Not vulnerable:**
- Parameterized queries that visually look like string concatenation
- ORM methods with safe interpolation (Django `filter()`, SQLAlchemy `query()`)
- Admin-only queries where input is from trusted admin, not user
- Queries where the "user input" is actually from a hardcoded allowlist

**Check:** Is user input actually reaching the query? Is it parameterized?

### Command Injection

**Not vulnerable:**
- Hardcoded command strings with no user input
- Input validated against strict allowlist before use
- Sandboxed execution environments (containers, seccomp)
- `subprocess.run(['cmd', arg])` without `shell=True` (args are escaped)

**Check:** Does user input reach the command? Is `shell=True` used?

### Cross-Site Scripting (XSS)

**Not vulnerable:**
- Auto-escaping template engines (Jinja2 default, React JSX)
- Content-Security-Policy blocking inline scripts
- API-only endpoints returning JSON (no HTML rendering)
- Input that only appears in HTTP headers, not response body

**Check:** Is the output context HTML? Is auto-escaping disabled?

### Path Traversal

**Not vulnerable:**
- Paths resolved relative to safe base directory with containment check
- `os.path.basename()` or similar extracting just filename
- Allowlist validation of permitted filenames
- Symlink checks preventing escape

**Check:** Can `../` actually escape the intended directory?

### Deserialization

**Not vulnerable:**
- Deserializing data from trusted internal source (not user input)
- Safe deserializers (JSON without type handling, `yaml.safe_load`)
- Signed/encrypted serialized data with integrity verification

**Check:** Is the serialized data user-controlled? Is the deserializer unsafe?

### SSRF

**Not vulnerable:**
- URLs from configuration, not user input
- Allowlist of permitted domains/IPs
- Network segmentation preventing internal access
- URL validation blocking internal ranges

**Check:** Is the URL user-controlled? Can internal services be reached?

## Filter Checklist

Before reporting, confirm:

- [ ] User input actually reaches the sink (trace the data flow)
- [ ] No sanitization/validation blocks the attack
- [ ] The attack is practical, not just theoretical
- [ ] You can describe a concrete exploit scenario
- [ ] It's not in test code, mocks, or examples

## When Uncertain

If a finding is borderline:
- Use `highlight_for_review` instead of `report_vulnerability`
- Set appropriate priority (low/medium)
- Explain why you're uncertain in the notes
