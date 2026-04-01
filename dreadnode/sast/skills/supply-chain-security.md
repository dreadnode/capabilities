---
name: supply-chain-security
description: Analyze dependencies for vulnerabilities, malicious packages, license issues, and supply chain attacks. Use for dependency audits, SCA scans, SBOM generation, typosquatting detection, or analyzing npm/pip/maven packages.
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Supply Chain Security Analysis

## When to Use

Use this skill when:
- Auditing project dependencies for vulnerabilities
- Detecting malicious or compromised packages
- Analyzing dependency confusion risks
- Generating Software Bill of Materials (SBOM)
- Checking for typosquatting attacks
- Validating package integrity and signatures
- Assessing license compliance risks

## When NOT to Use

Do NOT use for:
- Source code vulnerability scanning (use semgrep or codeql)
- Runtime security monitoring
- Infrastructure security audits
- Network security analysis

## Quick Dependency Scan

```bash
# Python (pip)
pip-audit --format json -o vulnerabilities.json

# JavaScript (npm)
npm audit --json > vulnerabilities.json

# JavaScript (yarn)
yarn audit --json > vulnerabilities.json

# Java (Maven)
mvn dependency-check:check

# Go
go list -json -m all | nancy sleuth
```

## Comprehensive Workflow

### Step 1: Generate SBOM

```bash
# Python - generate SBOM with CycloneDX
pip install cyclonedx-bom
cyclonedx-py -o sbom.json

# JavaScript - generate SBOM
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Java - generate SBOM
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# Multi-language - using syft
syft dir:. -o json > sbom.json
```

### Step 2: Vulnerability Scanning

```bash
# Scan SBOM with Grype
grype sbom:sbom.json -o json

# OSV.dev scanner (Python, Node, Go, Rust, Java)
osv-scanner --lockfile package-lock.json --format json

# Trivy (multi-language)
trivy fs --security-checks vuln . -f json -o trivy-results.json
```

### Step 3: Malicious Package Detection

**Check for suspicious patterns:**

```bash
# Find packages with install/postinstall scripts
jq '.scripts | select(.install or .postinstall)' package.json

# Check for obfuscated code in node_modules
rg -t js "eval\(|Function\(|atob\(" node_modules/ --files-with-matches

# Find network calls in install scripts
rg -t js "(fetch|http\.get|https\.request|child_process)" node_modules/ -A 3
```

**Analyze package metadata:**

```python
# Check npm package age and download count
import requests
pkg = "suspicious-package"
data = requests.get(f"https://registry.npmjs.org/{pkg}").json()
created = data['time']['created']
weekly_downloads = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{pkg}").json()['downloads']

# Red flags:
# - Created very recently (< 7 days)
# - Similar name to popular package (typosquatting)
# - Very few downloads
# - No repository URL
# - Suspicious maintainer
```

### Step 4: Dependency Confusion Check

```bash
# Find private package names from package.json
jq -r '.dependencies | keys[]' package.json > private_packages.txt

# Check if they exist on public registries
while read pkg; do
  echo "Checking $pkg..."
  # npm
  curl -s "https://registry.npmjs.org/$pkg" | jq -r '.name // "NOT FOUND"'
  # PyPI
  curl -s "https://pypi.org/pypi/$pkg/json" | jq -r '.info.name // "NOT FOUND"'
done < private_packages.txt
```

**If private package name exists publicly: CRITICAL vulnerability**

### Step 5: Typosquatting Detection

```bash
# Generate common typosquat variations
# Example: "requests" → "request", "requets", "reqeusts", "requ3sts"

# Check if typosquat packages exist
curl -s "https://pypi.org/pypi/requets/json" && echo "⚠️ Typosquat found: requets"
```

**Common typosquat patterns:**
- Character omission: `requests` → `requets`
- Character swap: `python` → `pytohn`
- Character addition: `numpy` → `numpyy`
- Lookalike characters: `urllib` → `urlib` (single l)
- Hyphen/underscore: `python-requests` vs `python_requests`

### Step 6: License Compliance

```bash
# Check licenses with pip-licenses (Python)
pip-licenses --format=json --with-urls > licenses.json

# Check licenses with license-checker (Node)
npx license-checker --json > licenses.json

# Identify problematic licenses
jq -r '.[] | select(.licenses | contains("GPL")) | .name' licenses.json
```

**License risk levels:**

| License | Risk | Use in Proprietary? |
|---------|------|---------------------|
| MIT, Apache-2.0, BSD | Low | ✅ Yes |
| LGPL | Medium | ✅ Yes (if dynamically linked) |
| GPL, AGPL | High | ❌ No (copyleft) |
| Unknown, None | Critical | ❌ No (legal risk) |

## Attack Patterns to Detect

### 1. Backdoored Dependencies

```bash
# Check for suspicious network calls
rg -t py -t js "(requests\.post|fetch\(|XMLHttpRequest)" . --files-with-matches

# Check for code execution in setup.py
rg "exec\(|eval\(|compile\(|__import__" setup.py

# Check for file system access in install scripts
rg "os\.system|subprocess\.|open\(" setup.py package.json
```

### 2. Credential Theft

```bash
# Find environment variable access
rg "process\.env|os\.environ|getenv" . -t py -t js

# Find file reads targeting sensitive paths
rg "\.ssh|\.aws|\.kube|id_rsa" . -t py -t js

# Find HTTP posts with env vars
rg "requests\.post.*os\.environ" . -t py
```

### 3. Cryptominers

```bash
# Find crypto-related strings
rg -i "stratum|monero|xmr|bitcoin|mining|hashrate" node_modules/ --files-with-matches

# Find high CPU usage patterns
rg "worker_threads|cluster\.fork|crypto\.createHash" node_modules/ -t js
```

## Tool Integration

### OSV.dev API

```bash
# Query vulnerability by package
curl -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.19"}' \
  | jq '.vulns[].id'
```

### Snyk Integration

```bash
# Snyk scan
snyk test --json > snyk-results.json

# Filter by severity
jq '.vulnerabilities[] | select(.severity == "high" or .severity == "critical")' snyk-results.json
```

### Dependency-Track

```bash
# Upload SBOM to Dependency-Track
curl -X PUT "https://dependency-track.example.com/api/v1/bom" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

## Prioritization

**Critical (immediate action):**
- Malicious package detected
- Dependency confusion vulnerability
- Known exploited CVE (KEV list)
- Credential theft code

**High (1-2 weeks):**
- High/Critical CVE with EPSS > 0.1
- Unmaintained dependencies (no updates in 2+ years)
- GPL license in proprietary code
- Typosquatting risk

**Medium (30-60 days):**
- Medium CVEs
- Outdated dependencies (known vulnerabilities)
- LGPL license concerns
- No SBOM available

**Low (backlog):**
- Informational CVEs
- License documentation missing
- Dependency bloat

## Prevention Best Practices

1. **Lock files:** Always commit `package-lock.json`, `poetry.lock`, `go.sum`
2. **Integrity checks:** Verify checksums/signatures before installing
3. **Private registry:** Use internal registry for private packages
4. **Scope packages:** Use npm scopes (@yourorg/package) to prevent confusion
5. **Minimal dependencies:** Audit and remove unused dependencies
6. **Automated scanning:** Run in CI/CD on every PR
7. **SBOM generation:** Generate and version control SBOMs

## Common Pitfalls

### Pitfall 1: Trusting Download Counts

**Wrong assumption:** "1M downloads/week = safe"

**Reality:** Attackers compromise popular packages (see: event-stream, ua-parser-js)

**Fix:** Verify package integrity, check recent changes, monitor security advisories

### Pitfall 2: Only Checking Direct Dependencies

**Wrong approach:**
```bash
npm list --depth=0  # Only shows direct deps
```

**Reality:** 90% of vulnerabilities are in transitive dependencies

**Correct approach:**
```bash
npm list  # Show full tree
npm audit  # Scans all dependencies
```

### Pitfall 3: Ignoring Install Scripts

**Dangerous:**
```json
{
  "scripts": {
    "postinstall": "node install.js"  // Can run arbitrary code
  }
}
```

**Fix:**
```bash
# Disable install scripts
npm install --ignore-scripts
pip install --no-build-isolation
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "Popular package = safe" | Popular packages get targeted by attackers (supply chain attacks) |
| "Vulnerability is low severity = ignore" | Context matters; "low" SQLi in auth code is critical |
| "We'll update dependencies later" | Vulnerabilities get exploited within days of disclosure |
| "Lock files are unnecessary" | Without locks, you get different versions = unreproducible builds |
| "License compliance is legal's problem" | GPL violations can force open-sourcing your entire codebase |

## Output Template

```markdown
# Supply Chain Security Report

## Summary
- **Total Dependencies:** 247 (42 direct, 205 transitive)
- **Vulnerabilities Found:** 12 (3 critical, 5 high, 4 medium)
- **Malicious Packages:** 0
- **License Issues:** 2 (GPL dependencies)

## Critical Findings

### 1. Dependency Confusion Risk
**Package:** `@company/auth-utils`
**Risk:** Public package with same name exists on npm
**Impact:** Attacker could inject malicious code
**Fix:** Use scoped private registry

### 2. Known Exploited Vulnerability
**Package:** `log4j@2.14.1`
**CVE:** CVE-2021-44228 (Log4Shell)
**EPSS:** 0.97 (actively exploited)
**Fix:** Upgrade to log4j@2.17.1

## Dependency Tree
[Include SBOM or dependency tree visualization]

## Recommended Actions
1. [Priority 1 fixes]
2. [Priority 2 fixes]
3. [Long-term improvements]
```

## Resources

- OSV.dev: https://osv.dev/
- NIST NVD: https://nvd.nist.gov/
- Snyk Vulnerability DB: https://security.snyk.io/
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
- Socket.dev (npm security): https://socket.dev/
- Related Skills: sarif-parsing, triage-priority
