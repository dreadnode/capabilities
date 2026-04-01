---
name: triage-priority
description: Prioritize vulnerability findings by exploitability, impact, and business context using CVSS, EPSS, and risk-based frameworks. Use when analyzing scan results, creating security roadmaps, deciding fix order, or reporting to stakeholders.
allowed-tools:
  - Read
  - Grep
  - Bash
---

# Vulnerability Triage and Prioritization

Systematic approach to prioritizing security findings based on risk, not just severity scores.

## When to Use

Use this skill when:
- Analyzing results from SAST, DAST, or SCA scans
- Creating security fix roadmaps with limited resources
- Deciding which vulnerabilities to fix first
- Explaining security priorities to non-security stakeholders
- Performing risk-based security assessments

**Ideal for:**
- Teams overwhelmed with vulnerability findings
- Organizations needing compliance-focused prioritization
- Security teams reporting to executive leadership

## When NOT to Use

Do NOT use this skill for:
- Initial vulnerability discovery (use audit-context-building or static analysis skills)
- Deep technical analysis of specific vulnerabilities (use variant-analysis)
- Writing vulnerability reports (use issue-writer after prioritization)
- Fixing vulnerabilities (use fix-review after prioritization)

## Core Prioritization Framework

Vulnerabilities are prioritized using a **Risk = Likelihood × Impact** model:

```
Priority = Exploitability Score × Business Impact × Attack Surface Exposure
```

### Exploitability Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| **EPSS Score** | 40% | Exploit Prediction Scoring System (probability of exploitation) |
| **Public Exploit** | 30% | Working exploit code available publicly |
| **Attack Complexity** | 20% | CVSS attack complexity metric |
| **Prerequisites** | 10% | Authentication, user interaction requirements |

### Business Impact Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| **Data Sensitivity** | 35% | PII, payment data, health records, IP |
| **System Criticality** | 30% | Revenue-generating, compliance-required, infrastructure |
| **User Exposure** | 20% | External-facing, internal-only, admin-only |
| **Compliance Impact** | 15% | PCI-DSS, SOC2, HIPAA, GDPR requirements |

### Attack Surface Exposure

| Exposure Level | Multiplier | Description |
|----------------|------------|-------------|
| **Internet-facing** | 3.0x | Public internet access, no authentication |
| **External auth** | 2.0x | Public internet, authentication required |
| **Internal network** | 1.0x | Internal network, VPN required |
| **Privileged access** | 0.5x | Admin-only, air-gapped, or highly restricted |

## Step-by-Step Workflow

### Step 1: Gather Vulnerability Data

Extract key fields from scan results (SARIF, JSON, etc.):

```bash
# Parse SARIF for findings
cat results.sarif | jq '.runs[].results[] | {
  ruleId: .ruleId,
  level: .level,
  message: .message.text,
  location: .locations[0].physicalLocation.artifactLocation.uri,
  line: .locations[0].physicalLocation.region.startLine
}'
```

**Required data points:**
- CWE/CVE identifier
- CVSS score (if available)
- Location (file, line, function)
- Vulnerability category
- Description

### Step 2: Calculate Exploitability Score (0-10)

#### Use EPSS When Available

```bash
# Check EPSS score via API
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX" | jq '.data[0].epss'
```

**EPSS to Exploitability Mapping:**
- EPSS ≥ 0.50: **9-10** (Very High - actively exploited)
- EPSS 0.10-0.49: **7-8** (High - likely to be exploited)
- EPSS 0.01-0.09: **4-6** (Medium - possible exploitation)
- EPSS < 0.01: **1-3** (Low - unlikely exploitation)

#### Manual Exploitability Assessment

If no EPSS score available, use this decision tree:

```
1. Is there a public exploit? (Metasploit, ExploitDB, GitHub)
   YES → Check attack complexity
   NO → Check prerequisites

2. Attack complexity (CVSS AC metric)
   LOW (no special conditions) → 8-10
   MEDIUM (some conditions) → 5-7
   HIGH (many preconditions) → 2-4

3. Prerequisites
   No authentication required → +2
   User interaction required → -1
   Privileged access required → -2
```

**Example:**
- SQL Injection in public API, no auth: **9/10**
- XSS requiring admin login: **5/10**
- Race condition in internal service: **3/10**

### Step 3: Assess Business Impact (0-10)

#### Data Sensitivity (35% weight)

| Data Type | Impact Score |
|-----------|--------------|
| Payment card data (PCI) | 10 |
| Health records (HIPAA) | 10 |
| Personally identifiable information (PII) | 8-9 |
| Authentication credentials | 9 |
| Intellectual property, trade secrets | 8-9 |
| Internal business data | 5-7 |
| Public data, logs, metrics | 1-3 |

#### System Criticality (30% weight)

| System Type | Impact Score |
|-------------|--------------|
| Payment processing, revenue generation | 10 |
| Authentication/authorization systems | 9-10 |
| Production databases | 8-9 |
| Customer-facing applications | 7-8 |
| Internal tools, admin panels | 5-6 |
| Development, staging environments | 2-4 |
| Test systems, documentation sites | 1-2 |

#### User Exposure (20% weight)

| Exposure | Impact Score |
|----------|--------------|
| All users (millions) | 10 |
| Authenticated users (thousands) | 7-8 |
| Internal employees (hundreds) | 4-6 |
| Administrators (tens) | 2-3 |

#### Compliance Impact (15% weight)

- **Compliance violation**: +2 to final impact
- **Audit finding**: +1 to final impact
- **No compliance requirement**: +0

**Calculate weighted impact:**
```
Impact = (Data_Sensitivity × 0.35) +
         (System_Criticality × 0.30) +
         (User_Exposure × 0.20) +
         (Compliance_Impact × 0.15)
```

### Step 4: Determine Attack Surface Exposure

```bash
# Check if service is internet-facing
nmap -sT -p <port> <public-ip>

# Check authentication requirements
curl -I https://example.com/vulnerable-endpoint
# Look for 401/403 without credentials
```

Apply exposure multiplier:
- Internet-facing, no auth: **3.0x**
- Internet-facing, with auth: **2.0x**
- Internal network: **1.0x**
- Privileged/restricted: **0.5x**

### Step 5: Calculate Final Priority Score

```
Priority Score = (Exploitability × Impact × Exposure) / 10
```

**Priority Levels:**

| Score | Priority | Action Timeline |
|-------|----------|-----------------|
| 9-10 | **CRITICAL** | Immediate (24 hours) |
| 7-8 | **HIGH** | 1-2 weeks |
| 5-6 | **MEDIUM** | 30-60 days |
| 3-4 | **LOW** | 90 days |
| 1-2 | **INFORMATIONAL** | Backlog |

### Step 6: Create Prioritized Remediation Plan

Output format:

```markdown
# Vulnerability Remediation Priority

## CRITICAL (Fix within 24 hours)
1. **[CWE-89] SQL Injection in /api/users** (Score: 9.2)
   - Location: api/handlers/users.py:156
   - Impact: Exposes PII of 100k users
   - Exploitability: Public exploit available, EPSS=0.82
   - Fix: Parameterized queries (2-hour fix)

## HIGH (Fix within 1-2 weeks)
...

## MEDIUM (Fix within 30-60 days)
...
```

## Advanced Techniques

### False Positive Filtering

Before prioritizing, filter obvious false positives:

```bash
# Example: Filter test code findings
rg -l "test_.*\.py$" results.txt > test_files.txt
grep -vf test_files.txt results.txt > filtered_results.txt
```

**Common FP patterns:**
- Findings in test files
- Dead code (unreachable)
- Sanitization not detected by SAST
- Framework-provided protections

### Risk Accept Documentation

For LOW/INFORMATIONAL findings that won't be fixed:

```markdown
## Risk Acceptance

**Finding:** [CWE-XXX] [Description]
**Risk Score:** 2.1 (Low)
**Justification:**
- Internal tool, requires admin access
- No sensitive data processed
- Cost to fix (40 hours) exceeds risk
**Compensating Controls:**
- Network segmentation
- Admin access requires 2FA
- Audit logging enabled
**Review Date:** 2026-06-30
**Approved By:** [Security Lead]
```

## Tool Integration

### With Semgrep

```bash
# Run Semgrep with metadata for triage
semgrep --config auto --json -o findings.json .

# Extract high-severity findings
jq '.results[] | select(.extra.severity == "ERROR")' findings.json
```

### With CodeQL

```bash
# Export CodeQL results with CVE mapping
codeql database analyze db/ --format=sarif-latest --output=results.sarif

# Parse for CVE identifiers
jq '.runs[].results[].ruleId' results.sarif | grep -oP 'CVE-\d{4}-\d+' | sort -u
```

### With EPSS API

```bash
# Batch CVE lookup
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678" \
  | jq '.data[] | {cve, epss, percentile}'
```

### With NVD API

```bash
# Get CVSS scores
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234" \
  | jq '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore'
```

## Common Pitfalls

### Pitfall 1: Relying Only on CVSS Severity

**Wrong approach:**
```
Sort by CVSS score: 9.8 CRITICAL → fix first
```

**Why it's wrong:** CVSS doesn't consider exploitability or business context. A 9.8 in an internal dev tool is lower priority than a 6.5 in a payment API.

**Correct approach:**
```
Calculate: CVSS × Exploitability × Business Impact
```

### Pitfall 2: Ignoring Attack Surface

**Wrong approach:**
```
High severity = high priority, regardless of accessibility
```

**Why it's wrong:** An RCE in an air-gapped internal tool is lower risk than SQLi in a public API.

**Correct approach:**
```
Apply exposure multiplier:
- Internet-facing: 3x priority
- Internal: 1x priority
```

### Pitfall 3: Not Filtering False Positives

**Wrong approach:**
```
Prioritize all SAST findings without validation
```

**Why it's wrong:** 30-50% of SAST findings are false positives, wasting triage time.

**Correct approach:**
```
1. Filter obvious FPs (tests, dead code)
2. Validate exploitability with PoC
3. Then prioritize confirmed findings
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "All CRITICAL findings fixed first" | Ignores business context; wastes time on low-risk criticals |
| "Fix everything marked ERROR" | SAST severity ≠ business risk; 50% may be FPs |
| "External findings are always top priority" | Some internal risks (credentials, PII) exceed external low-impact issues |
| "We'll fix them all eventually" | Without triage, teams burn out and miss actually exploitable issues |
| "CVSS score is enough" | CVSS lacks exploitability + business context + exposure factors |

## Output Template

Create a stakeholder-friendly report:

```markdown
# Security Findings Triage Report
**Date:** 2026-01-31
**Scan:** Semgrep + CodeQL Full Scan
**Total Findings:** 247
**After FP Filtering:** 112

## Summary
- CRITICAL: 3 (fix immediately)
- HIGH: 12 (fix within 2 weeks)
- MEDIUM: 35 (fix within 60 days)
- LOW: 62 (backlog)

## Top 5 Priorities

### 1. SQL Injection in User API (Score: 9.5)
- **CWE-89** | api/users.py:156
- **Exploitability:** 9/10 (EPSS=0.89, public exploit)
- **Impact:** 10/10 (100k PII records)
- **Exposure:** Internet-facing, no auth
- **Fix Timeline:** 24 hours
- **Assigned To:** @security-team

[Repeat for top 5]

## Deferred (Risk Accepted)
- 62 LOW findings in internal admin tools
- Documented in risk-acceptance-2026-01.md
```

## Resources

- EPSS API: https://www.first.org/epss/api
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- OWASP Risk Rating: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- Related Skills: sarif-parsing, variant-analysis, fix-review
