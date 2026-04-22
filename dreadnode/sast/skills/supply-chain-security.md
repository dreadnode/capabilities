---
name: supply-chain-security
description: Perform lightweight dependency security checks such as SBOM generation, SCA scanning, dependency confusion checks, and license review. Use for package-level scanning workflows, not dependency-risk assessment.
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Supply Chain Security Analysis

Use this skill for basic dependency and package security checks. It is intentionally narrower than `supply-chain-risk-auditor`.

## When to Use

- Running lightweight dependency vulnerability scans
- Generating or reviewing SBOMs
- Checking dependency confusion or typosquatting exposure
- Reviewing package license posture
- Looking for obviously malicious package behavior in manifests or install scripts

## When NOT to Use

- Dependency maintainer-risk or ecosystem-health assessment (use `supply-chain-risk-auditor`)
- CI/CD workflow security review (use `ci-cd-security`)
- General application vulnerability discovery (use SAST analysis workflows)
- Runtime monitoring or host/infrastructure auditing

## Core Principle

This skill answers: "What do our dependencies contain and what obvious package-level risks exist?"

It does **not** answer: "Which dependencies are strategically risky to trust?" That is the job of `supply-chain-risk-auditor`.

## Quick Checks

### Vulnerability Scanning

```bash
# Python
pip-audit --format json -o vulnerabilities.json

# Node
npm audit --json > vulnerabilities.json

# Go
go list -json -m all | nancy sleuth
```

### SBOM Generation

```bash
# Multi-language
syft dir:. -o json > sbom.json
```

### Dependency Confusion / Registry Presence

```bash
# Example: inspect dependency names from package.json
jq -r '.dependencies | keys[]' package.json
```

Check whether internal-looking package names exist on public registries.

### License Review

```bash
# Python
pip-licenses --format=json --with-urls > licenses.json

# Node
npx license-checker --json > licenses.json
```

## Red Flags

- high/critical known vulnerabilities in production dependencies
- internal package names published publicly
- suspicious install/postinstall scripts
- obvious credential theft or network exfiltration patterns in package setup code
- unknown or disallowed licenses for the deployment context

## Hand-off Rules

Use `supply-chain-risk-auditor` when the task is about:
- maintainer concentration
- project abandonment
- low popularity or ecosystem trust
- governance and security contact quality
- identifying safer replacement dependencies

## Output Guidance

Report:
- package name and ecosystem
- scanner or evidence source
- concrete risk category
- severity or urgency
- recommended next action

If the problem is dependency trust/risk posture rather than a concrete package-level issue, hand off to `supply-chain-risk-auditor`.
