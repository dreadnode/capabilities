---
name: ci-cd-security
description: Review CI/CD pipeline configurations for workflow trust-boundary flaws, secret exposure, permission mistakes, and untrusted code execution. Use when auditing GitHub Actions, GitLab CI, Jenkins, or CircleCI pipeline security.
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# CI/CD Security Analysis

Review CI/CD pipelines for security flaws in how workflows are triggered, what they execute, and what secrets or permissions they receive.

## When to Use

- Auditing GitHub Actions, GitLab CI, Jenkins, or CircleCI pipelines
- Checking untrusted input reaching shell commands or workflow expressions
- Reviewing secret exposure, token handling, and permission scope
- Verifying trusted vs untrusted checkout and execution behavior
- Assessing artifact signing and provenance as part of pipeline integrity

## When NOT to Use

- Dependency health or maintainer-risk reviews (use `supply-chain-risk-auditor`)
- Broad dependency scanning, SBOM generation, or license analysis (use `supply-chain-security`)
- General application vulnerability discovery (use SAST analysis workflows)
- Infrastructure as Code, container, or Kubernetes audits

## Core Questions

For every pipeline, answer:

1. Can attacker-controlled input reach a shell, script, or templating context?
2. Can untrusted code run in a privileged workflow context?
3. Are secrets or tokens exposed to pull requests, forks, logs, or artifacts?
4. Are workflow permissions broader than necessary?
5. Is provenance/signing configured where build integrity matters?

## High-Risk Patterns

### Untrusted Input to Shell

Look for workflow expressions or CI variables flowing directly into shell commands.

```bash
rg "run:.*\\$\\{\\{.*(github\\.event|inputs\\.|env\\.)" .github/workflows/ .gitlab-ci.yml Jenkinsfile
```

Examples:
- GitHub Actions `${{ github.event.pull_request.title }}`
- GitLab CI `$CI_COMMIT_REF_NAME`
- Jenkins environment variables interpolated inside `sh "..."`

### Trusted Context + Untrusted Checkout

Look for workflows that run with privileged context but execute attacker-controlled code.

```bash
rg -n "pull_request_target|checkout|ref:.*head.sha|permissions:" .github/workflows/
```

Critical case:
- `pull_request_target`
- checkout of PR head or fork code
- access to repository secrets or write permissions

### Secret Exposure

Look for direct secret interpolation, secret use in PR contexts, or logging of sensitive material.

```bash
rg -n "secrets\\.|token|password|api[_-]?key" .github/workflows/ .gitlab-ci.yml Jenkinsfile
```

Check:
- direct interpolation into `run:` blocks
- secrets available on fork-triggerable workflows
- tokens echoed to logs or written to artifacts

### Over-Broad Permissions

Review workflow/job-level permissions and CI tokens.

```bash
rg -n "^permissions:|actions: write|contents: write|packages: write|id-token: write" .github/workflows/
```

Prefer explicit least-privilege permissions over defaults.

## Minimal Review Workflow

1. Enumerate pipeline files and triggers.
2. Identify workflows exposed to external input.
3. Check whether those workflows execute untrusted code.
4. Review secret handling and permission scope.
5. Note provenance/signing gaps only when they materially affect build trust.

## Output Guidance

Report:
- file and line
- trigger context
- attacker-controlled input or privilege boundary
- concrete impact
- recommended fix

If the issue is only a broader dependency-health concern rather than a workflow flaw, hand off to `supply-chain-risk-auditor`.
