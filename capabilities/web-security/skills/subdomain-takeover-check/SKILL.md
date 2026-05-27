---
name: subdomain-takeover-check
description: Ground-truth subdomain takeover candidates by checking CNAME resolution, verifying service availability, and validating fingerprint matches against can-i-take-over-xyz before reporting. Use when an agent or scanner flags a potential subdomain takeover, dangling CNAME, or unclaimed cloud resource.
---

# Subdomain Takeover Ground-Truth Check

Validates subdomain takeover candidates against the canonical [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) service registry.

## Procedure

1. **Resolve DNS** — identify the target service:
   ```bash
   dig CNAME <subdomain> +short
   ```
   If no CNAME is returned, check for A/AAAA records with `dig A <subdomain> +short`. No DNS resolution at all suggests the record was already cleaned up — flag as INVESTIGATE but note DNS is clean.

2. **Fetch the registry** — pull the raw README and find the service row:
   ```bash
   curl -s https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md | rg -i "<service_name>"
   ```
   If the registry fetch fails (network error, 404), note it and proceed with manual assessment.

3. **Check status** — is the service listed as `Vulnerable`, `Not Vulnerable`, or `Edge Case`?

4. **Match fingerprint** — fetch the subdomain and check for the documented fingerprint:
   ```bash
   curl -skL "https://<subdomain>" -o /tmp/takeover_body.txt 2>/dev/null
   rg -c "NoSuchBucket\|There isn't a GitHub Pages site here\|This page is reserved" /tmp/takeover_body.txt
   ```

5. **Credence check** — run `credence assess_confidence` with: service name, registry status, fingerprint match result, and raw evidence

## Output

Always log the result in the target's gadget-ledger and flag to the user. Format:

```
## Subdomain Takeover: <subdomain>
- CNAME: <target>
- Service: <service name>
- Registry status: Vulnerable | Not Vulnerable | Edge Case | Not Listed
- Fingerprint match: Yes | No | N/A
- Credence: <confidence level>
- Verdict: LIKELY VALID | INVESTIGATE | LIKELY FP
```

## Philosophy

**Prefer alerts over missed true positives.** This check adds confidence, not a gate. If the service is Not Listed or the fingerprint is ambiguous, flag it as INVESTIGATE — never silently drop.
