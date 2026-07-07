---
name: network-ops-methodology
description: "Load when performing network operations or Active Directory exploitation. Enforces enumeration-before-attack discipline, credential verification, trust boundary awareness, scope compliance, reversibility preference, and structured reporting. Prevents premature exploitation, credential misuse, and scope violations."
---

# Network Operations Methodology

**The goal is verified compromise, not activity volume.** One confirmed credential with validated access is worth more than ten unverified hashes.

## Hard Rules

### 1. Enumerate before attacking — never guess when you can query

Do not launch attacks based on assumptions. Query LDAP, SMB, or DNS for the information first. Kerberoasting without confirming SPN existence, spraying credentials without enumerating the password policy, or attempting secretsdump without verifying admin access are all methodology failures.

**Before attacking, confirm:**
- What accounts, groups, and trusts exist?
- What is the password policy (lockout threshold, complexity)?
- What services are running and on which hosts?
- What access does the current credential set provide?

### 2. Verify every credential before relying on it

Never report credential access without testing authentication. A cracked hash that does not authenticate is not a valid credential. Use netexec SMB/LDAP/WinRM auth checks to confirm every recovered credential before using it for lateral movement or escalation.

**Before using a credential:**
- Test authentication against at least one target (netexec SMB auth)
- Confirm access level (look for "Pwn3d!" for local admin)
- Record what the credential can access, not just that it exists

### 3. Map trust relationships before crossing domain boundaries

Never attempt lateral movement to another domain without first enumerating trust relationships. Blind cross-domain attacks waste time and create noise. Query trusts via netexec LDAP, SharpView, or bloodyAD before planning inter-domain attack paths.

### 4. Verify scope at every step

Check Rules of Engagement exclusions before targeting any host, account, or service. Out-of-scope accounts (e.g., vagrant, ansible) must never be targeted, even if they appear vulnerable. Re-verify scope when moving to new network segments or domains.

### 5. Prefer reversible actions over destructive ones

Avoid operations that lock accounts, change production passwords, or corrupt AD objects unless explicitly authorized. Prefer read-only enumeration and non-destructive exploitation paths. When password changes are necessary for exploitation (e.g., RBCD setup), use dedicated machine accounts you create rather than modifying existing ones.

### 6. Track credential provenance

Every credential must have a recorded origin: how it was obtained (Kerberoasting, AS-REP roast, secretsdump, share access, etc.), from which host, and what access it grants. This chain enables accurate attack path reconstruction and supports the report synthesizer.

### 7. Validate hash type and format before cracking

Do not submit hashes to cracking tools without confirming the hash type matches the cracking mode. NTLM hashes use mode 1000, Kerberos TGS uses 13100, AS-REP uses 18200. Mismatched modes waste time and produce false negatives.

### 8. Report findings immediately upon discovery

Use the `report_item` tool as soon as a finding is confirmed — do not batch findings for later. Immediate reporting ensures no data is lost if a stage times out and provides downstream stages with the freshest intelligence.

## Confidence Levels

Every reported finding must include a confidence assessment.

| Level | Criteria | AD-Specific Examples |
|---|---|---|
| **Confirmed** | Full attack path executed, access verified | Credential cracked and authenticated, secretsdump completed, DA access verified |
| **Probable** | Strong indicators but verification incomplete | Hash cracked but auth not tested, delegation path identified but not exploited, ACL abuse path exists but not executed |
| **Suspected** | Pattern match or partial enumeration | SPN found but ticket not requested, potential Kerberoastable account, share accessible but contents not reviewed |

### Severity Calibration

| Impact | Severity | Example |
|---|---|---|
| Domain Admin / Enterprise Admin compromise | Critical | DCSync, Golden Ticket, forest trust abuse |
| Multiple host compromise or domain-wide credential access | High | NTDS dump, mass credential spray success, RBCD to server admin |
| Single host local admin or limited credential recovery | Medium | Single Kerberoasted service account, one share with sensitive data |
| Information disclosure without direct exploitation | Low | User list enumeration, password policy disclosure, SPN enumeration |

## Anti-patterns

| Anti-pattern | Example | Why it's wrong |
|---|---|---|
| Attack before enumerate | Running secretsdump on a host without verifying admin access | Wastes time, creates noise, may trigger alerts |
| Unverified credentials | Reporting "DA compromise" from a cracked hash without auth check | Hash may be expired, disabled, or wrong format |
| Ignoring trust boundaries | Attempting DCSync in child domain with parent domain creds | Trust direction matters — verify before acting |
| Scope violation | Targeting vagrant/ansible accounts despite RoE exclusion | Explicit methodology and ethics failure |
| Blind credential spray | Spraying without checking lockout policy | May lock accounts, violating reversibility rule |
| Premature secretsdump | Running secretsdump before confirming local admin | Command fails, alerts SOC, wastes step budget |
| Ignoring password policy | Spraying 50 passwords when lockout threshold is 5 | Account lockout is destructive and irreversible |
| Orphan hashes | Cracking hashes without recording type, source, or target | Useless for attack path reconstruction |
| Sequential single-target focus | Spending entire budget on one host when others are available | Miss easier paths; breadth before depth |
| Reporting raw output | Dumping tool output without structured reporting | Downstream stages cannot parse unstructured text |

## Reporting Standards

Reports must:
- Use `report_item` with the correct model type (DomainController, Credential, Hash, Weakness, etc.)
- Include credential provenance (source host, extraction method, verification status)
- State access level explicitly (local admin, domain user, DA, EA)
- Map weaknesses to specific misconfigurations (not "AD misconfiguration" but "unconstrained delegation on WEB01$")
- Separate confirmed access from suspected access
- Record attack paths as ordered sequences: initial access → escalation → objective
