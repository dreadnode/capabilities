# Web Security Capability — Agent Instructions

## Core Principle

Never accept findings at face value. Differential analysis alone is NOT proof of a bug — factual ground truth (working PoC with demonstrated CIA impact) is the only way to confirm a vulnerability.

## Impact Gate (mandatory, every finding)

Before calling anything a finding, it must pass all three:

1. **Attacker control** — External attacker can trigger this. Prove the input path.
2. **CIA impact** — Causes concrete confidentiality, integrity, or availability loss to *another user* or *the system*. "I can see X" is not impact unless X is sensitive and unauthorized.
3. **Exploitable now** — Working PoC against the live target, not a theoretical vector.

Fail any one → it's a **lead**, not a finding.

### Always-reject patterns (leads, not findings, unless chained to proven CIA impact)

| Pattern | Why it fails the gate |
|---|---|
| CORS misconfiguration without `Access-Control-Allow-Credentials: true` AND demonstrated exfiltration PoC | No confidentiality impact — browser won't send cookies |
| CORS with credentials but only public/own-user data in response | No *unauthorized* data access |
| WAF bypass that doesn't deliver a payload achieving C/I/A | Bypass is a gadget, delivered payload is the finding |
| Differential behavior (status codes, error messages, timing) without proven exploitation | Observation is recon, not a vulnerability |
| Source map / version / config disclosure without concrete exploitation path | Information is a gadget — show what you do with it |
| Open redirect without chained attack (OAuth token theft, session fixation) | Redirect alone has no C/I/A impact |
| GraphQL introspection / debug endpoints without unauthorized data access or state change | Endpoint existence is not a vulnerability |
| Missing rate limiting without demonstrated account takeover or financial abuse | Theoretical abuse is not demonstrated impact |
| Username / email enumeration without brute-force or credential-stuffing PoC | Enumeration is a gadget, not standalone impact |

## Verification Sequence

Before writing any report:

1. **Impact Gate** — Does it pass all three checks above?
2. **Triple-Check** — Static viability → Dynamic trigger → Sink confirmation with evidence.
3. **Confidence assessment** — Structured reflection on evidence quality.
4. **Report** — Only after steps 1-3 pass.

## Gadget vs Vulnerability

```
Gadget         — code pattern that enables a capability          — NOT reportable
Vulnerability  — attacker-controlled input reaches a gadget      — reportable
                 without sanitization, with demonstrated CIA impact
```

Gadgets go in the ledger. Vulnerabilities get reports. The missing link between them is attacker control + impact proof.
