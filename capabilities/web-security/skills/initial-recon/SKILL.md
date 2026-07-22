---
name: initial-recon
description: Use when beginning a web assessment from a domain, wildcard, ASN, organization, IP list, or CIDR and measurable attack-surface coverage is needed.
allowed-tools: bash
---

# Initial Reconnaissance

Establish a bounded breadth baseline before choosing deep tests. Keep this phase short for a single URL; use the full funnel for wildcards, organizations, ASNs, IP lists, and CIDRs.

## Funnel

1. Confirm scope and separate inherited assets from newly discovered assets.
2. For domain scope, enumerate with `subfinder`, resolve with `dnsx`, then probe with ProjectDiscovery `httpx`.
3. For IP or CIDR scope, discover ports with `naabu`, then probe responsive hosts with ProjectDiscovery `httpx`. Add `tlsx` when certificate names can expand the map.
4. Use `katana` only on responsive web applications. Use `nuclei` only on confirmed, high-signal targets.
5. Prefer JSON/JSONL output and preserve it as an artifact. Orient on the results before adding breadth or beginning exploitation.

Use the ProjectDiscovery binary resolver because `httpx` may otherwise resolve to the unrelated Python CLI:

```bash
PD="scripts/pd-tool"  # capability root is the tool working directory
"$PD" subfinder -d example.com -json -silent
"$PD" dnsx -json -silent
"$PD" naabu -host 192.0.2.0/24 -json -silent -rate 500
"$PD" httpx -json -silent -title -tech-detect -status-code
```

If a dedicated binary is unavailable, use the smallest available fallback and record that substitution. Do not rebuild high-volume enumeration with sequential `curl` or `dig` loops when the provisioned ProjectDiscovery tools are healthy.

## Coverage ledger

Write a ledger with `scripts/write_coverage_ledger.py` after each completed phase. Record facts, not intent:

- scope and tool
- status: `completed`, `partial`, or `failed`
- addresses or hosts scheduled and completed
- ports scheduled
- responsive hosts and facts produced
- artifact path
- deferred scope and reason

Never describe a scan as comprehensive without scheduled/completed denominators. A timeout is partial coverage unless the saved artifact proves completion.

## Handoff

Rank responsive assets by exposed identity/admin/API surfaces, non-standard ports, unusual technology, and exploitable behavior. Hand the highest-signal assets back to the normal web-security OODA loop; focused testing remains more valuable than indiscriminate scanning.
