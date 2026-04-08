---
name: reconnaissance-planning
description: Strategic reconnaissance planning for external attack surface management. Use when starting a new engagement, choosing initial scan strategy, or deciding how to expand coverage after initial results.
---

# Reconnaissance Planning

## When to Use

- Starting a new ASM engagement against a target
- Deciding scan strategy after initial enumeration
- Expanding coverage when initial results are sparse
- Pivoting approach based on discovered infrastructure

## Phased Approach

### Phase 1: Passive Discovery (Low Noise)

Start with passive techniques to map the target without generating traffic.

**Subdomain Enumeration:**
```
run_bbot_scan(targets=["target.com"], presets=["subdomain-enum"], flags=["passive"])
```

This queries certificate transparency logs, DNS databases, archive.org, and OSINT sources without touching the target directly.

**What to look for after Phase 1:**
- Total number of discovered subdomains (establishes scale)
- Naming conventions (numbered patterns like `app01`, `srv02` suggest more exist)
- Cloud providers visible in DNS (CNAME to AWS, Azure, GCP)
- Mail infrastructure (MX records, SPF/DKIM)
- Development/staging indicators in subdomain names

### Phase 2: Active Enumeration (Moderate Noise)

Probe discovered assets to understand what's running.

**Web service detection + technology fingerprinting:**
```
run_bbot_scan(targets=["target.com"], presets=["subdomain-enum", "web-basic"])
```

**Port scanning on key IPs:**
```
run_bbot_scan(targets=["10.0.0.1"], modules=["portscan"], config=["modules.portscan.ports=top_1000"])
```

**What to look for after Phase 2:**
- HTTP services on non-standard ports
- Technology stack patterns (is everything Rails? Is there one random PHP app?)
- Login pages, admin panels, API documentation
- SSL certificate details (org names, SANs with more domains)
- Default pages or error pages revealing server versions

### Phase 3: Targeted Deep Scanning (Focused)

Focus on high-value targets identified in Phase 2.

**Vulnerability scanning on interesting hosts:**
```
run_bbot_scan(targets=["api.target.com"], presets=["nuclei"])
```

**Web spidering on complex applications:**
```
run_bbot_scan(targets=["app.target.com"], presets=["spider"], config=["web.spider_distance=2", "web.spider_depth=3"])
```

**Screenshot collection for visual triage:**
```
run_bbot_scan(targets=["target.com"], modules=["gowitness"], presets=["subdomain-enum"])
```

**Cloud resource enumeration:**
```
run_bbot_scan(targets=["target.com"], presets=["cloud-enum"])
```

### Phase 4: Expansion & Synthesis

- Cross-reference findings across phases using graph queries
- Look for patterns: shared infrastructure, common technologies, consistent misconfigurations
- Identify assets that warrant manual investigation
- Build the final areas-of-interest list

## Decision Tree: Choosing Scan Strategy

```
Is this a new target with no prior data?
├── YES → Start with Phase 1 (passive subdomain-enum)
└── NO → Do you have subdomains but no service info?
    ├── YES → Run web-basic + tech-detect
    └── NO → Do you have services but no vuln data?
        ├── YES → Run nuclei on interesting hosts
        └── NO → Focus on graph analysis and synthesis
```

## Scale Considerations

| Target Size | Approach |
|---|---|
| Single domain | kitchen-sink preset covers everything |
| Small org (< 50 subdomains) | Full phased approach, thorough coverage |
| Medium org (50-500 subdomains) | Passive first, then targeted active scans on high-value assets |
| Large org (500+ subdomains) | Passive + selective active, prioritize by naming/business context |

## Common Pitfalls

- **Going too broad too early**: Don't run `kitchen-sink` on a large target. You'll drown in data.
- **Ignoring the graph**: Running scans without querying results between phases wastes cycles.
- **Scanning out of scope**: Always use `--whitelist` or `--strict-scope` for targets with clear boundaries.
- **Missing API keys**: Many passive modules (Shodan, SecurityTrails, etc.) need API keys configured in bbot.yml. Check if they're set before relying on passive results.
