---
name: shodan-reconnaissance
description: Shodan query strategies for internet-wide host intelligence, asset discovery, vulnerability correlation, and attack surface mapping. Use when enriching BBOT results with Shodan data, hunting for exposed services, or correlating CVEs with discovered infrastructure.
---

# Shodan Reconnaissance

## Purpose

Use Shodan to complement BBOT reconnaissance with internet-wide scan intelligence. Shodan provides passive host data, banner analysis, CVE correlation, and historical records that BBOT's active scanning may miss.

## Integration with BBOT Graph

The primary workflow is: **BBOT discovers assets → Shodan enriches them.**

1. Query the Neo4j graph for discovered IPs and domains
2. Use Shodan to enrich with service details, CVEs, and historical data
3. Feed Shodan findings back into analysis

### Enrichment Patterns

**Enrich all discovered IPs.** BBOT exposes IPs two ways: as
`(:IP_ADDRESS)` nodes (when `dnsresolve` promoted them to events) and as the
`resolved_hosts` list on every `(:DNS_NAME)`. Cover both:
```cypher
// Explicit IP_ADDRESS nodes
MATCH (ip:IP_ADDRESS) RETURN ip.data AS ip
UNION
// IPs from DNS resolution that may not have been promoted
MATCH (d:DNS_NAME) WHERE d.resolved_hosts IS NOT NULL
UNWIND d.resolved_hosts AS ip
RETURN DISTINCT ip
```
Then for each IP: `shodan_host_info(ip="x.x.x.x")`.

**Find org-wide exposure:**
```
shodan_host_search(query='org:"Target Corp"')
```
Cross-reference results against known IPs in the graph.

**Discover assets BBOT missed:**
```
shodan_host_search(query='ssl.cert.subject.cn:target.com')
shodan_host_search(query='hostname:target.com')
```
Compare with `MATCH (d:DNS_NAME) RETURN d.data` to find gaps.

## Query Strategies

### Asset Discovery

| Goal | Query |
|---|---|
| All hosts for an org | `org:"Target Corp"` |
| Hosts by hostname | `hostname:target.com` |
| Hosts by SSL cert | `ssl.cert.subject.cn:target.com` |
| Hosts by IP range | `net:10.0.0.0/24` |
| Hosts by ASN | `asn:AS12345` |
| Cloud-hosted assets | `org:"Amazon" hostname:target.com` |

### Service Hunting

| Goal | Query |
|---|---|
| Web servers | `hostname:target.com port:80,443` |
| Remote desktop | `port:3389 org:"Target Corp"` |
| SSH servers | `port:22 org:"Target Corp"` |
| Databases | `port:3306,5432,27017,6379 org:"Target Corp"` |
| Elasticsearch | `port:9200 org:"Target Corp"` |
| Docker APIs | `port:2375,2376 org:"Target Corp"` |
| Kubernetes | `port:6443,10250 org:"Target Corp"` |

### Vulnerability Hunting

| Goal | Query |
|---|---|
| Hosts with known CVEs | `vuln:CVE-2021-44228 org:"Target Corp"` |
| Outdated SSL | `ssl.version:sslv2 hostname:target.com` |
| Expired certs | `ssl.cert.expired:true hostname:target.com` |
| Self-signed certs | `ssl.cert.issuer.cn:target.com hostname:target.com` |
| Default credentials | `"default password" org:"Target Corp"` |
| Specific product vulns | `product:"Apache" version:"2.4.49"` |

### Technology Fingerprinting

| Goal | Query |
|---|---|
| Specific product | `product:"nginx" org:"Target Corp"` |
| HTTP title match | `http.title:"Dashboard" org:"Target Corp"` |
| Specific server header | `"Server: Apache/2.4.49"` |
| WAF detection | `http.waf:"Cloudflare" hostname:target.com` |
| CMS detection | `http.component:"WordPress" hostname:target.com` |

## Workflow: Full ASM Enrichment

### Step 1: Check Credits
Always start here to avoid hitting limits.
```
shodan_api_info()
```

### Step 2: Scope Assessment
Use `shodan_count` (free, no credits) before committing to full searches.
```
shodan_count(query='org:"Target Corp"')
shodan_count(query='hostname:target.com')
shodan_count(query='ssl.cert.subject.cn:target.com')
```

### Step 3: Broad Discovery
Run full searches on the most productive queries.
```
shodan_host_search(query='org:"Target Corp"', facets='port,product,country')
```
Facets give you instant distribution analysis without paging through results.

### Step 4: Targeted Enrichment
For high-value IPs found by BBOT, get full details.
```
shodan_host_info(ip="x.x.x.x", history=True)
```
Historical data reveals services that were recently taken down or changed.

### Step 5: CVE Correlation
For any CVEs found on hosts, look up vuln intel via Shodan's CVEDB.
```
shodan_exploits_search(query="CVE-2021-44228")    # full CVSS/EPSS/KEV detail
shodan_exploits_search(query="log4j", limit=10)   # recent CVEs for a product
```
Note: this tool now hits Shodan's CVEDB API directly (the legacy
`exploits.shodan.io` endpoint was deprecated and the shodan-python
library wasn't updated). It consumes no Shodan credits and works
without a paid plan.

### Step 6: DNS Cross-Reference
Validate and expand DNS data.
```
shodan_dns_lookup(hostnames=["api.target.com", "dev.target.com"])
shodan_dns_reverse(ips=["x.x.x.x", "y.y.y.y"])
shodan_dns_domain_info(domain="target.com")  # subdomain inventory + DNS tags
```
`shodan_dns_domain_info` is usually the highest-yield free Shodan call
for ASM — Shodan returns its full crawled subdomain list for the domain
plus DNS-feature tags (e.g. `dmarc`, `spf`, `google-verified`, `ipv6`),
which is far richer than just resolving to IPs.

## Facet Analysis

Facets are the most powerful Shodan feature for ASM. They aggregate across all results without pagination.

**Key facets:**
- `port` — Service distribution
- `product` — Technology distribution
- `country` — Geographic distribution
- `org` — Hosting provider distribution
- `os` — Operating system distribution
- `vuln` — CVE distribution (requires paid plan)
- `ssl.version` — SSL/TLS version distribution
- `http.title` — Web page title distribution

**Example: Full surface profile in one query:**
```
shodan_host_search(
    query='org:"Target Corp"',
    facets='port,product,country,os,vuln,ssl.version'
)
```

## Credit Management

| Operation | Credit Cost |
|---|---|
| `shodan_count` | Free |
| `shodan_host_search` | 1 query credit per page |
| `shodan_host_info` | Free (IP lookups are free) |
| `shodan_dns_lookup` | Free |
| `shodan_dns_reverse` | Free |
| `shodan_dns_domain_info` | Free |
| `shodan_exploits_search` | Free (CVEDB, no credits) |
| `shodan_query_search` / `shodan_query_tags` | Free **but currently returning HTTP 500 from Shodan's backend** — the call shape is correct, the service is down. Re-test periodically. |

**Strategy**: Use `count` + facets first, `host_info` for specific IPs (free), and reserve `host_search` for when you need the full match list.
