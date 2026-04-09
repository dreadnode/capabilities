---
name: cypher-query-playbook
description: Neo4j Cypher query patterns for analyzing BBOT reconnaissance data in the graph database. Use when you need to analyze scan results, map infrastructure, find anomalies, or synthesize findings from the attack surface graph.
---

# Cypher Query Playbook

> **Read this first.** BBOT's `neo4j` output module spreads each event's
> `event.json(mode="graph")` onto the node, so every label shares one envelope:
> `id`, `uuid`, `data`, `type`, `host`, `netloc`, `port`, `tags`,
> `scope_distance`, `module`, `parent`, `dns_children`, `resolved_hosts`, …
>
> The canonical primary value lives in **`.data`** for every label. There is
> no `.name`, `.address`, `.url`, `.title`, `.status_code`, `.provider`, or
> `.public` — those are common a-priori guesses that don't match what BBOT
> actually persists. When in doubt, run `get_db_schema` (or
> `CALL db.schema.nodeTypeProperties()`) and inspect a node directly.
>
> **DNS resolution is two parallel mechanisms.** Whether you traverse a
> `(:DNS_NAME)-[:A|:AAAA|:CNAME]->(...)` relationship or read the
> `n.resolved_hosts` list / `n.dns_children` JSON-string property depends on
> which BBOT modules ran. Patterns below cover both. The `resolved_hosts`
> approach is more universal because every DNS-resolved node carries it.

## Quick Reference

### Orientation queries (run first)

**Asset summary:**
```cypher
MATCH (n) RETURN labels(n)[0] AS type, count(n) AS count ORDER BY count DESC
```

**Recent scans (parse `s.data` as a Python-repr dict):**
```cypher
MATCH (s:SCAN) RETURN s.data ORDER BY s.id DESC LIMIT 10
```

**Database schema:** call the `get_db_schema` MCP tool, or run
`CALL db.labels()`, `CALL db.relationshipTypes()`, and
`CALL db.schema.nodeTypeProperties()` directly.

**Sample a node label** (essential when meeting an unfamiliar label):
```cypher
MATCH (n:DNS_NAME) RETURN keys(n) AS properties, n LIMIT 1
```

### Relationship vocabulary

BBOT names relationships after the **module that emitted the edge** or, for
DNS resolution, after the **DNS record type**. Common types you'll see:

| Relationship | Origin | Typical pattern |
|---|---|---|
| `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, `PTR` | `dnsresolve` (DNS record types) | `(DNS_NAME)-[:A]->(IP_ADDRESS)`, `(DNS_NAME)-[:CNAME]->(DNS_NAME)` |
| `TARGET` | scan setup | `(SCAN)-[:TARGET]->(DNS_NAME\|IP_ADDRESS)` |
| `host` | host helper | scan parent → child for any host event |
| `httpx` | `httpx` module | `(OPEN_TCP_PORT)-[:httpx]->(URL)`, `(URL)-[:httpx]->(URL)` (redirects) |
| `excavate` | `excavate` internal module | `(URL)-[:excavate]->(DNS_NAME\|EMAIL_ADDRESS\|URL_UNVERIFIED)` |
| `speculate` | `speculate` internal module | `(DNS_NAME)-[:speculate]->(OPEN_TCP_PORT\|ORG_STUB)` |
| `cloudcheck`, `dnsresolve`, `badsecrets`, … | named after module | varies by module |

There are **no** semantic relationship types like `RESOLVES_TO`, `HAS_PORT`,
`HAS_TECHNOLOGY`, `HAS_FINDING`, or `USED_BY` in BBOT's neo4j output. If you
need a particular semantic edge that hasn't been emitted by any module in your
scan, traverse via the `resolved_hosts` / `dns_children` properties or via the
generic `host` / `parent` chain instead.

---

## Finding High-Value Assets

**Dev/test/staging subdomains** (regex on `data`, case-insensitive):
```cypher
MATCH (n:DNS_NAME)
WHERE n.data =~ '(?i).*(dev|test|stage|uat|vpn|api|admin|internal|staging|qa|sandbox).*'
RETURN n.data ORDER BY n.data
```

**Admin/login URLs** (path patterns in the URL string itself):
```cypher
MATCH (n:URL)
WHERE n.data =~ '(?i).*(admin|panel|dashboard|console|login|signin|auth).*'
RETURN n.data, n.host, n.port
```

**API endpoints:**
```cypher
MATCH (n:URL)
WHERE n.data CONTAINS '/api/'
   OR n.data CONTAINS '/v1/'
   OR n.data CONTAINS '/v2/'
   OR n.data CONTAINS '/graphql'
RETURN n.data, n.host
```

**Critical/high findings.** `FINDING.data` is a JSON-stringified dict
containing `description`, `host`, `severity`, `url`, etc. Filter via substring
match (severities are typically uppercase: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`):
```cypher
MATCH (f:FINDING)
WHERE f.data CONTAINS '"severity": "CRITICAL"'
   OR f.data CONTAINS '"severity": "HIGH"'
RETURN f.host, f.data
```

**In-scope-only filter** (BBOT tags every node with its scope state):
```cypher
MATCH (n) WHERE 'in-scope' IN n.tags
RETURN labels(n)[0] AS type, count(*) AS cnt ORDER BY cnt DESC
```

---

## Infrastructure Mapping

> Most reconnaissance scans expose DNS resolution two ways: as explicit
> `(:DNS_NAME)-[:A|:AAAA|:CNAME]->(...)` relationships for nodes that BBOT
> actively resolved, **and** via the `resolved_hosts` list property on every
> DNS_NAME (a string array of all IPs the host resolves to, IPv4 + IPv6).
> Prefer `resolved_hosts` for breadth; prefer the typed relationship when you
> need to walk a specific record type.

**All DNS → IP resolutions (resolved_hosts):**
```cypher
MATCH (d:DNS_NAME)
WHERE d.resolved_hosts IS NOT NULL AND size(d.resolved_hosts) > 0
RETURN d.data, d.resolved_hosts
ORDER BY d.data
```

**Find all domains that resolve to a specific IP:**
```cypher
MATCH (d:DNS_NAME)
WHERE $ip IN d.resolved_hosts
RETURN $ip AS ip, collect(d.data) AS domains
```

**Find IPs for a specific domain:**
```cypher
MATCH (d:DNS_NAME {data: $domain})
RETURN d.data, d.resolved_hosts
```

**Shared hosting (IPs hosting multiple in-scope domains):**
```cypher
MATCH (d:DNS_NAME)
WHERE d.resolved_hosts IS NOT NULL
UNWIND d.resolved_hosts AS ip
WITH ip, collect(d.data) AS domains, count(*) AS cnt
WHERE cnt > 1
RETURN ip, cnt, domains
ORDER BY cnt DESC
```

**DNS resolution via explicit DNS-record relationships** (only populated when
`dnsresolve` promoted the IP/CNAME target to its own event):
```cypher
MATCH (d:DNS_NAME)-[r:A|AAAA]->(ip:IP_ADDRESS)
RETURN d.data, type(r) AS record, ip.data
ORDER BY d.data
```

**CNAME chains:**
```cypher
MATCH (d:DNS_NAME)-[:CNAME]->(target:DNS_NAME)
RETURN d.data AS source, target.data AS cname_target
```

**MX record map:**
```cypher
MATCH (d:DNS_NAME)-[:MX]->(mx:DNS_NAME)
RETURN d.data AS domain, collect(mx.data) AS mx_servers
```

**Cloud provider breakdown** (BBOT tags nodes with `cloud-<provider>`):
```cypher
MATCH (n) WHERE any(t IN n.tags WHERE t STARTS WITH 'cloud-')
WITH n, [t IN n.tags WHERE t STARTS WITH 'cloud-'] AS providers
UNWIND providers AS provider
RETURN provider, count(DISTINCT n) AS asset_count
ORDER BY asset_count DESC
```

**WAF / CDN detection:**
```cypher
MATCH (n) WHERE any(t IN n.tags WHERE t STARTS WITH 'waf-' OR t STARTS WITH 'cdn-')
RETURN labels(n)[0] AS type, n.data,
       [t IN n.tags WHERE t STARTS WITH 'waf-' OR t STARTS WITH 'cdn-'] AS protections
LIMIT 50
```

---

## Service Discovery

**All web URLs:**
```cypher
MATCH (u:URL) RETURN u.data, u.host, u.port LIMIT 50
```

**Interesting ports (databases, admin services):**
```cypher
MATCH (p:OPEN_TCP_PORT)
WHERE p.port IN [3306, 5432, 6379, 27017, 9200, 8080, 8443, 9090, 3389, 5900, 11211]
RETURN p.host, p.port, p.data
```

**Port distribution across hosts:**
```cypher
MATCH (p:OPEN_TCP_PORT)
RETURN p.port, count(*) AS host_count
ORDER BY host_count DESC
LIMIT 20
```

**Which OPEN_TCP_PORTs got promoted to URLs by httpx:**
```cypher
MATCH (p:OPEN_TCP_PORT)-[:httpx]->(u:URL)
RETURN p.host, p.port, u.data
```

> **`URL` nodes do not carry `status_code`, `title`, or `content_length`.**
> Those fields live on `HTTP_RESPONSE` events, which BBOT omits from output by
> default (`omit_event_types: [HTTP_RESPONSE]` in `defaults.yml`). Pass
> `--config 'omit_event_types=[]'` to your scan to persist them. Even when
> persisted, the rich fields are stored as a Python-repr-style string inside
> `h.data` (single-quoted), so filter via substring matching:
> ```cypher
> MATCH (h:HTTP_RESPONSE)
> WHERE h.data CONTAINS "'title': 'Login'"
>    OR h.data CONTAINS "'title': 'Admin'"
> RETURN h.host, h.data
> ```

---

## Technology Analysis

> `TECHNOLOGY.data` is the technology name *string* (e.g. `"nginx"`,
> `"cloudflare"`), set via the event's `_pretty_string()` from the
> `technology` field of the underlying dict. There is no separate `version`
> or `category` property on the node — only the name.

**All discovered technologies (deduped, with usage counts):**
```cypher
MATCH (t:TECHNOLOGY)
RETURN t.data AS technology, count(*) AS usage
ORDER BY usage DESC
```

**Technology stack for a specific host:**
```cypher
MATCH (t:TECHNOLOGY)
WHERE t.host = $domain
RETURN DISTINCT t.host, t.port, t.data AS technology
```

**Hosts running a specific technology:**
```cypher
MATCH (t:TECHNOLOGY {data: $tech_name})
RETURN DISTINCT t.host, t.port
```

**Risky / legacy software fingerprints:**
```cypher
MATCH (t:TECHNOLOGY)
WHERE t.data IN ['JBoss', 'ColdFusion', 'Struts', 'WebLogic', 'Tomcat', 'IIS', 'phpMyAdmin']
RETURN t.host, t.port, t.data
```

---

## Security Analysis

> Both `FINDING` and `VULNERABILITY` store their detail as a JSON-stringified
> dict in `.data` (`description`, `host`, `severity`, `url`, …). Use substring
> matching for severity filters and parse the dict client-side if you need
> structured access. Severities are typically uppercase: `INFO`, `LOW`,
> `MEDIUM`, `HIGH`, `CRITICAL`.

**All findings, with affected asset (via the parent edge):**
```cypher
MATCH (asset)-[r]->(f:FINDING)
RETURN labels(asset)[0] AS asset_type, asset.data AS asset, type(r) AS via, f.data AS finding
```

**Findings on a specific host:**
```cypher
MATCH (f:FINDING) WHERE f.host = $host RETURN f.data
```

**Critical/high severity only:**
```cypher
MATCH (f:FINDING)
WHERE f.data CONTAINS '"severity": "CRITICAL"' OR f.data CONTAINS '"severity": "HIGH"'
RETURN f.host, f.data
```

**Confirmed vulnerabilities (`VULNERABILITY` is a stronger signal than `FINDING`):**
```cypher
MATCH (v:VULNERABILITY) RETURN v.host, v.data
```

**Public storage buckets** (`STORAGE_BUCKET.data` is a JSON-string dict; the
`open` flag varies by module — substring-match it):
```cypher
MATCH (b:STORAGE_BUCKET)
WHERE b.data CONTAINS '"open": true' OR 'open-bucket' IN b.tags
RETURN b.host, b.data
```

**Exposed databases (port-based heuristic):**
```cypher
MATCH (p:OPEN_TCP_PORT)
WHERE p.port IN [3306, 5432, 6379, 27017, 9200, 5984, 11211]
RETURN p.host, p.port
```

---

## Cross-Reference & Correlation

**High-value subdomains sharing infrastructure:**
```cypher
MATCH (d:DNS_NAME)
WHERE (d.data CONTAINS 'dev' OR d.data CONTAINS 'api'
       OR d.data CONTAINS 'staging' OR d.data CONTAINS 'admin')
  AND d.resolved_hosts IS NOT NULL
UNWIND d.resolved_hosts AS ip
WITH ip, collect(d.data) AS domains, count(*) AS cnt
WHERE cnt > 1
RETURN ip, domains
```

**Naming-convention discovery (e.g. app01, db02):**
```cypher
MATCH (d:DNS_NAME)
WHERE d.data =~ '(?i).*(app|srv|db|web|mail|ns|mx)0[0-9].*'
RETURN collect(d.data) AS pattern
```

**Domains co-hosted with a domain that has a finding:**
```cypher
MATCH (asset)-[]->(f:FINDING)
WHERE asset.resolved_hosts IS NOT NULL
UNWIND asset.resolved_hosts AS ip
MATCH (sibling:DNS_NAME)
WHERE ip IN sibling.resolved_hosts AND sibling.data <> asset.data
RETURN asset.data AS finding_asset,
       ip,
       collect(DISTINCT sibling.data)[..10] AS co_hosted
```

**Hosts with the same technology fingerprint:**
```cypher
MATCH (t:TECHNOLOGY)
WITH t.data AS tech, collect(DISTINCT t.host) AS hosts
WHERE size(hosts) > 1
RETURN tech, hosts
ORDER BY size(hosts) DESC
```

---

## Path Analysis

**Connection paths from a domain to any finding (≤3 hops):**
```cypher
MATCH p = (d:DNS_NAME {data: $domain})-[*1..3]-(f:FINDING)
RETURN p LIMIT 10
```

**All relationships touching a specific asset:**
```cypher
MATCH (n {data: $value})-[r]-(m)
RETURN labels(n)[0] AS src_type, n.data,
       type(r) AS rel,
       labels(m)[0] AS dst_type, m.data
LIMIT 25
```

**Shortest path between two assets:**
```cypher
MATCH p = shortestPath(
  (n1:DNS_NAME {data: $start})-[*..6]-(n2:DNS_NAME {data: $end})
)
RETURN p
```

---

## Aggregation & Statistics

**Top open ports across all hosts:**
```cypher
MATCH (p:OPEN_TCP_PORT)
RETURN p.port, count(*) AS cnt
ORDER BY cnt DESC LIMIT 10
```

**Domain distribution per resolved IP:**
```cypher
MATCH (d:DNS_NAME) WHERE d.resolved_hosts IS NOT NULL
UNWIND d.resolved_hosts AS ip
RETURN ip, count(d) AS domain_count
ORDER BY domain_count DESC LIMIT 20
```

**Email addresses by domain:**
```cypher
MATCH (e:EMAIL_ADDRESS) WHERE e.data ENDS WITH $domain
RETURN e.data
```

**Subdomain count for a target:**
```cypher
MATCH (n:DNS_NAME) WHERE n.data ENDS WITH $domain
RETURN count(*) AS subdomains
```

**Tag frequency** (great for spotting patterns BBOT detected):
```cypher
MATCH (n) UNWIND n.tags AS tag
RETURN tag, count(*) AS freq
ORDER BY freq DESC LIMIT 30
```

---

## Tips

- **Always parameterize** user input (`$param`) instead of string-concatenating —
  the MCP `query_graph` tool accepts a `params` dict for exactly this.
- **`.data` is always the primary value.** If you find yourself reaching for
  `.name`, `.url`, `.address`, or `.title`, you're guessing — go back and run
  `keys(n)` on a sample node first.
- **Tags carry classification.** BBOT tags nodes with things like `subdomain`,
  `in-scope`, `a-record`, `cloud-amazon`, `waf-cloudflare`, `cdn-cloudfront`,
  `<provider>-ip`, `<provider>-cname`. Filter with
  `WHERE 'tag' IN n.tags` or `any(t IN n.tags WHERE t STARTS WITH 'prefix-')`.
- **`resolved_hosts` is a Cypher list** (no parsing needed); `dns_children` is a
  JSON-encoded **string** (regex match with `=~`, or parse client-side).
- **Dict-shaped event data is stringified.** `FINDING`, `VULNERABILITY`,
  `STORAGE_BUCKET`, `HTTP_RESPONSE`, `WEBSCREENSHOT`, and `SCAN` all carry
  their detail in a Python-repr or JSON string in `.data`. Use `CONTAINS`
  patterns for filtering or parse the string in your client.
- **Start with small `LIMIT` clauses** (10–20) when exploring an unfamiliar
  scan; expand once you trust the shape.
- **Case-insensitive regex:** prefix the pattern with `(?i)`, e.g.
  `WHERE n.data =~ '(?i).*admin.*'`.
- **NOT conditions:** `WHERE NOT 'cloud-google' IN n.tags`.
