---
name: cypher-query-playbook
description: Neo4j Cypher query patterns for analyzing BBOT reconnaissance data in the graph database. Use when you need to analyze scan results, map infrastructure, find anomalies, or synthesize findings from the attack surface graph.
---

# Cypher Query Playbook

## Quick Reference

## Schema Compatibility

Run `get_db_schema()` before using relationship-heavy queries. BBOT-backed
graphs may expose friendly properties (`name`, `address`, `url`) or the BBOT
event envelope (`data`, `host`, `netloc`, `port`, `tags`, `scope_distance`,
`module`, `scan`). Use `coalesce(n.name, n.data, n.host)` for asset names when
you are not sure which shape is present. Relationship names also vary: some
fixtures use semantic types such as `RESOLVES_TO` and `HAS_PORT`, while BBOT
module output may use DNS-record or module names such as `A`, `CNAME`, `httpx`,
or `nuclei`.

### Orientation Queries (Run First)

**Asset summary:**
```cypher
MATCH (n) RETURN labels(n)[0] as type, count(n) AS count ORDER BY count DESC
```

**Recent scans:**
```cypher
MATCH (s:SCAN) RETURN s.name, s.id, s.start_time ORDER BY s.start_time DESC LIMIT 10
```

**Database schema:**
Use the `get_db_schema` tool for a complete schema overview.

---

## Finding High-Value Assets

**Dev/test/staging subdomains:**
```cypher
MATCH (n:DNS_NAME)
WITH coalesce(n.name, n.data, n.host) AS name
WHERE name =~ '.*(dev|test|stage|uat|vpn|api|admin|internal|staging|qa|sandbox).*'
RETURN name ORDER BY name
```

**Interesting web page titles:**
```cypher
MATCH (n:URL)
WHERE n.status_code = 200
AND n.title =~ '.*(Login|Admin|Dashboard|Unauthorized|Forbidden|Console|Manager|Portal|Panel|Config).*'
RETURN n.name, n.title
```

**Critical and high findings:**
```cypher
MATCH (f:FINDING)
WHERE f.severity IN ['critical', 'high']
RETURN f.type, f.severity, f.description, f.data
```

**Admin panels and login pages:**
```cypher
MATCH (n:URL)
WHERE n.name =~ '.*(admin|panel|dashboard|console|login|signin|auth).*'
AND n.status_code < 400
RETURN n.name, n.status_code, n.title
```

---

## Infrastructure Mapping

**DNS to IP resolution:**
```cypher
MATCH (d:DNS_NAME)-[:RESOLVES_TO]->(ip:IP_ADDRESS)
RETURN d.name, ip.address
ORDER BY ip.address
```

**Find all domains on a specific IP:**
```cypher
MATCH (ip:IP_ADDRESS {address: $ip})<-[:RESOLVES_TO]-(d:DNS_NAME)
RETURN ip.address, collect(d.name) AS domains
```

**Find IPs for a domain:**
```cypher
MATCH (d:DNS_NAME {name: $domain})-[:RESOLVES_TO]->(ip:IP_ADDRESS)
RETURN d.name, ip.address
```

**Shared hosting (IPs with multiple domains):**
```cypher
MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d:DNS_NAME)
WITH ip, collect(d.name) AS domains, count(d) as cnt
WHERE cnt > 1
RETURN ip.address, cnt, domains
ORDER BY cnt DESC
```

**Reverse DNS — all domains per IP:**
```cypher
MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d:DNS_NAME)
RETURN ip.address, collect(d.name) as domains
ORDER BY size(collect(d.name)) DESC
```

---

## Service Discovery

**Web services responding 200:**
```cypher
MATCH (n:URL)
WHERE n.status_code >= 200 AND n.status_code < 300
RETURN n.name, n.status_code, n.title
LIMIT 50
```

**API endpoints:**
```cypher
MATCH (n:URL)
WHERE n.name CONTAINS '/api/' OR n.name CONTAINS '/v1/' OR n.name CONTAINS '/v2/' OR n.name CONTAINS '/graphql'
RETURN n.name, n.status_code, n.title
```

**Interesting ports (databases, admin services):**
```cypher
MATCH (p:OPEN_TCP_PORT)
WHERE p.port IN [3306, 5432, 6379, 27017, 9200, 8080, 8443, 9090, 3389, 5900, 11211]
MATCH (ip:IP_ADDRESS)-[:HAS_PORT]->(p)
RETURN ip.address, p.port, p.service
```

**Services by port:**
```cypher
MATCH (ip:IP_ADDRESS)-[:HAS_PORT]->(p:OPEN_TCP_PORT)
RETURN p.port, count(ip) as host_count
ORDER BY host_count DESC
LIMIT 20
```

---

## Technology Analysis

**All discovered technologies:**
```cypher
MATCH (t:TECHNOLOGY)
RETURN DISTINCT t.name, t.version, count(*) as usage_count
ORDER BY usage_count DESC
```

**Technology stack for a host:**
```cypher
MATCH (d:DNS_NAME {name: $domain})-[:RESOLVES_TO]->(ip)-[:HAS_PORT]->()-[:HAS_TECHNOLOGY]->(t)
RETURN d.name, t.name, t.version
```

**Technology outliers (old/unusual software):**
```cypher
MATCH (t:TECHNOLOGY)
WITH t, coalesce(t.name, t.data) AS tech_name
WHERE tech_name IN ['JBoss', 'ColdFusion', 'Struts', 'WebLogic', 'Tomcat', 'IIS']
OR t.version =~ '.*[0-4]\\..*'
MATCH (n)-[:HAS_TECHNOLOGY]->(t)
RETURN labels(n)[0] as asset_type, coalesce(n.name, n.data, n.host) AS asset, tech_name, t.version
```

**Assets with a specific technology:**
```cypher
MATCH (t:TECHNOLOGY {name: $tech_name})<-[:HAS_TECHNOLOGY]-(n)
RETURN labels(n)[0] as type, n.name, t.version
```

---

## Security Analysis

**All findings by severity:**
```cypher
MATCH (f:FINDING)
RETURN f.severity, count(f) as count
ORDER BY CASE f.severity
  WHEN 'critical' THEN 0
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
  ELSE 4
END
```

**Findings with affected assets:**
```cypher
MATCH (asset)-[:HAS_FINDING]->(f:FINDING)
RETURN f.type, f.severity, f.description, labels(asset)[0] as asset_type, asset.name
ORDER BY f.severity
```

**Public storage buckets:**
```cypher
MATCH (n:STORAGE_BUCKET)
WHERE n.public = true
RETURN n.name, n.url
```

**Exposed databases:**
```cypher
MATCH (p:OPEN_TCP_PORT)
WHERE p.port IN [3306, 5432, 6379, 27017, 9200, 5984, 11211]
MATCH (ip:IP_ADDRESS)-[:HAS_PORT]->(p)
OPTIONAL MATCH (ip)<-[:RESOLVES_TO]-(d:DNS_NAME)
RETURN ip.address, p.port, p.service, collect(d.name) as hostnames
```

---

## Cross-Reference & Correlation

**Shared infrastructure for high-value assets:**
```cypher
MATCH (d:DNS_NAME)-[:RESOLVES_TO]->(ip:IP_ADDRESS)
WHERE d.name CONTAINS 'dev' OR d.name CONTAINS 'api' OR d.name CONTAINS 'staging' OR d.name CONTAINS 'admin'
WITH ip, collect(d.name) AS domains, count(*) as domainCount
WHERE domainCount > 1
RETURN ip.address, domains
```

**Correlate findings by technology:**
```cypher
MATCH (f:FINDING)<-[:HAS_FINDING]-(root)
MATCH (root)-[:HAS_TECHNOLOGY]->(tech:TECHNOLOGY)
MATCH (other_asset)-[:HAS_TECHNOLOGY]->(tech)
WHERE other_asset <> root
RETURN tech.name, collect(DISTINCT other_asset.name) AS related_assets
```

**Discover naming conventions:**
```cypher
MATCH (d:DNS_NAME)
WHERE d.name =~ '.*(app|srv|db|web|mail|ns|mx)0[0-9].*'
RETURN collect(d.name) AS discovered_pattern
```

**Cross-reference: domains sharing IP with a finding:**
```cypher
MATCH (f:FINDING)<-[:HAS_FINDING]-(asset)
OPTIONAL MATCH (asset)-[:RESOLVES_TO]->(ip:IP_ADDRESS)
OPTIONAL MATCH (ip)<-[:RESOLVES_TO]-(sibling:DNS_NAME)
WHERE sibling <> asset
RETURN f.type, asset.name, ip.address, collect(DISTINCT sibling.name) as co_hosted
```

---

## Path Analysis

**Connection paths from domain to finding:**
```cypher
MATCH p=(d:DNS_NAME)-[*1..3]-(f:FINDING)
WHERE d.name = $domain
RETURN p
```

**All relationships for a specific asset:**
```cypher
MATCH (n)-[r]-(m)
WHERE n.name = $name
RETURN labels(n)[0] as source_type, n.name, type(r) as relationship, labels(m)[0] as target_type, m.name
```

**Shortest path between two assets:**
```cypher
MATCH p=shortestPath((n1:DNS_NAME {name: $start})-[*]-(n2:DNS_NAME {name: $end}))
RETURN p
```

---

## Aggregation & Statistics

**Top ports across all hosts:**
```cypher
MATCH (p:OPEN_TCP_PORT)
RETURN p.port, count(p) as cnt
ORDER BY cnt DESC
LIMIT 10
```

**Domains per IP (distribution):**
```cypher
MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d)
RETURN ip.address, count(d) as domain_count
ORDER BY domain_count DESC
LIMIT 20
```

**Email addresses by domain:**
```cypher
MATCH (e:EMAIL_ADDRESS)
WHERE e.address ENDS WITH $domain
RETURN e.address
```

**Cloud provider breakdown:**
```cypher
MATCH (ip:IP_ADDRESS)
WHERE ip.provider IS NOT NULL
RETURN ip.provider, count(ip) as count
ORDER BY count DESC
```

---

## Tips

- **Always use parameters** (`$param`) for user input to prevent Cypher injection
- **Start with small limits** (10-20) and increase if needed
- **Use regex escaping** (`\\`) for special characters in patterns
- **Combine queries** in the Orient phase to build a complete picture before deciding on the next scan
- **Date filtering**: `WHERE n.created_at > datetime('2024-01-01')`
- **NOT conditions**: `WHERE NOT n.status_code IN [404, 403, 401]`
- **Case-insensitive regex**: `WHERE n.name =~ '(?i).*admin.*'`
