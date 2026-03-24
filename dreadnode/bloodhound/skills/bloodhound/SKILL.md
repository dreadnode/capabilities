---
name: bloodhound
description: BloodHound CE attack path analysis — AD graph queries, Cypher, and domain assessment methodology. Use when analyzing Active Directory, finding attack paths, or querying the BloodHound graph.
---

# BloodHound Attack Path Analysis

## Connect First

```
connect(password="...", bloodhound_url="http://bh:8080", neo4j_url="bolt://neo:7687")
```

Or set env vars: `BLOODHOUND_PASSWORD`, `BLOODHOUND_URL`, `NEO4J_URL`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`.

## Four Tools

| Tool | Purpose |
|------|---------|
| `connect(...)` | Authenticate to BloodHound CE API + Neo4j |
| `list_queries(category=)` | Browse the query catalog by category |
| `standard_query(name=)` | Run a named query from the catalog |
| `query(cypher=, params=)` | Run arbitrary Cypher against the graph |

## Query Catalog

Use `list_queries()` to see all available queries. Filter by category:

| Category | What it finds |
|----------|--------------|
| `domain-admins` | Domain Admin members, trust relationships |
| `tier-zero` | Paths to high-value targets, logged-in locations |
| `kerberos` | Kerberoastable users, AS-REP roastable, paths to DA |
| `delegation` | Unconstrained delegation paths |
| `privileges` | DCSync rights, Domain Users with local admin |
| `pki` | CA hierarchy, ESC1/ESC8 vulnerable templates |
| `network` | NTLM relay opportunities, SMB signing, WebClient |
| `hygiene` | Unsupported OS, stale passwords |
| `azure` | Global Admins, Entra-to-on-prem paths |

## Domain Assessment Workflow

### Phase 1: Orientation

```
standard_query(name="find_all_domain_admins")
standard_query(name="map_domain_trusts")
```

Establish the domain structure. How many DAs? Are there trust relationships to other domains?

### Phase 2: Tier Zero Analysis

```
standard_query(name="find_shortest_paths_to_tier_zero")
standard_query(name="find_tier_zero_locations")
standard_query(name="find_paths_from_domain_users_to_tier_zero")
```

If you have owned principals, mark them and check:
```
standard_query(name="find_paths_from_owned_objects")
```

### Phase 3: Quick Wins

```
standard_query(name="find_all_kerberoastable_users")
standard_query(name="find_kerberoastable_tier_zero")
standard_query(name="find_asreproast_users")
standard_query(name="find_paths_from_kerberoastable_to_da")
```

Kerberoastable tier-zero users are critical findings — offline crackable path to DA.

### Phase 4: Delegation & Privilege Abuse

```
standard_query(name="find_shortest_paths_unconstrained_delegation")
standard_query(name="find_dcsync_privileges")
standard_query(name="find_domain_users_local_admins")
```

### Phase 5: PKI/ADCS

```
standard_query(name="find_pki_hierarchy")
standard_query(name="find_esc1_vulnerable_templates")
standard_query(name="find_esc8_vulnerable_cas")
```

ESC1 = enrollee supplies subject + auth-enabled + no approval. ESC8 = NTLM relay to HTTP enrollment.

### Phase 6: Network-Level

```
standard_query(name="find_ntlm_relay_edges")
standard_query(name="find_computers_no_smb_signing")
standard_query(name="find_computers_webclient_running")
```

WebClient + no SMB signing = NTLM relay chain.

### Phase 7: Azure/Hybrid

```
standard_query(name="find_global_administrators")
standard_query(name="find_paths_from_entra_to_tier_zero")
```

## Custom Cypher Queries

When the catalog doesn't cover your case, use `query(cypher=...)`. Read `docs/analysis/explore/cypher-search.md` for syntax.

**Find paths from a specific user to DA:**
```
query(cypher="MATCH p=shortestPath((u:User {name:'USER@DOMAIN.LOCAL'})-[r*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p")
```

**Find all computers a user has admin rights on:**
```
query(cypher="MATCH p=(u:User {name:'USER@DOMAIN.LOCAL'})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN p")
```

**Find users with paths to a specific computer:**
```
query(cypher="MATCH p=shortestPath((u:User)-[r*1..]->(c:Computer {name:'TARGET$'})) RETURN p LIMIT 50")
```

**Mark a principal as owned** (then use `find_paths_from_owned_objects`):
```
query(cypher="MATCH (n {name:'COMPROMISED_USER@DOMAIN.LOCAL'}) SET n.owned=true RETURN n")
```

## Edge Reference

The `docs/edges/` directory contains 132 edge type docs — each describes an AD relationship, how to abuse it, and OPSEC considerations. Key edges:

- **AdminTo** — local admin rights → RCE via PsExec/WMI/WinRM
- **MemberOf** — group membership chains
- **HasSession** — where users are logged in
- **GenericAll/GenericWrite/WriteDacl/WriteOwner** — ACL abuse paths
- **ForceChangePassword** — reset another user's password
- **AddMember** — add yourself to a group
- **DCSync** (GetChanges + GetChangesAll) — replicate credentials
- **AllowedToDelegate/AllowedToAct** — constrained/RBCD delegation
- **Enroll/AutoEnroll** — ADCS certificate abuse
- **CoerceAndRelayNTLM*** — NTLM relay attack chains

Read `docs/edges/<edge-name>.md` for abuse steps and OPSEC notes.

## Node Reference

The `docs/nodes/` directory covers all entity types in the graph (User, Computer, Group, Domain, GPO, OU, CertTemplate, EnterpriseCA, etc.) with their properties and relationships.
