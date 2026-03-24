---
name: bloodhound
description: Use when analyzing Active Directory attack paths, querying the BloodHound graph, or assessing domain security posture.
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

Use `list_queries()` to see all. Filter by category:

| Category | What it finds |
|----------|--------------|
| `domain-admins` | DA members, trust relationships |
| `tier-zero` | Paths to high-value targets, logged-in locations |
| `kerberos` | Kerberoastable users, AS-REP roastable, paths to DA |
| `delegation` | Unconstrained delegation paths |
| `privileges` | DCSync rights, Domain Users with local admin |
| `pki` | CA hierarchy, ESC1/ESC8 vulnerable templates |
| `network` | NTLM relay, SMB signing, WebClient |
| `hygiene` | Unsupported OS, stale passwords |
| `azure` | Global Admins, Entra-to-on-prem paths |

## Domain Assessment Workflow

### Phase 1: Orientation
```
standard_query(name="find_all_domain_admins")
standard_query(name="map_domain_trusts")
```
How many DAs? Trust relationships to other domains?

### Phase 2: Tier Zero
```
standard_query(name="find_shortest_paths_to_tier_zero")
standard_query(name="find_tier_zero_locations")
standard_query(name="find_paths_from_domain_users_to_tier_zero")
standard_query(name="find_paths_from_owned_objects")
```

### Phase 3: Quick Wins
```
standard_query(name="find_all_kerberoastable_users")
standard_query(name="find_kerberoastable_tier_zero")
standard_query(name="find_asreproast_users")
standard_query(name="find_paths_from_kerberoastable_to_da")
```
Kerberoastable tier-zero users = offline crackable path to DA.

### Phase 4: Delegation & Privileges
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

### Phase 6: Network
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

## Custom Cypher

When the catalog doesn't cover your case, use `query(cypher=...)`. Read `docs/analysis/explore/cypher-search.md` for syntax.

```
# Paths from specific user to DA
query(cypher="MATCH p=shortestPath((u:User {name:'USER@DOMAIN.LOCAL'})-[r*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p")

# Computers a user has admin on
query(cypher="MATCH p=(u:User {name:'USER@DOMAIN.LOCAL'})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN p")

# Mark a principal as owned
query(cypher="MATCH (n {name:'COMPROMISED@DOMAIN.LOCAL'}) SET n.owned=true RETURN n")
```

## Key Edge Types

Read `docs/edges/<edge-name>.md` for abuse steps and OPSEC notes per edge. 132 total.

| Edge | Source → Target | Abuse |
|------|----------------|-------|
| AdminTo | User/Group → Computer | RCE via PsExec/WMI/WinRM |
| MemberOf | Any → Group | Group membership chains |
| HasSession | Computer → User | Where users are logged in |
| GenericAll | Any → Any | Full control — reset password, modify object |
| GenericWrite | Any → Any | Write arbitrary attributes |
| WriteDacl | Any → Any | Modify ACL to grant yourself access |
| WriteOwner | Any → Any | Take ownership, then WriteDacl |
| ForceChangePassword | User → User | Reset another user's password |
| AddMember | Any → Group | Add yourself to a group |
| GetChanges + GetChangesAll | Any → Domain | DCSync — replicate all credentials |
| AllowedToDelegate | Computer → Computer | Constrained delegation abuse |
| AllowedToAct | Any → Computer | RBCD (resource-based constrained delegation) |
| Enroll | Any → CertTemplate | ADCS certificate enrollment |
| CoerceAndRelayNTLM* | Computer → Any | NTLM relay attack chains |

## Node Reference

`docs/nodes/` covers all entity types (User, Computer, Group, Domain, GPO, OU, CertTemplate, EnterpriseCA, etc.) with properties and relationships.
