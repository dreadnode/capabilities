---
name: cypher-investigation
description: Open-ended graph investigation via raw OpenCypher queries. Use when the prebuilt tools don't capture the question — bespoke "find every X that can reach Y via Z" queries, ad-hoc relationship walks, novel attack-path patterns, or one-off exports for analysis. Read-only by default; writes require explicit opt-in.
---

# Cypher investigation

The pre-built BHE endpoints answer most common questions, but the graph holds far more than they expose. Cypher is the escape hatch — a query language that walks nodes and edges arbitrarily — and `run_cypher` is the tool that lets the agent ask anything.

The cost of that flexibility is that bad queries can either drown the session in results or accidentally mutate state. This skill walks the agent through the discipline of writing safe, scoped, useful Cypher.

## Preconditions

`bhe-bootstrap` has run.

## Workflow

### 1. Reach for prebuilt tools first

Before writing Cypher, check whether the question maps to one of the dedicated tools:

- "Who has admin on this computer?" → `computer_admins`.
- "What does this user have RDP on?" → `user_admin_rights(kind="rdp-rights")`.
- "What attack paths are active in this domain?" → `domain_attack_paths`.
- "Who is in this asset group tag?" → `list_tag_members`.

Use Cypher only when the answer needs a graph traversal the prebuilt tools don't cover.

### 2. Browse the saved-query library

Call `list_saved_queries`. The deployment usually carries a curated set: "Find all kerberoastable users", "Map domain trusts", "Find shortest paths from owned to high value". Run a saved query before writing a fresh one — saved queries have been reviewed by operators and tend to handle edge cases (excluding gMSAs, capping by domain) the agent's first attempt won't.

### 3. Write the query

A few rules that keep queries productive:

- **Always cap with `LIMIT`** — even small graphs can return tens of thousands of paths from a `MATCH p=shortestPath(...)` query. The runtime injects a default `LIMIT`, but explicit limits give the agent control.
- **Use specific labels** — `MATCH (u:User)` vs `MATCH (u)`. The latter walks every node kind and is dramatically slower.
- **Filter by `objectid` ENDS WITH** for well-known SIDs — `'-512'` for Domain Admins, `'-513'` for Domain Users, `'-519'` for Enterprise Admins.
- **`shortestPath` for attack paths** — finds the minimal route between two anchors. Often the only practical way to enumerate paths in a large graph.
- **Avoid Cartesian products** — multiple `MATCH` clauses without a relationship between them produces N×M rows. Bound them with `WHERE` predicates joined by `AND`.

Examples that come up often:

```cypher
// Every user in Tier Zero who has an SPN (Kerberoastable Tier Zero)
MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true
  AND u.gmsa <> true AND u.msa <> true AND u.highvalue = true
RETURN u
LIMIT 100
```

```cypher
// Shortest paths from Domain Users to Tier Zero
MATCH p = shortestPath((g:Group)-[*1..]->(t))
WHERE g.objectid ENDS WITH '-513' AND t.highvalue = true
RETURN p
LIMIT 50
```

```cypher
// Cert templates with dangerous ESC1 prerequisites
MATCH (ct:CertTemplate)
WHERE ct.requiresmanagerapproval = false
  AND ct.authenticationenabled = true
  AND ct.enrolleessuppliessubject = true
  AND ct.nocertificatemapping = false
RETURN ct
LIMIT 100
```

### 4. Run with `allow_writes=False`

The tool's default refuses queries containing `CREATE`, `MERGE`, `DELETE`, `SET`, `REMOVE`, `DETACH`, or `DROP`. That blocks accidental mutation. If the query genuinely needs to write (rare — usually selector creation is the right path), pass `allow_writes=True` explicitly and document why.

### 5. Interpret + iterate

The tool returns a digest: counts + the first N nodes / edges. If the result is truncated, refine the query rather than asking for more rows — refining is cheaper and produces better-targeted answers. Common refinements:

- Add a domain filter: `AND n.domain_sid = 'S-1-5-21-...'`.
- Restrict by node kind: `MATCH (n:User|Computer)`.
- Bound traversal depth: `[*1..3]` instead of `[*1..]`.

### 6. Persist queries that prove useful

If a query answers a recurring question, persist it via `create_saved_query` so the rest of the team (and future agents) can reuse it. Use a clear name and one-paragraph description — saved queries get accumulated, not curated.

## Output

For one-off investigations, the digest from `run_cypher` is sufficient. For recurring patterns, the output is the persisted saved query plus a one-paragraph explanation of what the query answers and when to reach for it.

## Cost budget

- ≤5 Cypher queries per investigation. If you're running more, you're either iterating on a query that's not converging (rewrite it) or you're flailing (step back and rethink the question).
- One `list_saved_queries` per session.

## What NOT to do

- Don't write `MATCH (n) RETURN n` — even with the default LIMIT, it returns nodes the agent can't act on.
- Don't compose Cypher with f-strings that include user input. The runtime doesn't sanitize, but BHE's own parser will reject malformed input — still, prefer parameter-shaped queries (`WHERE n.objectid = $oid`) when you can; we just don't have a parameter-binding tool yet.
- Don't pass `allow_writes=True` for read queries. The flag is auditable; misuse muddies the audit trail.
- Don't attempt to mutate the graph to "fix" findings. Findings reflect real graph state — fix the underlying AD configuration; the next analysis cycle removes the finding.
