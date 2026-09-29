# bloodhound

Wires a local [BloodHound Community Edition](https://bloodhound.specterops.io) deployment into chat and agents. The MCP authenticates to the CE REST API to verify the session, then runs **Cypher against the underlying Neo4j graph over Bolt** for AD/Entra attack-path analysis — domain enumeration, Tier Zero, Kerberos, delegation, ADCS, NTLM relay, and hygiene. It ships ~25 named "standard queries" alongside an arbitrary-Cypher tool.

Twin of `bloodhound-enterprise/`: **this** talks Bolt to a local CE Neo4j; **that** talks HMAC-signed REST to a hosted BloodHound Enterprise deployment. Use this one when you run your own CE/Neo4j stack.

## Setup

The server connects to two endpoints — the CE web API (to authenticate) and the Neo4j graph (where queries run). Both default to a standard local CE Docker stack; the only value you must supply is the BloodHound password:

| Var | Default | Reason to change |
|-----|---------|------------------|
| `BLOODHOUND_URL` | `http://localhost:8080` | CE running on another host/port |
| `BLOODHOUND_USERNAME` | `admin` | non-default CE account |
| `BLOODHOUND_PASSWORD` | (required) | the CE login secret — no default |
| `NEO4J_URL` | `bolt://localhost:7687` | Neo4j not co-located with CE |
| `NEO4J_USERNAME` | `neo4j` | non-default Neo4j account |
| `NEO4J_PASSWORD` | `bloodhoundcommunityedition` | you changed the CE Neo4j password |
| `NEO4J_DATABASE` | `neo4j` | multi-database Neo4j |

Set these as capability secrets, or pass them at runtime via the `connect` tool (overrides env for the session). Until a password is present the server raises `Not connected` on first query.

## Before you trust it

- **Read/query only.** The four tools (`connect`, `query`, `standard_query`, `list_queries`) execute Cypher against the graph — there is no SharpHound/AzureHound ingest path here. Collect and import data with the normal CE tooling first; this capability analyzes what's already loaded.
- **`query` runs arbitrary Cypher** with the configured Neo4j credentials — scope those credentials to the read posture you want.
- **`docs/`** is imported SpecterOps BloodHound reference (node/edge/glossary docs), bundled under its own Apache-2.0 `LICENSE` for offline schema lookup.

Agent-facing usage — Cypher idioms, the standard-query catalog, and attack-path tradecraft — lives in `skills/bloodhound/`, not here.
