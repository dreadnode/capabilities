# bloodhound-enterprise

A Dreadnode capability that wraps the [BloodHound Enterprise](https://bloodhound.specterops.io) v2 REST API. Gives an LLM HMAC-signed access to attack-path findings, asset-group / tier-zero curation, AD + Azure entity walks, raw + saved Cypher, data ingestion (SharpHound / AzureHound uploads), posture trending, and audit logs — plus a 41-pattern curated query library and a self-driving `attack-pattern-explore` skill so an unfamiliar deployment becomes "list of concrete findings" without operator hand-holding.

Complementary to the existing `bloodhound/` capability — that one talks Bolt to a local Community Edition Neo4j; this one talks REST to a hosted BHE deployment.

## What's in the box

| Shape | Count | Highlights |
|-------|-------|------------|
| Runtime modules | 4 | HMAC client, pydantic types, Cypher helpers, curated library |
| LLM tools | 38 | Across 7 toolsets — auth, attack-paths, asset-groups, entities, cypher, data, posture |
| Curated Cypher patterns | 41 | 12 categories: domain-admins, tier-zero, kerberos, delegation, adcs (ESC1-ESC15), acl-abuse, sessions-lateral, gpo, credentials, azure, trust, owned |
| Skills | 8 | bootstrap, attack-path-triage, tier-zero-audit, attack-pattern-explore, ad-entity-walk, cypher-investigation, exposure-trending, data-ingestion |
| Agents | 3 | `bhe-analyst` meta + `attack-path-hunter` + `tier-zero-curator` |
| Tests | 415 passing |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│   Dreadnode runtime                                          │
│                                                              │
│   tools/* (7 toolsets, 38 LLM tools)                        │
│      ↓                                                       │
│   runtime/client.BHEClient                                   │
│      ↓ HMAC-SHA-256 signed requests OR JWT bearer            │
└──────────────────────────────────────────────────────────────┘
                       ↓
            BloodHound Enterprise REST API
                  (/api/v2/*)
```

## Authentication

Two modes. Configure via env vars or the `connect` tool:

### HMAC (recommended for long-lived integrations)

```bash
export BLOODHOUND_URL="https://bhe.example.com"
export BHE_TOKEN_ID="..."
export BHE_TOKEN_KEY="..."
```

Each request is signed with the published three-stage HMAC chain:

1. `OperationKey = HMAC-SHA-256(token_key, METHOD + URI)`
2. `DateKey = HMAC-SHA-256(OperationKey, RFC3339_datetime[:13])`
3. `Signature = HMAC-SHA-256(DateKey, body_bytes)` → base64

Headers: `Authorization: bhesignature <token_id>`, `RequestDate: <RFC3339>`, `Signature: <base64>`.

### JWT (interactive)

```bash
export BLOODHOUND_URL="https://bhe.example.com"
export BHE_USERNAME="alice@example.com"
export BHE_PASSWORD="..."
```

The first `connect` exchanges credentials for a session token. Token expires per server policy.

## Tool surface

| Toolset | Tool | Purpose |
|---------|------|---------|
| `auth` | `connect`, `whoami`, `api_version`, `list_api_tokens`, `create_api_token`, `revoke_api_token` | session + credential management |
| `attack_paths` | `list_attack_paths`, `list_attack_path_types`, `domain_attack_paths`, `domain_attack_path_details`, `attack_path_sparklines`, `attack_path_trends`, `export_attack_path_findings`, `accept_finding_risk`, `start_attack_path_analysis` | findings, trends, risk acceptance |
| `asset_groups` | `list_asset_groups`, `list_asset_group_tags`, `get_asset_group_tag`, `list_tag_members`, `count_tag_members`, `search_asset_group_tags`, `list_tag_selectors`, `create_tag_selector`, `delete_tag_selector`, `preview_selector`, `certify_member`, `get_certifications`, `tag_history` | tier curation + selectors |
| `entities` | `get_entity`, `entity_controllers`, `entity_controllables`, `user_admin_rights`, `user_admins`, `user_sessions`, `user_membership`, `computer_admins`, `computer_sessions`, `computer_admin_rights`, `cert_template_info`, `cert_template_cas`, `azure_entity` | per-principal walks |
| `cypher` | `run_cypher`, `list_saved_queries`, `run_saved_query`, `create_saved_query`, `delete_saved_query`, `list_attack_patterns`, `run_attack_pattern`, `describe_attack_pattern` | graph queries + curated library |
| `data` | `search_graph`, `list_file_upload_jobs`, `create_file_upload_job`, `upload_collection_file`, `end_file_upload_job`, `accepted_upload_types`, `list_clients`, `list_client_jobs`, `schedule_collection_job` | search + ingest |
| `posture` | `posture_snapshot`, `posture_history`, `audit_logs` | exposure + audit |

## Skills

- **`bhe-bootstrap`** — confirm credentials work; precondition for everything else.
- **`attack-pattern-explore`** — autonomous discovery: walk the 41-pattern catalog, surface concrete findings, recommend follow-ups.
- **`attack-path-triage`** — rank active findings, drill into evidence, hand off to remediation.
- **`tier-zero-audit`** — review tier-zero membership, certify deliberate inclusions, surface drift.
- **`ad-entity-walk`** — single-principal blast-radius investigation.
- **`cypher-investigation`** — open-ended Cypher with safety guards.
- **`exposure-trending`** — produce a stakeholder report on posture deltas.
- **`data-ingestion`** — push SharpHound / AzureHound output and monitor processing.

## Agents

- **`bhe-analyst`** — meta-orchestrator. Routes open-ended questions to specialist skills.
- **`attack-path-hunter`** — focused triage specialist. Returns ranked, evidence-backed action plans.
- **`tier-zero-curator`** — Tier Zero hygiene specialist. Recommends certifications + revocations; flags shadow changes.

## Curated query library

`runtime/cypher_library.py` ships 41 read-only OpenCypher patterns covering:

- **Domain admins / trusts**: DA / EA membership, DCSync rights, trust map.
- **Tier Zero**: shortest paths to / from / sessions / non-DC review.
- **Kerberos**: roastable (all + Tier Zero), AS-REP roastable.
- **Delegation**: unconstrained, constrained, RBCD, S4U2Self.
- **ADCS**: ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC8, ESC15.
- **ACL abuse**: GenericAll / WriteDacl / ResetPassword / Shadow Creds / AdminSDHolder on Tier Zero.
- **Sessions / lateral**: RDP fan-out, sessions on DCs, owned-to-tier-zero paths.
- **GPO**: writable GPOs, GPOs linked to DC OUs, GPOs linked to TZ-bearing OUs.
- **Credentials**: LAPS readers, gMSA readers, stale TZ accounts, old-password TZ.
- **Azure**: Global Admins, subscription Owners, app credential writers, VM contributors.
- **Trust**: SID history, foreign-domain TZ controllers.

Each entry is read-only, LIMIT-bounded, and carries a description explaining why it matters and how an attacker exploits it. Browse via `list_attack_patterns`, run via `run_attack_pattern("pattern-id")`, read source via `describe_attack_pattern`.

## Quickstart

```python
# Set credentials
export BLOODHOUND_URL="https://bhe.example.com"
export BHE_TOKEN_ID="..."
export BHE_TOKEN_KEY="..."

# In the runtime, call from an agent or tool:
@bhe-analyst please audit this deployment for tier-zero exposure
```

The meta-agent runs `bhe-bootstrap` then routes through the relevant specialists.

## Environment

| Var | Default | Purpose |
|-----|---------|---------|
| `BLOODHOUND_URL` | (required) | Base URL of the BHE deployment |
| `BHE_TOKEN_ID` | (HMAC mode) | API token id |
| `BHE_TOKEN_KEY` | (HMAC mode) | API token key |
| `BHE_JWT` | (JWT mode) | Pre-obtained session token |
| `BHE_USERNAME` | (JWT mode) | Login email for `connect` |
| `BHE_PASSWORD` | (JWT mode) | Login password |
| `BHE_VERIFY_SSL` | `true` | Set to `false` for self-signed certs |
| `BHE_TIMEOUT` | `30` | Default per-request timeout (seconds) |

## Running tests

```bash
cd capabilities/bloodhound-enterprise
uv run --with pytest --with pytest-asyncio --with httpx --with pydantic \
       --with pyyaml --with loguru pytest tests/ -q
```

Tests cover the HMAC signing chain (8 reference vectors), client behaviours (auth header construction, error mapping, env config), Cypher safety guards (write detection, LIMIT injection, graph summarisation), the curated library (every pattern is read-only, LIMIT-bounded, and has the required fields), and capability manifest sanity (skills + agents + tool modules parse).

## Layout

```
.
├── README.md
├── capability.yaml
├── pyproject.toml
├── runtime/
│   ├── client.py              # BHEClient + HMAC signing
│   ├── cypher_helpers.py      # is_write_query, ensure_limit, summarise_graph
│   ├── cypher_library.py      # 41 curated attack-pattern queries
│   └── types.py               # pydantic models
├── tools/                     # 7 Toolset modules, 38 @tool_methods
├── skills/                    # 8 SKILL.md playbooks
├── agents/                    # 3 agent persona files
└── tests/                     # 415 unit + integration tests
```

## What this capability deliberately does NOT cover

The BHE API has admin / governance surfaces this capability skips:

- User CRUD (list / create / update / delete users; password / MFA management). Out of scope for an analyst agent.
- SSO providers (SAML / OIDC create / update / delete).
- Collector binary management (manifests, downloads, checksums).
- AIA CA endpoints (PKI hierarchy traversal beyond cert-template + EnterpriseCA).

Each is a few hundred lines of additional surface and roughly an extra skill. Add when concrete demand surfaces.

## References

- [BHE API overview](https://bloodhound.specterops.io/reference/overview)
- [Working with the BHE API](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api)
- [SpecterOps `apiclient.py` reference impl](https://github.com/SpecterOps/bloodhound-docs/blob/main/docs/assets/apiclient.py)
- [BloodHound community edition (`bloodhound`)](../bloodhound/) — the Bolt-to-Neo4j companion capability
