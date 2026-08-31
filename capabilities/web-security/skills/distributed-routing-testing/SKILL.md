---
name: distributed-routing-testing
description: Geo-distributed DNS resolution via in-region open resolvers (Shodan/Censys) to detect geo-fenced infrastructure, GSLB-routed backends, and region-specific endpoints invisible from a single vantage point. Use when the target appears to serve different infrastructure per region, when encountering geo-blocking or geo-fencing, or when recon from a single location misses region-locked assets.
---

# Distributed Routing Testing

**Activation gate:** Only use this skill when `GEO_RESOLVERS_ENABLED` is set (any value). If unset, do not suggest, reference, or offer geo-distributed resolution. Do not ask the user to enable it.

**Credential requirement:** At least one of `SHODAN_API_KEY` or `CENSYS_PAT` must be set. When both are present, `auto` selects Shodan first (cheaper credit cost for this query pattern).

## Concept

Some targets use geo-aware authoritative nameservers, GSLB appliances, or geo-fenced edges that return different A/AAAA records depending on where the DNS **resolver** sits. From a single vantage point you only ever see your own region's answer — the target's region-specific infrastructure is invisible.

This is orthogonal to IP rotation (`flareprox`/`fireprox`): those change the **egress IP** of an HTTP request; this changes the **vantage point** of a DNS lookup.

Open recursive resolvers physically located in different countries act as regional vantage points. Querying the same hostname through resolvers in DE, SG, BR, JP reveals whether the authoritative nameserver hands back different addresses per region.

## When to Use

- **Geo-fencing detected:** target returns `403`, `451`, or redirects to a regional portal based on client geography
- **CDN/GSLB in use:** multiple A records, Anycast ranges, or `X-Served-By` headers suggesting regional routing
- **Recon gap:** subfinder/httpx/nuclei from a single location may miss region-locked subdomains or IP ranges
- **Scope expansion:** in-scope CIDRs may only cover one region; geo-differentiated DNS reveals whether more infra exists elsewhere

## When NOT to Use

- Routine DNS lookups from the local resolver (use `dnsx` instead)
- When `GEO_RESOLVERS_ENABLED` is not set
- For resolving internal/private hostnames (open resolvers cannot reach them)

## Workflow

### 1. Check readiness

```
check_geo_resolver_readiness
```

Confirms the gate is set, which provider keys are present, and how many resolvers are cached.

### 2. Discover resolvers

```
discover_open_resolvers  countries="US,DE,SG,JP,BR,AU"  provider="auto"
```

Queries Shodan or Censys for hosts running recursive DNS in each country, then **verifies** each candidate actually resolves a known hostname to its correct answer. Hijacking resolvers that serve ads or NXDOMAIN-redirect are discarded — they would produce false geo-divergence.

Results are cached **in memory only** for this session.

| Parameter | Default | Notes |
|---|---|---|
| `countries` | (required) | ISO-3166 codes, max 20 |
| `provider` | `auto` | `shodan`, `censys`, or `auto` |
| `max_per_country` | `2` | Verified resolvers per country, 1-5 |
| `verify` | `true` | Probe candidates against a known hostname; strongly recommended |

### 3. Resolve and diff

```
resolve_via_open_resolvers  hostnames="target.example.com,api.example.com"
```

For each hostname, queries every cached resolver and compares the per-country answers against a local baseline (`1.1.1.1` by default). The output tells you:

- **`geo_differentiated`:** whether any country sees different addresses
- **`addresses_only_seen_regionally`:** IPs invisible from your local vantage — the actionable new surface
- **`answers_by_country`:** full answer set per country
- **`unreachable_resolvers`:** resolvers that timed out (expected — open resolvers are unreliable)

| Parameter | Default | Notes |
|---|---|---|
| `hostnames` | (required) | Comma-separated, max 25 per call |
| `countries` | all cached | Filter to specific countries |
| `record_type` | `A` | `A` or `AAAA` |
| `baseline_resolver` | `1.1.1.1` | Override for the local baseline |

### 4. Interpret results

When `geo_differentiated` is `true`:

1. **Check scope.** The region-specific IPs may belong to a different org, CDN, or cloud account. Confirm they fall within the engagement scope before probing.
2. **Differentiate CDN geo-routing from target-owned infra.** CDN Anycast addresses (Cloudflare, Akamai, Fastly) appear as divergent but are expected — they're the CDN serving regional PoPs, not hidden target infra. Compare ASNs.
3. **Probe from the right region.** If the target's infra is genuinely geo-locked, you may need IP rotation (`flareprox`/`fireprox` via the `ip-rotation` skill) to reach it over HTTP.
4. **Feed new IPs back into recon.** Run `httpx`, `nuclei`, and `tlsx` against the newly discovered addresses.

### 5. Clean up

```
clear_open_resolver_cache
```

Discard cached resolvers. Do this when switching engagements.

## Provider Reference

### Shodan (`SHODAN_API_KEY`)

- Query: `port:53 country:{CC} "Recursion: enabled"`
- Auth: `?key=` query parameter
- Cost: 1 query credit per country (filters consume credits)
- Typical yield: 10-100 candidates per country

### Censys (`CENSYS_PAT` / `CENSYS_API_KEY`)

- Query: `host.services: (port=53 and protocol=DNS) and host.location.country_code="{CC}"`
- Auth: `Authorization: Bearer` header
- Optional: `CENSYS_ORGANIZATION_ID` for org-scoped access (required for Starter+)
- Cost: 1 API credit per query
- Typical yield: 5-50 candidates per country

## Constraints

- **Open resolvers are unreliable.** They go offline, get patched, or lie. Verification filters out liars but cannot guarantee availability. Re-discover if results degrade.
- **Rate cap.** Max 20 countries, 25 hostnames, 5 resolvers per country. This prevents runaway credit consumption and excessive probing of third-party infrastructure.
- **Session-scoped.** Nothing is written to disk. Resolvers are cached in memory and disappear when the session ends.
- **UDP only.** Queries use raw UDP to port 53. Environments that block outbound UDP/53 (some cloud sandboxes) will fail silently — check `unreachable_resolvers` in the output.
