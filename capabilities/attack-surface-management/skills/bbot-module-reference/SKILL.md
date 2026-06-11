---
name: bbot-module-reference
description: BBOT module and preset reference for reconnaissance scanning. Use when choosing which modules, presets, or flags to use for a BBOT scan, or when you need to understand what a specific module does.
---

# BBOT Module & Preset Reference

## Presets (-p flag)

Presets are curated combinations of modules for common tasks.

### Discovery

| Preset | Purpose | Key Modules |
|---|---|---|
| `subdomain-enum` | Comprehensive subdomain discovery | anubisdb, certspotter, crt, dnsdumpster, dnsbrute, shodan_dns, securitytrails, wayback, +40 more |
| `cloud-enum` | Cloud resource enumeration (includes subdomain-enum) | bucket_amazon, bucket_azure, bucket_firebase, bucket_google |
| `code-enum` | Git repos, Docker images | github_codesearch, dockerhub, git_clone, postman |
| `email-enum` | Email address harvesting | emailformat, hunterio, pgp, skymem |

### Web Scanning

| Preset | Purpose | Key Modules |
|---|---|---|
| `web-basic` | Quick web scan for essentials | httpx, wappalyzer, badsecrets, robots, sslcert, ffuf_shortnames |
| `web-thorough` | Aggressive web scan (includes web-basic) | All web-basic + web-thorough flagged modules |
| `spider` | Recursive web crawling | distance:2, depth:4, 25 links/page |
| `spider-intense` | Aggressive spidering | distance:4, depth:6, 50 links/page |
| `tech-detect` | Technology detection only | wappalyzer, nuclei tech templates, fingerprintx |

### Vulnerability Scanning

| Preset | Purpose | Notes |
|---|---|---|
| `nuclei` | Template-based vulnerability scanning | directory_only mode |
| `nuclei-intense` | All URLs with robots/urlscan/wayback | More thorough, slower |
| `nuclei-technology` | Templates matching discovered tech | Targeted based on detected stack |
| `nuclei-budget` | Low-hanging fruit mode | budget:10, fastest nuclei option |

### Fuzzing

| Preset | Purpose | Notes |
|---|---|---|
| `dirbust-light` | Basic directory brute-force | 1000-line wordlist |
| `dirbust-heavy` | Recursive directory brute-force | 5000-line wordlist, depth:3 |
| `lightfuzz-light` | Basic fuzzing | path, sqli, xss only |
| `lightfuzz-medium` | All fuzzing modules | No POST requests |
| `lightfuzz-heavy` | Intense fuzzing | Includes POST and paramminer |
| `paramminer` | Parameter discovery | Brute-force parameter names |

### Specialized

| Preset | Purpose |
|---|---|
| `baddns-intense` | DNS misconfiguration checks (CNAME, MX, NS, TXT) |
| `iis-shortnames` | IIS shortname enumeration |
| `dotnet-audit` | Comprehensive IIS/.NET scanning |
| `fast` | Minimal discovery, strict scope |
| `kitchen-sink` | Everything combined (use with caution on large targets) |

## Flags (-f flag)

Flags enable groups of modules sharing a characteristic.

| Flag | Description | Use When |
|---|---|---|
| `passive` | No direct target contact | Stealth required |
| `safe` | Non-intrusive modules only | Production systems |
| `active` | Modules that contact target | Standard engagement |
| `aggressive` | Potentially disruptive | Lab/controlled environment |
| `subdomain-enum` | All subdomain discovery | Comprehensive DNS mapping |
| `web-basic` | Essential web modules | Quick web assessment |
| `web-thorough` | Extended web modules | Deep web analysis |
| `web-screenshots` | Visual capture | Screenshot collection |
| `portscan` | Port scanning | Network service discovery |
| `cloud-enum` | Cloud resources | Cloud-focused targets |
| `code-enum` | Code repositories | OSINT / code leakage |

## Key Modules

### Subdomain Discovery
- `dnsbrute` — Active DNS brute-forcing with wordlists
- `certspotter` / `crt` — Certificate transparency logs
- `dnsdumpster` — DNSDumpster.com queries (passive)
- `wayback` — Archive.org historical data
- `shodan_dns` — Shodan DNS database (requires API key)
- `securitytrails` — Historical DNS records (requires API key)

### Web Analysis
- `httpx` — Fast web service detection, status codes, titles
- `gowitness` — Web page screenshots (configurable resolution)
- `wappalyzer` — Technology fingerprinting
- `ffuf` — Fast web fuzzer for directories/files
- `nuclei` — Template-based vulnerability scanner

### Cloud Resources
- `bucket_amazon` / `bucket_azure` / `bucket_google` — Storage bucket enumeration
- `azure_realm` / `azure_tenant` — Azure-specific enumeration
- `oauth` — OAuth endpoint discovery

### Security Testing
- `badsecrets` — Hardcoded secrets/keys detection
- `baddns` — DNS misconfigurations and potential takeovers
- `lightfuzz` — Lightweight vulnerability fuzzing
- `git` / `gitdumper` — Exposed git repository detection and dumping

### OSINT / Code
- `github_codesearch` — Search code for secrets/info
- `dockerhub` — Docker image discovery
- `postman` — API documentation discovery
- `social` — Social media profile enumeration

## Common Recipes

**Passive-only subdomain discovery:**
```
targets=["target.com"], presets=["subdomain-enum"], flags=["passive"]
```

**Subdomain enum + basic web scan:**
```
targets=["target.com"], presets=["subdomain-enum", "web-basic"]
```

**Targeted nuclei scan on known hosts:**
```
targets=["api.target.com", "admin.target.com"], presets=["nuclei"]
```

**Technology detection across all subdomains:**
```
targets=["target.com"], presets=["subdomain-enum", "tech-detect"]
```

**Screenshot collection:**
```
targets=["target.com"], modules=["gowitness"], presets=["subdomain-enum"]
```

**Cloud resource hunt:**
```
targets=["target.com"], presets=["cloud-enum"]
```

**Deep web spider on specific app:**
```
targets=["app.target.com"], presets=["spider"], config=["web.spider_distance=2", "web.spider_depth=3"]
```

**Full kitchen sink (small targets only):**
```
targets=["target.com"], presets=["kitchen-sink"]
```

## Configuration Tips

- **API keys**: Configure in `~/.config/bbot/bbot.yaml` for modules like Shodan, SecurityTrails, VirusTotal
- **Scope control**: Use `extra_args=["--strict-scope"]` to prevent scope creep
- **Proxy**: Use `extra_args=["--proxy", "http://127.0.0.1:8080"]` to route through a proxy
- **Custom headers**: Use `extra_args=["--custom-headers", "Authorization=Bearer token"]`
- **Timeouts**: Set via config: `config=["modules.http.timeout=10"]`
