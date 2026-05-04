---
name: kiterunner
description: API-aware content discovery using Swagger/OpenAPI-derived wordlists. Sends properly formatted requests with correct HTTP methods, headers, and parameters. Use after identifying API targets or extracting Swagger specs from source maps.
---

# kiterunner -- API Content Discovery

Content discovery that understands API route structures. Each wordlist entry carries HTTP method, headers, path, and parameters -- not just a path string.

## When to Use

- Target exposes API endpoints (REST, GraphQL gateway, microservices)
- Swagger/OpenAPI spec extracted from source maps or recon
- Traditional bruting (feroxbuster/gobuster) returned only generic 404s
- Need to discover undocumented API routes with correct methods

## When NOT to Use

- Static file discovery (use feroxbuster/gobuster instead)
- Target behind aggressive WAF with rate limiting (kr is noisy)

## CLI Reference

| Command | Purpose |
|---------|---------|
| `kr scan <target> -w routes.kite` | API scan with .kite wordlist (method+headers+params per route) |
| `kr brute <target> -w wordlist.txt` | Traditional path brute (like gobuster) |
| `kr kb replay "OUTPUT_LINE" --proxy=http://localhost:8080` | Replay finding through Caido |
| `kr kb convert wordlist.txt wordlist.kite` | Convert between txt/json/kite formats |
| `kr wordlist list` | List available Assetnote wordlists |

## Key Flags (scan/brute)

| Flag | Purpose |
|------|---------|
| `-A apiroutes-260227:20000` | Assetnote wordlist (`:N` = head N entries) |
| `-w routes.kite` | Local .kite or .txt wordlist |
| `-x 5` | Max connections per host (default: 3) |
| `-j 50` | Max parallel hosts (default: 50) |
| `-t 3s` | Request timeout |
| `-H "Header: value"` | Custom header |
| `--fail-status-codes 400,401,404,403,501,502` | Blacklist response codes |
| `--ignore-length 100-105` | Ignore responses by content-length range |
| `-o json` | Output format: `json`, `text`, `pretty` |

**Proxy:** Only available on `kb replay --proxy=http://localhost:8080`. Scan/brute do not support proxy directly.

**Wordlist aliases rotate monthly.** Run `kr wordlist list` to see current aliases.

## Patterns

```bash
# API scan with Assetnote wordlist
kr scan https://api.target.com -A=apiroutes-260227:20000 -x 5 \
  --fail-status-codes 400,401,404,403,501,502

# Scan multiple targets
kr scan targets.txt -A=apiroutes-260227:20000 -x 3 -j 100

# Replay finding through Caido for evidence
kr kb replay -q --proxy=http://localhost:8080 -w routes.kite "OUTPUT_LINE"

# Technology-specific brute (.NET)
kr brute https://target.com -A=aspx-260227:10000 -x 5
```

## Chain With

- **jxscout** -- extract Swagger/OpenAPI specs from source maps, convert to .kite
- **Caido** -- replay findings via `kb replay --proxy` for evidence capture
- **vulnx** -- discovered endpoints reveal technology versions for CVE lookup
